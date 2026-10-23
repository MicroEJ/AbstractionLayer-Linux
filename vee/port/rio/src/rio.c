/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief rio — event-driven I/O multiplexing engine.
 * @author @CCO_AUTHOR@
 * @version 1.0.0
 * @date @CCO_DATE@
 *
 * Central source pool + worker thread for the ej.rio Foundation
 * Library.
 *
 * Each source carries two link fields and a lifecycle `state`
 * (FREE/ACTIVE/DETACHED/PENDING_FREE — see rio_selector.h).  Ownership map:
 *
 *   - free list (`free_head`, threaded via `next_free`) — VM-C-task-only,
 *     lock-free.  MicroEJ is green-threaded: at most one Java native runs at a
 *     time on the VM C task, so the alloc/free path (rio_poll / rio_wait_ready
 *     and their scoped-resource closes) never races itself.  It may transiently
 *     hold PENDING_FREE sources the VM linked during a stop two-phase free that
 *     are not yet allocatable, so `alloc_source` / `count_free_sources` filter
 *     by `state`.  (The worker flips those PENDING_FREE→FREE under the mutex;
 *     the VM only reads `state` here — a single aligned load/store, benign.)
 *   - active list (`active_head`, threaded via `next_active`) and every
 *     `state` transition — shared between the VM C task (register-splice;
 *     stop-time PENDING_FREE marking) and the worker (poll, dispatch-detach,
 *     stop reclaim).  Guarded by `rio_pool.mutex`.
 *
 * Per-wait sources never leak: each `rio_poll` / `rio_wait_ready` chunk is an
 * SNI scoped resource (close = `rio_scoped_release`), so the VM frees it on
 * normal return-to-Java AND on app/VM stop.  Freeing is two-phase — the worker
 * detaches off the active list, the VM links onto the free list — so each list
 * keeps a single writer on the hot path.
 *
 * The worker manages timeouts: each source carries an absolute
 * `deadline_ms`, the selector backend's `prepare()` returns
 * `min(deadline) - now` along with the kernel fd-set, and the
 * dispatch walk detaches and resumes any chunk whose deadline has
 * passed (even if no kernel event arrived).  Java threads are
 * suspended with an infinite SNI timeout — the worker is the
 * sole authority on when to resume them.
 *
 * No `worker_sem` is needed any more: when the active list is empty
 * the worker just blocks in `rio_selector_wait(-1)` with the
 * backend's wake mechanism registered.  The next
 * `rio_selector_wake` from a VM-side rio_poll returns it
 * immediately.
 *
 * The actual I/O multiplexing primitive (poll, select) is
 * abstracted behind `rio_selector.h`.  The active
 * backend is selected at compile time by a `#define` in
 * `rio_configuration.h`.
 */

#include "rio.h"
#include "rio_errors.h"
#include "rio_selector.h"
#include "rio_util.h"
#include "rio_configuration.h"

#if RIO_CONFIGURATION_VERSION != 2
#error "Version of the configuration file rio_configuration.h is not compatible with this implementation."
#endif

#include "sni.h"
#include "osal.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLRIO_LOG_MODULE_NAME, LLRIO_LOG_LEVEL)

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Each registered source occupies a (fd, interests, revents) triplet in the
 * flat int[] buffer the Java Poll hands native (see LLRIO_impl.c).  Name the
 * stride and the slots so every access into the buffer is explicit. */
#define RIO_ENTRY_FIELDS 3
#define RIO_ENTRY_FD(entries, i)        ((entries)[(i) * RIO_ENTRY_FIELDS])
#define RIO_ENTRY_INTERESTS(entries, i) ((entries)[(i) * RIO_ENTRY_FIELDS + 1])
#define RIO_ENTRY_REVENTS(entries, i)   ((entries)[(i) * RIO_ENTRY_FIELDS + 2])

/* ── Pool ────────────────────────────────────────────────────── */

typedef struct {
	/* Free half — VM-C-task-only, threaded via `next_free`.  Touched from
	 * rio_poll / rio_wait_ready and their SNI callbacks (alloc/free); never by
	 * the worker thread.  No locking.  May transiently hold RIO_SRC_PENDING_FREE
	 * sources (stop two-phase free) that are not yet allocatable — `alloc_source`
	 * / `count_free_sources` filter by `state`. */
	rio_source_t sources[RIO_MAX_SOURCES];
	rio_source_t *free_head;

	/* Active half — threaded via `next_active`, shared between the VM C task
	 * (register-splice) and the worker thread (poll / dispatch-detach).
	 * `mutex` guards `active_head` and every `next_active` reachable from it,
	 * plus the `state` transitions. */
	rio_source_t *active_head;
	OSAL_mutex_handle_t mutex;
} rio_pool_t;

static rio_pool_t rio_pool;

/* ── Pool helpers (VM C task only — no locking) ─────────────── */

/** Number of allocatable (RIO_SRC_FREE) sources on the free list.  The free
 *  list may also carry RIO_SRC_PENDING_FREE sources (linked by the VM during a
 *  stop two-phase free, not yet flipped to FREE by the worker), so we count by
 *  state rather than keep a counter the worker would have to mutate.  VM-C-task-only. */
static int count_free_sources(void) {
	int n = 0;
	for (rio_source_t *s = rio_pool.free_head; s != NULL; s = s->next_free) {
		if (s->state == RIO_SRC_FREE) {
			n++;
		}
	}
	return n;
}

/** Pop the first allocatable (RIO_SRC_FREE) source from the free list, skipping
 *  any RIO_SRC_PENDING_FREE ones.  Returns NULL when none are free.  VM-C-task-only. */
static rio_source_t *alloc_source(void) {
	rio_source_t *prev = NULL;
	for (rio_source_t *s = rio_pool.free_head; s != NULL; prev = s, s = s->next_free) {
		if (s->state == RIO_SRC_FREE) {
			if (prev == NULL) {
				rio_pool.free_head = s->next_free;
			} else {
				prev->next_free = s->next_free;
			}
			s->next_free = NULL;
			return s;
		}
	}
	return NULL;
}

/** Push a source back onto the free list as allocatable (RIO_SRC_FREE).  Used by
 *  the normal completion path (DETACHED->FREE).  VM-C-task-only. */
static void free_source(rio_source_t *s) {
	s->state = RIO_SRC_FREE;
	s->next_free = rio_pool.free_head;
	rio_pool.free_head = s;
}

/* ── rio_scoped_release: SNI scoped-resource close (two-phase free) ── */

/**
 * Scoped-resource close for a `rio_poll` / `rio_wait_ready` chunk, registered
 * with `SNI_registerScopedResource` at suspend.  The VM C task runs it on
 * every exit of the owning native — normal return-to-Java AND app/VM stop — so
 * a per-wait source can never leak.
 *
 * This is phase 2 of the two-phase free and **never touches the active list**
 * (the worker owns active-list detach).  Under `rio_pool.mutex` it walks the
 * chunk — the contiguous same-`waiter_thread_id` block, whose tid boundary
 * bounds the walk both when the worker has already self-terminated it (detached
 * case) and when it is still inline on the active list (stop case) — and
 * branches on each source's state:
 *
 *   - DETACHED — the worker already detached it (normal completion, or a
 *     DETACHED-at-stop source whose resume won't run): free it now (link
 *     `next_free`, state FREE).
 *   - ACTIVE — stop arrived while the worker was still waiting on it: mark
 *     PENDING_FREE and link `next_free` (on the free list but NOT yet
 *     allocatable — `alloc_source` skips non-FREE), leaving it on the active
 *     list for the worker to detach and flip FREE.  Wake the worker for phase 2.
 *
 * The mutex serialises the ready-vs-stop race with the worker so exactly one of
 * {worker ACTIVE->DETACHED+resume, this ACTIVE->PENDING_FREE} wins; both loser
 * paths are defined (see the state-machine notes).
 */
static void rio_scoped_release(void *resource) {
	rio_source_t *head = (rio_source_t *)resource;
	if (head == NULL) {
		return;
	}

	int32_t chunk_tid = head->waiter_thread_id;
	bool wake = false;

	OSAL_mutex_take(&rio_pool.mutex, OSAL_INFINITE_TIME);

	rio_source_t *s = head;
	while (s != NULL && s->waiter_thread_id == chunk_tid) {
		rio_source_t *next = s->next_active;
		if (s->state == RIO_SRC_DETACHED) {
			free_source(s);
		} else {
			s->state = RIO_SRC_PENDING_FREE;
			s->next_free = rio_pool.free_head;
			rio_pool.free_head = s;
			wake = true;
		}
		s = next;
	}

	OSAL_mutex_give(&rio_pool.mutex);

	if (wake) {
		rio_selector_wake();
	}
}

/* ── Worker thread ──────────────────────────────────────────── */

/**
 * Walks `active_head` in per-thread chunks (a chunk = consecutive
 * sources with the same `waiter_thread_id`, guaranteed contiguous by
 * `rio_poll()`'s splice-as-block insertion).  For each chunk:
 *
 *   - if any source has revents set OR has a now-expired
 *     `deadline_ms`, detach the entire chunk from the active list
 *     (chunk_tail's `next` becomes NULL so the chunk is
 *     self-terminating) and resume the suspended thread exactly
 *     once;
 *   - if none is ready and none has timed out, leave the chunk in
 *     place for a later pass.
 *
 * Pulling the whole chunk on first-ready (rather than just the
 * ready source) prevents the worker from observing a stale
 * not-ready sibling on a later pass and attempting a second
 * resume of an already-resumed thread.  Caller must hold
 * `rio_pool.mutex`.
 */
static void dispatch_ready_or_timed_out_chunks(void) {
	int64_t now = LLMJVM_IMPL_getCurrentTime__Z(1);

	rio_source_t *prev = NULL;
	rio_source_t *s = rio_pool.active_head;

	while (s != NULL) {
		int32_t chunk_tid = s->waiter_thread_id;
		rio_source_t *chunk_head = s;
		rio_source_t *chunk_tail = s;
		/* A whole chunk shares one lifecycle: the VM marks every source of a
		 * stopping app's chunk PENDING_FREE together (rio_scoped_release), so the
		 * head's state classifies the chunk. */
		bool stop_reclaim = (s->state == RIO_SRC_PENDING_FREE);
		bool chunk_ready = stop_reclaim || (s->revents != 0) || (s->polled && s->deadline_ms <= now) || s->closed;

		/* Advance through the contiguous block of same-tid sources (next_active). */
		while (chunk_tail->next_active != NULL
		       && chunk_tail->next_active->waiter_thread_id == chunk_tid) {
			chunk_tail = chunk_tail->next_active;
			if (chunk_tail->state == RIO_SRC_PENDING_FREE
			    || chunk_tail->revents != 0
			    || (chunk_tail->polled && chunk_tail->deadline_ms <= now)
			    || chunk_tail->closed) {
				chunk_ready = true;
			}
		}

		rio_source_t *after_chunk = chunk_tail->next_active;

		if (chunk_ready && chunk_tid != 0) {
			/* Detach the whole chunk from the active list (next_active). */
			if (prev == NULL) {
				rio_pool.active_head = after_chunk;
			} else {
				prev->next_active = after_chunk;
			}
			chunk_tail->next_active = NULL;

			if (stop_reclaim) {
				/* Stop two-phase free, phase 2: the VM already linked these onto
				 * the free list (next_free) and marked them PENDING_FREE.  Flip
				 * to FREE (now allocatable); NO resume — the waiter is gone. */
				for (rio_source_t *t = chunk_head; t != NULL; t = t->next_active) {
					t->state = RIO_SRC_FREE;
				}
			} else {
				/* UC1: mark the chunk DETACHED (in-flight to the VM); the resumed
				 * native's scoped close frees each (DETACHED->FREE).  Resume by
				 * tid only — the callback recovers the chunk via
				 * SNI_getScopedResource, so no resume arg is needed. */
				for (rio_source_t *t = chunk_head; t != NULL; t = t->next_active) {
					t->state = RIO_SRC_DETACHED;
				}
				SNI_resumeJavaThreadWithArg(chunk_tid, NULL);
			}

			/* `prev` unchanged; continue from the next chunk. */
			s = after_chunk;
		} else {
			/* Chunk stays in the active list. */
			prev = chunk_tail;
			s = after_chunk;
		}
	}
}

static void *rio_worker(void *arg) {
	(void)arg;

	while (1) {
		OSAL_mutex_take(&rio_pool.mutex, OSAL_INFINITE_TIME);

		/* `prepare` does one walk of the active list to build the
		 * backend's fd set and to fold in `min(deadline_ms) - now`
		 * as the return value.  Returns -1 when there is nothing
		 * to wait on (empty list or all-infinite deadlines), so the
		 * worker blocks in the selector with only its wake
		 * mechanism registered. */
		int timeout = rio_selector_prepare(rio_pool.active_head);

		OSAL_mutex_give(&rio_pool.mutex);

		rio_selector_wait(timeout);

		OSAL_mutex_take(&rio_pool.mutex, OSAL_INFINITE_TIME);

		rio_selector_drain_wake();
		rio_selector_collect();
		dispatch_ready_or_timed_out_chunks();

		OSAL_mutex_give(&rio_pool.mutex);
	}

	return NULL;
}

/* ── init ───────────────────────────────────────────────────── */

int rio_init(void) {
	/* Idempotent, and lock-free by construction.  rio_init is the wait-mechanism
	 * init for every consumer that runs over rio — rio's own PollNative static
	 * init, net-rio (LLNET_INIT_WAIT_MECHANISM), SSL — so an application that
	 * uses more than one of them calls this repeatedly.  It only ever runs as a
	 * side effect of an SNI native the VM invokes, i.e. on the single VM C task;
	 * MicroEJ is green-threaded (at most one Java native runs at a time on that
	 * task), so these calls are serialized and can never race — the static flag
	 * needs no mutex or atomic.  Do the one-time setup (mutex, pool, selector,
	 * worker thread) only on the first call and just return the pool size
	 * afterwards: a second worker thread, or resetting the pool while it is live,
	 * would corrupt the engine.  The flag is set only after a fully successful
	 * init, so a failed mutex / selector / worker create stays retryable. */
	static bool rio_initialized = false;
	if (rio_initialized) {
		return RIO_MAX_SOURCES;
	}

	if (OSAL_mutex_create((uint8_t *)"rio_mutex", &rio_pool.mutex) != OSAL_OK) {
		VEEPORT_ERRORS_throw_caught_exception_message(J_EUNKNOWN, "rio: mutex create failed");
		return SNI_IGNORED_RETURNED_VALUE;
	}

	/* Chain every source slot into the free list (threaded via next_free), all
	 * RIO_SRC_FREE; next_active is NULL until a source is spliced onto active. */
	rio_pool.active_head = NULL;
	for (int i = 0; i < RIO_MAX_SOURCES; i++) {
		rio_pool.sources[i].fd = -1;
		rio_pool.sources[i].interests = 0;
		rio_pool.sources[i].revents = 0;
		rio_pool.sources[i].waiter_thread_id = 0;
		rio_pool.sources[i].deadline_ms = INT64_MAX;
		rio_pool.sources[i].closed = false;
		rio_pool.sources[i].polled = false;
		rio_pool.sources[i].state = RIO_SRC_FREE;
		rio_pool.sources[i].next_active = NULL;
		rio_pool.sources[i].next_free = (i + 1 < RIO_MAX_SOURCES)
		                                       ? &rio_pool.sources[i + 1]
		                                       : NULL;
	}
	rio_pool.free_head = &rio_pool.sources[0];

	if (rio_selector_init() < 0) {
		VEEPORT_ERRORS_throw_caught_exception_message(J_EUNKNOWN, "rio: selector init failed");
		return SNI_IGNORED_RETURNED_VALUE;
	}

	OSAL_task_handle_t worker_handle;
	OSAL_task_stack_declare(worker_stack, RIO_WORKER_STACK_SIZE);
	if (OSAL_task_create(rio_worker, (uint8_t *)"rio_worker",
	                     worker_stack, RIO_WORKER_PRIORITY,
	                     NULL, &worker_handle) != OSAL_OK) {
		VEEPORT_ERRORS_throw_caught_exception_message(J_EUNKNOWN, "rio: worker thread create failed");
		return SNI_IGNORED_RETURNED_VALUE;
	}

	rio_initialized = true;
	return RIO_MAX_SOURCES;
}

/* ── rio_close_fd: wake any source watching this fd ────────── */

void rio_close_fd(int fd) {
	bool any_marked = false;

	OSAL_mutex_take(&rio_pool.mutex, OSAL_INFINITE_TIME);

	/* Walk the active list — fd alone, no thread-id filter: the
	 * closing call comes from a *different* Java thread than the
	 * one(s) suspended on the fd, so we cannot narrow by tid.
	 * Every active source carrying this fd is marked closed; the
	 * worker's next dispatch sees the flag and resumes the
	 * corresponding waiter. */
	for (rio_source_t *s = rio_pool.active_head; s != NULL; s = s->next_active) {
		if (s->fd == fd) {
			s->closed = true;
			any_marked = true;
		}
	}

	OSAL_mutex_give(&rio_pool.mutex);

	if (any_marked) {
		rio_selector_wake();
	}
}

/* ── rio_poll: stateless multi-fd poll ─────────────────────── */

/**
 * SNI callback for `rio_poll`.  Must match the SNI native signature
 * (same parameters and return type as `LLRIO_IMPL_poll`).
 *
 * The chunk was registered as a scoped resource at suspend, so the worker
 * resumes by thread id with no resume arg; this callback recovers the chunk
 * head via `SNI_getScopedResource`.  It walks the chunk via `next_active` in
 * lock-step with the caller's `entries[]` buffer, writes each source's
 * `revents` back into its `RIO_ENTRY_REVENTS` slot, and returns the count of ready
 * sources.  It does **not** free the sources: the scoped close
 * (`rio_scoped_release`) runs on return-to-Java and performs phase 2 of the
 * two-phase free.  Runs entirely on the VM C task.
 *
 * On a count of 0 it throws `J_ETIMEDOUT` rather than returning 0, mirroring
 * `wait_ready_callback`: the worker only resumes a chunk on ready / deadline /
 * closed-fd, so a zero ready count means the deadline expired with nothing
 * ready (a concurrent `rio_close_fd` wake folds into the same timeout report,
 * exactly as it does for the per-fd wait).
 */
static jint poll_callback(jint *entries, jint n, jint timeout_ms) {
	(void)timeout_ms;

	rio_source_t *head = NULL;
	SNI_getScopedResource((void **)&head, NULL, NULL);

	int count = 0;
	rio_source_t *s = head;
	int i = 0;
	while (s != NULL && i < n) {
		RIO_ENTRY_REVENTS(entries, i) = (jint)s->revents;
		if (s->revents != 0) {
			count++;
		}

		s = s->next_active;
		i++;
	}

	if (count == 0) {
		VEEPORT_ERRORS_throw_caught_exception(J_ETIMEDOUT);
		return SNI_IGNORED_RETURNED_VALUE;
	}

	return (jint)count;
}

/**
 * SNI resume callback for a source-less `rio_poll` (see the `n <= 0` branch).
 * No source was registered, so the only thing that resumes the caller is the
 * SNI suspend timeout firing — report it as a poll timeout.  There is no scoped
 * resource to recover or free.
 */
static jint poll_timeout_callback(jint *entries, jint n, jint timeout_ms) {
	(void)entries;
	(void)n;
	(void)timeout_ms;
	VEEPORT_ERRORS_throw_caught_exception(J_ETIMEDOUT);
	return SNI_IGNORED_RETURNED_VALUE;
}

int rio_poll(int *entries, int n, int timeout_ms) {
	if (n <= 0) {
		/* No sources to watch: nothing can ever become ready, so the call can
		 * only end in a timeout.  There is no source for the worker to carry a
		 * deadline on, so the VM C task arms the SNI suspend with the poll
		 * timeout itself (no scoped resource, no worker) — it blocks for the
		 * timeout like select() with an empty fd set, then `poll_timeout_callback`
		 * throws `J_ETIMEDOUT`.  A non-blocking probe (`timeout_ms == 0`) has no
		 * positive timeout to arm, so it throws at once; a negative (infinite)
		 * timeout suspends indefinitely, as select() would with no fds. */
		if (timeout_ms == 0) {
			VEEPORT_ERRORS_throw_caught_exception(J_ETIMEDOUT);
			return SNI_IGNORED_RETURNED_VALUE;
		}
		int64_t sni_timeout = (timeout_ms < 0) ? 0 /* SNI infinite */ : (int64_t)timeout_ms;
		SNI_suspendCurrentJavaThreadWithCallback(sni_timeout,
		                                         (SNI_callback)poll_timeout_callback,
		                                         NULL);
		return SNI_IGNORED_RETURNED_VALUE;
	}

	int32_t tid = SNI_getCurrentJavaThreadID();

	/* Up-front capacity check: confirm the pool has room for the
	 * whole chunk before allocating.  Avoids the partial-allocation
	 * unwind path entirely.  The free list is a VM-C-task-only structure
	 * so no lock is needed.  Also catches `n > RIO_MAX_SOURCES` (the
	 * pool holds at most RIO_MAX_SOURCES slots, so the free count is
	 * bounded by it). */
	if (count_free_sources() < n) {
		VEEPORT_LOGGER_LOG_ERR("rio: source pool exhausted (RIO_MAX_SOURCES reached)");
		VEEPORT_ERRORS_throw_caught_exception(J_ENOMEM);
		return SNI_IGNORED_RETURNED_VALUE;
	}

	/* Compute the absolute deadline once for the whole chunk. */
	int64_t deadline = (timeout_ms < 0)
	        ? INT64_MAX
	        : (LLMJVM_IMPL_getCurrentTime__Z(1) + (int64_t)timeout_ms);

	/* Build the chunk off-list (no mutex needed — pool half is
	 * VM-C-task-only).  Splice it onto `active_head` in one pointer
	 * update under the mutex below. */
	rio_source_t *head = NULL;
	rio_source_t *tail = NULL;
	for (int i = 0; i < n; i++) {
		int fd = RIO_ENTRY_FD(entries, i);
		/* fd validity is the VM C task's responsibility — the worker assumes
		 * every active source has a valid fd.  Reject here; the chunk is still
		 * off-list (not yet spliced onto active_head), so unwinding it just
		 * returns the slots to the pool. */
		if (fd < 0) {
			while (head != NULL) {
				rio_source_t *next = head->next_active;
				free_source(head);
				head = next;
			}
			VEEPORT_ERRORS_throw_caught_exception(J_EBADF);
			return SNI_IGNORED_RETURNED_VALUE;
		}

		rio_source_t *s = alloc_source();

		s->fd = fd;
		s->interests = (short)RIO_ENTRY_INTERESTS(entries, i);
		s->revents = 0;
		s->polled = false;
		s->waiter_thread_id = tid;
		s->deadline_ms = deadline;
		s->closed = false;
		s->state = RIO_SRC_ACTIVE;
		s->next_active = NULL;

		if (head == NULL) {
			head = s;
		} else {
			tail->next_active = s;
		}
		tail = s;
	}

	OSAL_mutex_take(&rio_pool.mutex, OSAL_INFINITE_TIME);

	/* Register each source while the chunk is still self-contained
	 * (tail->next_active == NULL), then splice it as a single contiguous block at
	 * the head of the active list.  The registration hook only matters to a
	 * stateful backend (e.g. epoll); the poll/select backends rebuild from the
	 * active list, so it is gated out for them. */
#ifdef RIO_SELECTOR_TRACKS_REGISTRATION
	for (rio_source_t *s = head; s != NULL; s = s->next_active) {
		rio_selector_on_register(s);
	}
#endif
	tail->next_active = rio_pool.active_head;
	rio_pool.active_head = head;

	/* Register the chunk as a scoped resource so the VM frees it on every exit
	 * path — normal return-to-Java AND app/VM stop (`rio_scoped_release` runs
	 * phase 2 of the two-phase free).  The chunk head is the resource handle;
	 * the callback recovers it via `SNI_getScopedResource`, so no SNI resume
	 * arg is needed. */
	SNI_registerScopedResource((void *)head, rio_scoped_release, NULL);

	/* Suspend the Java caller BEFORE waking the worker.  Otherwise
	 * the worker could observe a ready source and call
	 * `SNI_resumeJavaThread()` on a thread that hasn't yet handed
	 * control back to the VM — the resume would be lost.
	 *
	 * SNI timeout is 0 (infinite): the worker owns deadlines now.  The worker
	 * resumes by thread id with no arg; the scoped resource carries the chunk. */
	SNI_suspendCurrentJavaThreadWithCallback(0,
	                                         (SNI_callback)poll_callback,
	                                         NULL);

	OSAL_mutex_give(&rio_pool.mutex);

	rio_selector_wake();

	return SNI_IGNORED_RETURNED_VALUE;
}

/* ── rio_wait_ready: per-fd blocking wait ──────────────────── */

/**
 * Internal SNI callback for `rio_wait_ready` when the caller does not provide
 * its own.  Recovers the source via the scoped resource, then returns 1 on
 * ready / throws `J_ETIMEDOUT` on deadline.  The source is freed by the scoped
 * close on return-to-Java, not here.
 */
static jint wait_ready_callback(jint fd, jint interests, jint timeout_ms) {
	(void)fd;
	(void)interests;
	(void)timeout_ms;

	/* Recover the source from the scoped resource (no resume arg).  Do not free
	 * it here — the scoped close (`rio_scoped_release`) runs on return-to-Java
	 * and performs phase 2 of the two-phase free. */
	rio_source_t *s = NULL;
	SNI_getScopedResource((void **)&s, NULL, NULL);

	/* A concurrent close() under the waiter must surface as a deterministic
	 * "socket closed" — matching java.net's SocketException: Socket closed.
	 * The worker resumes the source with `closed` set; the underlying poll may
	 * report POLLNVAL, nothing, or a stray revent on the closed fd, so `closed`
	 * is the reliable signal. Without this a closed source whose revents look
	 * ready returns "ready" and defers the error to a follow-up read — which is
	 * racy and, on an infinite wait, re-parks and hangs. */
	if (s != NULL && s->closed) {
		VEEPORT_ERRORS_throw_caught_exception(J_EBADF);
		return 0;
	}

	bool ready = (s != NULL) && (s->revents != 0);

	if (!ready) {
		VEEPORT_ERRORS_throw_caught_exception(J_ETIMEDOUT);
		return 0;
	}
	return 1;
}

int rio_wait_ready(int fd, int interests, int timeout_ms,
                   SNI_callback callback, void *suspend_arg) {
	/* fd validity is the VM C task's responsibility; the worker assumes valid. */
	if (fd < 0) {
		VEEPORT_ERRORS_throw_caught_exception(J_EBADF);
		return SNI_IGNORED_RETURNED_VALUE;
	}

	SNI_callback cb = (callback != NULL) ? callback
	                                     : (SNI_callback)wait_ready_callback;

	int32_t tid = SNI_getCurrentJavaThreadID();
	/* `timeout_ms == 0` is a non-blocking readiness probe: the deadline is
	 * `now`, so the worker's next cycle polls the fd once (zero-timeout select)
	 * and the dispatch walk resumes the thread with the actual revents if it is
	 * ready, or as a timeout if not — it never blocks.  Negative waits forever. */
	int64_t deadline = (timeout_ms < 0)
	        ? INT64_MAX
	        : (LLMJVM_IMPL_getCurrentTime__Z(1) + (int64_t)timeout_ms);

	/* Re-wait reuse.  When the suspend callback is the *caller's own native*
	 * (net/SSL), the worker resumes it, it retries the op, and on a repeated
	 * would-block it calls `rio_wait_ready` again — still inside the same SNI
	 * native scope.  That scope's scoped resource is still registered, so
	 * `SNI_getScopedResource` returns the source from the previous wait (now
	 * DETACHED, off the active list).  Reuse it — reset and re-splice — instead
	 * of alloc/realloc, so one scoped resource covers the whole loop. */
	rio_source_t *s = NULL;
	SNI_getScopedResource((void **)&s, NULL, NULL);
	bool reuse = (s != NULL);

	if (!reuse) {
		/* First wait in this scope: allocate and register the scoped resource. */
		if (count_free_sources() < 1) {
			VEEPORT_LOGGER_LOG_ERR("rio: source pool exhausted (RIO_MAX_SOURCES reached)");
			VEEPORT_ERRORS_throw_caught_exception(J_ENOMEM);
			return SNI_IGNORED_RETURNED_VALUE;
		}
		s = alloc_source();
	}

	s->fd = fd;
	s->interests = (short)interests;
	s->revents = 0;
	s->polled = false;
	s->waiter_thread_id = tid;
	s->deadline_ms = deadline;
	s->closed = false;
	s->state = RIO_SRC_ACTIVE;
	s->next_active = NULL;

	OSAL_mutex_take(&rio_pool.mutex, OSAL_INFINITE_TIME);

	/* Splice this one-source chunk onto the active list.  Same shape
	 * as the multi-fd path, just with N=1. */
#ifdef RIO_SELECTOR_TRACKS_REGISTRATION
	rio_selector_on_register(s);
#endif
	s->next_active = rio_pool.active_head;
	rio_pool.active_head = s;

	/* First wait registers the chunk as a scoped resource so the VM frees it on
	 * every exit (return-to-Java AND app/VM stop); the reuse path keeps the
	 * already-registered one.  The callback recovers `s` via
	 * `SNI_getScopedResource`, so no SNI resume arg is needed.  The caller's
	 * `suspend_arg` still flows through as the SNI suspend arg (per-call state,
	 * e.g. net-rio-wait's `written_so_far`). */
	if (!reuse) {
		SNI_registerScopedResource((void *)s, rio_scoped_release, NULL);
	}
	SNI_suspendCurrentJavaThreadWithCallback(0, cb, suspend_arg);

	OSAL_mutex_give(&rio_pool.mutex);

	rio_selector_wake();

	return SNI_IGNORED_RETURNED_VALUE;
}
