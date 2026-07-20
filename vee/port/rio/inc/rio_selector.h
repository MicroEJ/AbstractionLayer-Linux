/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief rio selector backend interface.
 * @author @CCO_AUTHOR@
 * @version 1.0.0
 * @date @CCO_DATE@
 *
 * Internal abstraction layer for I/O multiplexing backends.  Each
 * backend (poll, select) implements the functions declared here.
 * rio.c calls them instead of using POSIX poll() directly.
 *
 * Backend selection: the BSP build lists exactly one of
 *   rio_poll.c     POSIX poll() + wake pipe  (portable default)
 *   rio_select.c   POSIX select() + wake pipe
 * in its source set.  Linking more than one in the same image
 * produces duplicate-symbol errors that flag the mistake at link
 * time.
 */

#ifndef RIO_SELECTOR_H
#define RIO_SELECTOR_H

#include "rio_configuration.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Canonical event flags ────────────────────────────────────
 *
 * All backends translate platform-specific flags into these values
 * when filling rio_event_t.events.  They match the POLLIN/POLLOUT
 * values that the Java Interest class uses, so rio.c doesn't need
 * any translation. */

#define RIO_EVENT_READABLE  0x0001  /* POLLIN  */
#define RIO_EVENT_WRITABLE  0x0004  /* POLLOUT */

/* ── Shared types ─────────────────────────────────────────────
 *
 * These were previously local to rio.c.  Both rio.c and the backends
 * need them, so they live here. */

typedef struct rio_source rio_source_t;

/**
 * Lifecycle / ownership state of a source. Transitions are taken under
 * `rio_pool.mutex`. This is the *ownership* axis; it is orthogonal to `closed`
 * (the *readiness reason* — ready/timeout/closed all share one lifecycle path).
 */
typedef enum {
	RIO_SRC_FREE = 0,       /**< On the free list (via `next_free`); allocatable. */
	RIO_SRC_ACTIVE,         /**< On the active list (via `next_active`); being polled. */
	RIO_SRC_DETACHED,       /**< Worker detached it off active; in-flight to the VM
	                         *   (resumed callback frees it, or re-wait reuses it). */
	RIO_SRC_PENDING_FREE,   /**< VM marked it for the worker to reclaim on app/VM stop;
	                        *   linked into the free list (`next_free`) but still on the
	                        *   active list (`next_active`) and NOT yet allocatable. */
} rio_source_state_t;

/**
 * A registered I/O source.
 *
 * Sources come from a static pool. Each carries **two** independent link
 * fields so a source can be on both lists during the two-phase free, with a
 * single writer per list:
 *
 *   - `next_free` — the **free list**, mutated **only by the VM C task**
 *     (alloc / free); the worker never touches it.
 *   - `next_active` — the **active list** (and a worker-detached **chunk**),
 *     mutated by the VM (register-splice) and the worker (dispatch-detach),
 *     under `rio_pool.mutex`.
 *
 * `rio_poll()` splices a caller's sources into the active list as one
 * contiguous block of equal `waiter_thread_id`, so the active list is
 * "chunked" by thread: the worker walks `active_head` via `next_active`,
 * identifies per-thread chunks by tid equality, and on first-ready detaches
 * the whole chunk (`chunk_tail->next_active = NULL`, self-terminating) and
 * resumes the thread by id. The callback recovers the chunk head via
 * `SNI_getScopedResource` (the chunk is registered as a scoped resource), not
 * via an SNI resume arg.
 *
 * @see rio_wait_ready, rio_poll
 */
struct rio_source {
	int32_t fd;
	short interests;             /**< Requested events (POLLIN/POLLOUT bitmask). */
	short revents;               /**< Events returned by the last selector pass. */
	int32_t waiter_thread_id;    /**< Suspended Java thread to resume on completion. */
	int64_t deadline_ms;         /**< Absolute deadline (LLMJVM time); INT64_MAX = no deadline. */
	bool closed;                 /**< Readiness reason: fd closed under the waiter by
	                              *   `rio_close_fd`. The worker treats it as a ready trigger
	                              *   (Linux `poll()` does not auto-deliver POLLNVAL on a
	                              *   concurrent close). Orthogonal to `state`. */
	bool polled;                 /**< Has been through >=1 selector pass.  Gates deadline
	                              *   expiry so a freshly-spliced source (e.g. a timeout=0
	                              *   readiness probe) is polled once before it can time out. */
	rio_source_state_t state;    /**< Lifecycle/ownership (under `rio_pool.mutex`). */
	rio_source_t *next_free;     /**< Free-list linkage — VM C task only. */
	rio_source_t *next_active;   /**< Active-list / detached-chunk linkage — VM splice + worker detach. */
};

/* ── Selector interface ───────────────────────────────────────
 *
 * Every backend implements the 6 core functions below.  The 2
 * registration hooks (on_register / on_deregister) are optional:
 * a backend that maintains a persistent kernel set
 * keyed by fd (e.g. epoll/kqueue) defines RIO_SELECTOR_TRACKS_REGISTRATION
 * and implements them; the poll/select backends rebuild from the
 * active list each cycle and leave the macro undefined, so the hooks
 * are neither declared nor called. */

/**
 * Creates backend-specific resources (the wake pipe).
 *
 * Called once from rio_init() after the OSAL mutex is created.
 *
 * @return 0 on success, -1 on failure.
 */
int rio_selector_init(void);

/**
 * Interrupts the blocked wait so the worker re-reads the registry.
 *
 * Called after register/deregister/poll to wake the worker thread.
 * Must be safe to call from any thread.
 */
void rio_selector_wake(void);

/**
 * Clears the wake signal after the wait returns.
 *
 * Called under the mutex, after rio_selector_wait() returns and
 * before processing results.
 */
void rio_selector_drain_wake(void);

/**
 * Builds the backend-specific fd set from the active source list
 * and returns the timeout the worker should pass to
 * `rio_selector_wait()`.
 *
 * The active-list walk also folds in `min(deadline_ms) - now`
 * along the way, so the worker gets fd-set and deadline in one
 * pass.
 *
 * Called under the mutex, before releasing the lock for the wait.
 * For poll/select this rebuilds the fd set (and stashes
 * `active_head` for the corresponding `collect()` walk) and folds
 * in the timeout in the same pass.
 *
 * @param active_head  head of the active-source linked list,
 *                     threaded via `next`.
 * @return the timeout in milliseconds to pass to
 *         `rio_selector_wait()`, or `-1` for infinite (empty list
 *         or every source has an infinite deadline).
 */
int rio_selector_prepare(rio_source_t *active_head);

/**
 * Blocks in the OS multiplexing primitive.
 *
 * Called without the mutex held so other threads can modify the
 * registry concurrently.
 *
 * @param timeout_ms  max wait in milliseconds, or -1 for infinite.
 * @return the number of ready descriptors (may be 0 on timeout or
 *         wake), or -1 on error (errno set).
 */
int rio_selector_wait(int timeout_ms);

/**
 * Extracts ready events from the last wait, writing kernel revents
 * into the matching source's `revents` field.
 *
 * Called under the mutex, after rio_selector_wait() returns.  poll
 * and select map kernel-side ready entries back to their
 * `rio_source_t` by walking the active-list snapshot saved by
 * `prepare()`.
 *
 * @return the number of sources whose `revents` were set non-zero.
 */
int rio_selector_collect(void);

#ifdef RIO_SELECTOR_TRACKS_REGISTRATION
/**
 * Hook called after a source is added to the registry.
 *
 * Only declared for backends that maintain a persistent kernel set
 * keyed by fd (RIO_SELECTOR_TRACKS_REGISTRATION).  Called under the
 * mutex.
 *
 * @param src  the registered source (fd, interests, token).
 */
void rio_selector_on_register(const rio_source_t *src);

/**
 * Hook called after a source is removed from the registry.
 *
 * Only declared when RIO_SELECTOR_TRACKS_REGISTRATION is defined.
 * Called under the mutex.
 *
 * @param src  the source being removed.  Still valid for the
 *             duration of the call; backends may dereference it.
 */
void rio_selector_on_deregister(const rio_source_t *src);
#endif /* RIO_SELECTOR_TRACKS_REGISTRATION */

#ifdef __cplusplus
}
#endif

#endif /* RIO_SELECTOR_H */
