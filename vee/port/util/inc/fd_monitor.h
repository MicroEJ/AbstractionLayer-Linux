/*
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief Generic epoll-based file descriptor monitor.
 *
 * Provides an actor-style monitor thread that watches file descriptors for
 * read/write readiness via edge-triggered epoll and resumes suspended SNI
 * Java threads when events occur.  Communication from VM tasks to the
 * monitor thread is done through an atomic command pipe.
 *
 * All API functions are parametric — they take a @c struct fd_monitor pointer.
 * A system-wide default instance @c fd_monitor_sys is provided for the
 * common single-monitor case.
 *
 * Use @c FD_MONITOR_DEFINE(name, n) to declare and initialize a monitor
 * with @a n watch slots.
 *
 * Each @c fd_monitor_watch call internally @c dup()s the provided file
 * descriptor.  The duplicate is closed when @c fd_monitor_unwatch is called.
 * This allows the caller to @c close() its own fd independently.
 *
 * Watch handles can be grouped into caller-managed chains (linked via the
 * @a chain parameter).  @c fd_monitor_resume_all walks a chain and resumes
 * all pending threads — useful for connection close paths.
 *
 * Configuration defines (override before #include or via -D):
 *   FD_MONITOR_SYS_MAX_WATCHES   — default watch slots for fd_monitor_sys (default 64)
 *   FD_MONITOR_MAX_EPOLL_EVENTS  — epoll_wait batch size                  (default 8)
 *   FD_MONITOR_STACK_SIZE        — monitor thread stack                   (default 16 KB)
 *
 * @par Thread safety
 * The module operates across two thread domains:
 * - <b>VM task</b>: the single MicroEJ VM thread that serializes all SNI native calls.
 * - <b>Monitor thread</b>: the internal epoll loop that processes commands and dispatches events.
 *
 * Thread-safety rules for the public API:
 * - @c fd_monitor_init / @c fd_monitor_destroy — <b>not thread-safe</b>.
 *   Lifecycle functions; call from a single thread with no concurrent API usage.
 * - @c fd_monitor_watch / @c fd_monitor_unwatch — <b>not thread-safe</b>.
 *   Manipulate the internal freelist without locking.  Safe when all callers
 *   are serialized on the VM task (the normal MicroEJ case).
 * - @c fd_monitor_resume_all — <b>thread-safe</b>.
 *   Only performs an atomic write to the command pipe (< @c PIPE_BUF).
 */

#ifndef FD_MONITOR_H
#define FD_MONITOR_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "veeport_logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── configurable defaults ───────────────────────────────────────────── */

#ifndef FD_MONITOR_SYS_MAX_WATCHES
#define FD_MONITOR_SYS_MAX_WATCHES   (64U)
#endif

#ifndef FD_MONITOR_MAX_EPOLL_EVENTS
#define FD_MONITOR_MAX_EPOLL_EVENTS  (8U)
#endif

#ifndef FD_MONITOR_STACK_SIZE
#define FD_MONITOR_STACK_SIZE        (16U * 1024U)
#endif

/* ── log module ──────────────────────────────────────────────────────── */

/**
 * @brief Name of the log module shared by every source file of the file descriptor monitor.
 *
 * Each source file that logs registers the module with VEEPORT_LOGGER_DEFINE_MODULE().
 */
#define FD_MONITOR_LOG_MODULE_NAME "fd-monitor"

/**
 * @brief Verbosity of the file descriptor monitor.
 *
 * Override it in veeport_configuration.h with one of VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF
 * or _DBG.
 */
#ifndef FD_MONITOR_LOG_LEVEL
#define FD_MONITOR_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

/* ── return codes ────────────────────────────────────────────────────── */

#define FD_MONITOR_OK     (0)
#define FD_MONITOR_ERROR  (-1)

/* ── interest flags ─────────────────────────────────────────────────── */

#define FD_MONITOR_IN    (1U << 0)   /**< readable  */
#define FD_MONITOR_OUT   (1U << 1)   /**< writable  */

/* ── watch entry ─────────────────────────────────────────────────────── */

struct fd_monitor_watch {
	int dup_fd;             /**< dup'd fd for epoll (closed by unwatch) */
	int32_t java_thread_id; /**< thread to resume when ready            */
	int next;               /**< freelist (free) / caller chain (allocated), -1 = end */
};

/* ── monitor instance ────────────────────────────────────────────────── */

struct fd_monitor {
	/**
	 * file descriptor for the epoll monitor. Set to 0 by FD_MONITOR_DEFINE.
	 * Tested by fd_monitor_init to make it idempotent.
	 */
	int epoll_fd;
	int cmd_pipe[2];                    /* VM task → monitor thread */
	pthread_t thread;
	struct fd_monitor_watch *watches;
	int free_head;                      /* freelist head index, -1 = full */
	int max_watches;
	bool quit;                          /* signal monitor thread to exit */
};

/* ── declarator macro ────────────────────────────────────────────────── */

/**
 * @brief Declare and zero-initialize a monitor with @a n watch slots.
 *
 * The freelist is built by @c fd_monitor_init().
 */
#define FD_MONITOR_DEFINE(name, n)                          \
		static struct fd_monitor_watch name ## _watches[n]; \
		struct fd_monitor name = {                          \
			.watches = name ## _watches,                    \
			.max_watches = (n),                             \
			.epoll_fd = 0,                                  \
			.free_head = -1,                                \
		}

/** System-wide default monitor instance. */
extern struct fd_monitor fd_monitor_sys;

/* ── API ─────────────────────────────────────────────────────────────── */

/**
 * @brief Initialize a monitor: build freelist, create epoll, command pipe, start thread.
 *
 * @warning Not thread-safe.  Must be called exactly once before any other
 *          function on this monitor instance, from a single thread.
 *
 * @param[in] mon  the monitor instance (must have watches/max_watches set, e.g. via FD_MONITOR_DEFINE)
 * @return FD_MONITOR_OK on success, FD_MONITOR_ERROR on failure
 */
int fd_monitor_init(struct fd_monitor *mon);

/**
 * @brief Destroy a monitor: stop thread, close epoll and command pipe.
 *
 * Fails if any watch handles are still allocated (freelist not full).
 * After successful destruction, the monitor can be re-initialized with
 * @c fd_monitor_init().
 *
 * @warning Not thread-safe.  Must be called after all other usage has
 *          stopped, from a single thread.
 *
 * @param[in] mon  the monitor instance
 * @return FD_MONITOR_OK on success, FD_MONITOR_ERROR if watches are still allocated or monitor is not initialized
 */
int fd_monitor_destroy(struct fd_monitor *mon);

/**
 * @brief Watch a file descriptor for readiness.
 *
 * Internally @c dup()s @a fd, allocates a watch slot, prepends it to the
 * caller's @a chain, captures @c SNI_getCurrentJavaThreadID(), and
 * registers the duplicate in edge-triggered epoll.  The current Java
 * thread will be resumed when the fd becomes ready.
 *
 * @warning Not thread-safe.  Manipulates the internal freelist without
 *          locking.  Safe when all callers are serialized on the VM task.
 *
 * @param[in]     mon        the monitor instance
 * @param[in]     fd         the file descriptor to watch
 * @param[in]     interests  bitmask of @c FD_MONITOR_IN / @c FD_MONITOR_OUT
 * @param[in,out] chain      pointer to the caller's chain head (updated on prepend)
 * @return a watch handle (>= 0) on success, -1 on failure
 */
int fd_monitor_watch(struct fd_monitor *mon, int fd, uint32_t interests, int *chain);

/**
 * @brief Cancel a watch: close the internal dup'd fd and free the slot.
 *
 * Unlinks the handle from the caller's @a chain, sends a command to the
 * monitor thread to close the dup'd fd (which also removes it from epoll),
 * and returns the slot to the freelist.
 *
 * @warning Not thread-safe.  Same freelist constraint as @c fd_monitor_watch().
 *
 * @param[in]     mon    the monitor instance
 * @param[in]     hdl    the watch handle to cancel
 * @param[in,out] chain  pointer to the caller's chain head (updated on unlink)
 * @return FD_MONITOR_OK on success, FD_MONITOR_ERROR on failure
 */
int fd_monitor_unwatch(struct fd_monitor *mon, int hdl, int *chain);

/**
 * @brief Resume all pending Java threads in a watch chain.
 *
 * Sends a command to the monitor thread, which walks the chain starting
 * at @a chain_head and resumes every thread that has a pending watch.
 * Does @b not close dup'd fds or remove from epoll — that is
 * @c fd_monitor_unwatch()'s responsibility.
 *
 * @note Thread-safe.  Uses only the atomic command pipe.
 *
 * @param[in] mon         the monitor instance
 * @param[in] chain_head  head index of the watch chain (-1 = empty)
 * @return FD_MONITOR_OK on success, FD_MONITOR_ERROR on failure
 */
int fd_monitor_resume_all(struct fd_monitor *mon, int chain_head);

#ifdef __cplusplus
}
#endif

#endif /* FD_MONITOR_H */
