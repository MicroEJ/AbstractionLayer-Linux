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
 * Implements the registry and worker thread for the ej.rio Foundation
 * Library.  The Java side owns the registry; each `Poll.poll()` call
 * passes the full `(fd, interest)` list to `rio_poll()`, which
 * suspends the calling Java thread until events land or the timeout
 * expires.
 *
 * Capabilities:
 * - Fixed-size pool of `rio_source_t` slots, capped by
 *   `RIO_MAX_SOURCES` from the BSP configuration.
 * - One worker thread that runs the selector primitive across the
 *   active source list, resuming each suspended caller exactly once
 *   when any of its sources fires.
 * - SNI callback integration: `rio_poll()` and `rio_wait_ready()`
 *   both suspend via `SNI_suspendCurrentJavaThreadWithCallback`; the
 *   worker resumes the caller when events arrive.
 * - Re-poll on registry changes via a wake mechanism (per-backend).
 * - Per-wait sources are SNI scoped resources: the VM frees each chunk
 *   on return-to-Java and on app/VM stop, so a suspended wait never
 *   leaks.  The free list is owned by the VM C task; the worker owns
 *   the active list.
 *
 * The BSP supplies socket operations through `LLRIO_NET_impl.h`.
 * Thread creation and mutual exclusion go through OSAL so the code
 * is portable across RTOSes.
 */

#ifndef RIO_H
#define RIO_H

#include "rio_configuration.h"
#include <sni.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque source handle.  The full layout lives in `rio_selector.h`
 * (consumed by the selector backends).  A `rio_poll` / `rio_wait_ready`
 * chunk is registered as an SNI scoped resource; the caller's SNI
 * callback recovers it with `SNI_getScopedResource`, and the scoped
 * close frees it automatically — callers never free a source directly.
 */
typedef struct rio_source rio_source_t;

/**
 * Initializes the rio event loop: OSAL mutex, wake mechanism, source
 * pool, and the worker thread.  Called once from `LLRIO_IMPL_init`.
 *
 * @return the maximum number of sources (`RIO_MAX_SOURCES`).
 */
int rio_init(void);

/**
 * Polls a caller-owned registry of sources.  The Java side packs N
 * sources into a single `int[n*3]` buffer: three slots per entry
 * (`fd`, `interestMask`, `revents`).  The caller fills `fd` and
 * `interestMask` and zeroes `revents`; this function suspends the
 * Java thread via SNI, runs the kernel selector on a worker, then
 * resumes the Java thread with each ready source's `revents` slot
 * written in place.
 *
 * The BSP LLAPI shim (`LLRIO_IMPL_poll`) is a thin wrapper around
 * this entry — it does no fd state of its own.
 *
 * Timeout contract (mirrors `rio_wait_ready`'s default callback): when the
 * deadline expires with no source ready, the SNI callback throws a
 * NativeIOException with `J_ETIMEDOUT` rather than reporting a zero ready
 * count.  This covers `timeout_ms == 0` (non-blocking probe: throws at once
 * if nothing is ready) and finite positive timeouts.  A negative timeout
 * (infinite) never throws — the worker resumes only on readiness.
 *
 * Requires `rio_init()` to have completed first: this uses the source pool,
 * mutex, and worker thread that init creates.
 *
 * @param entries     `[fd0, interest0, revents0, fd1, interest1,
 *                    revents1, ...]`, length 3*n.
 * @param n           number of source entries.
 * @param timeout_ms  max wait in milliseconds, negative = infinite.
 * @return SNI_IGNORED_RETURNED_VALUE (the actual ready count is
 *         delivered by the SNI callback as the native's return value;
 *         the callback throws `J_ETIMEDOUT` on a zero ready count).
 */
int rio_poll(int *entries, int n, int timeout_ms);

/**
 * Forces the worker to resume any thread suspended on `fd`.
 * Called from another Java thread's `close()`: the Linux kernel
 * does not auto-unblock `poll()` / `select()` when an fd is
 * closed in another thread, so without this hook the waiter
 * would sleep to its own deadline.  rio walks the active list,
 * marks every source whose fd matches as `closed`, and wakes the
 * worker; the worker dispatches the chunks and resumes the
 * waiting threads.  The resumed code retries its syscall on the
 * now-closed fd and gets `EBADF`, which Java surfaces as a
 * closed-socket exception.
 *
 * Requires `rio_init()` to have completed first: this takes the pool mutex and
 * walks the active list that init creates.
 *
 * @param fd  file descriptor being closed.
 */
void rio_close_fd(int fd);

/**
 * Waits for an fd to become ready for the specified interests.
 * Operates on the fd alone — the primitive used by LLNET /
 * openssl-rio-wait for blocking I/O on socket fds.
 *
 * The caller's callback is re-entered on resume.  The per-wait source is
 * an SNI scoped resource: if the callback needs it, it recovers it with
 * `SNI_getScopedResource` and must NOT free it — the scoped close runs on
 * return-to-Java and performs the two-phase free from the VM C task (never
 * from the worker — the free list is not lock-protected).  The `suspend_arg`
 * the caller passes below flows through unchanged as the SNI suspend arg —
 * typically per-call state (e.g. a `written_so_far` counter for a retry
 * loop); rio does not read it.
 *
 * Timeout contract: with the internal default callback (NULL below — the
 * path used by the rio blocking wrappers via `PollNative.waitReady`),
 * a deadline reached before the fd is ready throws a NativeIOException with
 * `J_ETIMEDOUT`.  A caller-supplied callback (net/openssl-rio-wait) is
 * re-entered on the same deadline and decides for itself — rio does not throw.
 *
 * Requires `rio_init()` to have completed first: this uses the source pool,
 * mutex, and worker thread that init creates.
 *
 * @param fd          file descriptor to wait on.
 * @param interests   interest bitmask (RIO_EVENT_READABLE/WRITABLE).
 * @param timeout_ms  max wait in milliseconds (negative = infinite).
 * @param callback    SNI callback on ready or timeout.  NULL = internal
 *                    default (throws J_ETIMEDOUT on timeout, returns 1 ready).
 * @param suspend_arg argument retrievable in the callback via
 *                    SNI_getCallbackArgs() as the suspend arg.
 *                    May be NULL.
 */
int rio_wait_ready(int fd, int interests, int timeout_ms,
                   SNI_callback callback, void *suspend_arg);

#ifdef __cplusplus
}
#endif

#endif /* RIO_H */
