/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief net-over-rio wait seam.
 *
 * Overrides bsp-net-bsd's @c LLNET_WAIT_OPERATION seam so a would-block socket
 * operation suspends on rio's event loop (@c rio_wait_ready) instead of issuing
 * an @c async_select request.  The canonical @c LLNET_*_bsd.c natives are reused
 * unchanged: they run over real non-blocking BSD sockets and only their
 * readiness wait is routed to rio.  This replaces the former per-native
 * reimplementation of the whole LLNET socket-channel surface.
 *
 * A rio veeport makes this override visible ahead of bsp-net-bsd's default by
 * including this header from its @c LLNET_configuration.h, which
 * @c LLNET_Common.h includes before @c LLNET_Common.c falls back to its own
 * @c \#ifndef default.
 *
 * No resume shim is needed.  @c rio_wait_ready registers the per-wait source as
 * an SNI scoped resource that the VM frees on every native exit (return-to-Java
 * and app/VM stop), and the canonical natives re-enter themselves on resume —
 * so the callback is the public entry point, exactly as the async_select
 * default already expects.
 */

#ifndef LLNET_RIO_H
#define LLNET_RIO_H

#include "rio.h"
#include "rio_util.h"      /* rio_remaining_to_deadline */
#include "async_select.h"  /* select_operation: SELECT_READ / SELECT_WRITE */
#include "LLNET_ERRORS.h"  /* J_ETIMEDOUT */

#include <sni.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** rio interest flags (RIO_EVENT_READABLE / RIO_EVENT_WRITABLE). */
#define LLNET_RIO_INTEREST_READABLE 0x0001
#define LLNET_RIO_INTEREST_WRITABLE 0x0004

/*
 * Suspend on rio until the fd is ready for the operation.  rio sockets are
 * always non-blocking and the rio worker owns the deadline, so the absolute
 * timeout is converted to the remaining relative timeout.  Because this seam
 * passes its own callback, rio_wait_ready leaves the timeout decision to that
 * callback rather than throwing itself, so an already-expired finite deadline
 * is reported here as J_ETIMEDOUT (matching the async_select default).  The
 * suspend arg (e.g. the partial-write counter) flows through unchanged.
 */
#define LLNET_WAIT_OPERATION(fd, operation, absolute_timeout_ms, callback, callback_suspend_arg) \
		do {                                                                                     \
			int32_t _rel = rio_remaining_to_deadline((absolute_timeout_ms));                     \
			if (((absolute_timeout_ms) != 0) && (_rel <= 0)) {                                   \
				(void)SNI_throwNativeIOException(J_ETIMEDOUT, "timeout");                        \
			} else {                                                                             \
				rio_wait_ready((fd),                                                             \
							   ((operation) == SELECT_READ) ? LLNET_RIO_INTEREST_READABLE        \
														: LLNET_RIO_INTEREST_WRITABLE,           \
							   _rel, (callback), (callback_suspend_arg));                        \
			}                                                                                    \
		} while (0)

/*
 * Initialise the readiness mechanism: start rio (worker + source pool).
 *
 * rio_init() returns the source-pool size (not a 0/non-zero status) and reports
 * its own failure by throwing an SNI exception, so there is no status code to
 * forward.  The comma operator `(A, B)` evaluates A then yields B: here it runs
 * rio_init() for its side effect, discards the pool-size return, and yields 0 —
 * success per the seam's "0 == success" contract.  On failure, rio_init()'s own
 * (specific) exception stays pending and propagates; yielding 0 keeps the caller
 * from overwriting it with a generic "init error".  async_select is not used.
 */
#define LLNET_INIT_WAIT_MECHANISM()  (rio_init(), 0)

/*
 * An fd was closed: wake any rio waiter blocked on it.  rio_close_fd marks the
 * active sources on the fd and wakes the worker, which resumes the waiters (they
 * retry and get EBADF) — the rio equivalent of async_select_notify_closed_fd,
 * needed because poll()/select() do not auto-detect a concurrent close.
 */
#define LLNET_NOTIFY_CLOSED_FD(fd)   rio_close_fd(fd)

#ifdef __cplusplus
}
#endif

#endif /* LLNET_RIO_H */
