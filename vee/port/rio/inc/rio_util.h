/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief rio shared inline helpers.
 * @author @CCO_AUTHOR@
 * @version 1.0.0
 * @date @CCO_DATE@
 *
 * Header-only utilities reused across rio-core, rio-net-bsd,
 * rio-pipe-socketpair, and net-rio-wait.  Each helper is a tiny inline
 * function — the compiler folds them into every call site, so this
 * factoring removes duplication without adding indirection.
 *
 * `rio_set_nonblocking` is POSIX-flavoured (fcntl).  Consumers that
 * link against a non-POSIX socket stack typically don't include this
 * header — their backend creates non-blocking fds via stack-specific
 * APIs (e.g., pipe-posix uses `pipe2(O_NONBLOCK)`).
 */

#ifndef RIO_UTIL_H
#define RIO_UTIL_H

#include <fcntl.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Monotonic time source provided by the Core Engine on every VEE port. */
extern int64_t LLMJVM_IMPL_getCurrentTime__Z(uint8_t system);

/**
 * Switches a file descriptor to non-blocking mode.
 *
 * @param fd  file descriptor.
 * @return 0 on success, -1 on failure (errno set by fcntl).
 */
static inline int rio_set_nonblocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * Converts an absolute deadline (in monotonic milliseconds) to a
 * relative timeout suitable for `rio_wait_ready` and other blocking
 * primitives that interpret 0 as "infinite".
 *
 * @param absolute_deadline_ms  monotonic deadline; 0 means infinite.
 * @return -1 for infinite, 0 if the deadline has already expired,
 *         otherwise the remaining milliseconds clamped to INT32_MAX.
 */
static inline int32_t rio_remaining_to_deadline(int64_t absolute_deadline_ms) {
	if (absolute_deadline_ms == 0) {
		return -1;
	}
	int64_t remaining = absolute_deadline_ms - LLMJVM_IMPL_getCurrentTime__Z(1);
	if (remaining <= 0) {
		return 0;
	}
	if (remaining > (int64_t)INT32_MAX) {
		return INT32_MAX;
	}
	return (int32_t)remaining;
}

#ifdef __cplusplus
}
#endif

#endif /* RIO_UTIL_H */
