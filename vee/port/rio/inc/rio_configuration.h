/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief rio event loop configuration.
 * @author @CCO_AUTHOR@
 * @version 1.0.0
 * @date @CCO_DATE@
 */

#ifndef RIO_CONFIGURATION_H
#define RIO_CONFIGURATION_H

#include "veeport_logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compatibility sanity check value.
 *
 * This define value is checked in the implementation to validate that
 * the version of this configuration is compatible with the implementation.
 *
 * This value must not be changed by the user of the CCO.
 */
#define RIO_CONFIGURATION_VERSION (2)

/* I/O selector backend.
 *
 * Each selector backend lives in its own .c file under rio-core/src.
 * The BSP build picks exactly one by compiling the corresponding .c
 * file — no header define needed.  Linking two backends in the same
 * image produces duplicate-symbol errors that surface the mistake at
 * link time.
 *
 * Reference (in canonical rio-core):
 *   rio_poll.c     POSIX poll() + wake pipe (default, portable)
 *   rio_select.c   POSIX select() + wake pipe (when poll() unavailable)
 */

/**
 * @brief Maximum number of I/O sources that can be in flight in the
 * event loop at any one moment.
 *
 * Each `rio_poll()` and `rio_wait_ready()` call allocates one slot
 * per registered fd from a fixed-size pool; the slot is returned to
 * the pool when the call's SNI callback fires.  Sizing it lets you
 * support either one Java thread polling N fds, several threads
 * each polling N/threads fds, or any mix in between.
 *
 * The worker thread's internal fd set is sized to MAX_SOURCES + 1
 * (extra slot for the wake mechanism).
 */
#define RIO_MAX_SOURCES (64)

/**
 * @brief Stack size (in bytes) for the rio worker thread.
 *
 * The worker thread runs the I/O multiplexing primitive and processes
 * results.  It may allocate backend-specific arrays on the stack, so
 * the stack must be large enough to hold those plus normal function
 * call overhead.
 *
 * Typical values: 4096 for constrained RTOSes, 65536 for Linux.
 */
#define RIO_WORKER_STACK_SIZE (65536)

/**
 * @brief Priority for the rio worker thread.
 *
 * Same value as ASYNC_SELECT_TASK_PRIORITY from the java.net CCO.
 */
#define RIO_WORKER_PRIORITY (12)

/** @brief Name of the log module of the rio abstraction layer. */
#define LLRIO_LOG_MODULE_NAME "rio"

/**
 * @brief Log level of the rio abstraction layer. Override it in veeport_configuration.h.
 */
#ifndef LLRIO_LOG_LEVEL
#define LLRIO_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

#ifdef __cplusplus
}
#endif

#endif /* RIO_CONFIGURATION_H */
