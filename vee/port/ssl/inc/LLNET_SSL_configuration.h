/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#ifndef LLNET_SSL_CONFIGURATION_H
#define LLNET_SSL_CONFIGURATION_H

/**
 * @file
 * @brief OpenSSL SSL socket configuration for this VEE Port.
 *
 * Mirrors the net LLNET_configuration.h pattern: the readiness wait is routed to
 * rio when the build selects rio (LLNET_WAIT_WITH_RIO, defined by CMake when
 * BUILD_RIO is ON) by including the rio SSL seam ahead of the canonical
 * #ifndef defaults so the override wins.  When rio is not built, the defaults
 * below reproduce the standard OpenSSL + async_select behaviour.
 */

#if defined(LLNET_WAIT_WITH_RIO)
#include "LLNET_SSL_rio.h"
#endif

#include <openssl/ssl.h>
#include "async_select.h"
#include "LLNET_SSL_util.h"

/* --- Transport bind ----------------------------------------------------- */
/* Default: OpenSSL's built-in socket BIO via SSL_set_fd, correct whenever the
 * fd is a real kernel descriptor. */
#ifndef llnet_ssl_set_transport
#define llnet_ssl_set_transport(ssl, fd)  (SSL_set_fd((ssl), (fd)) == 1)
#endif

/* --- Non-blocking mode -------------------------------------------------- */
/* Default: the net-common LLNET_set_non_blocking (returns < 0 on error). */
#ifndef llnet_ssl_set_non_blocking
#define llnet_ssl_set_non_blocking(fd)  LLNET_set_non_blocking(fd)
#endif

/* --- Blocking wait ------------------------------------------------------ */
/* Default: the async_select request mechanism, through the SSL helper so a reached
 * timeout is reported with the SSL error code. */
#ifndef LLNET_SSL_WAIT_READ
#define LLNET_SSL_WAIT_READ(fd, absolute_timeout_ms, callback)                                               \
		LLNET_SSL_handle_blocking_operation_error((fd), llnet_errno(fd), SELECT_READ, (absolute_timeout_ms), \
												  (callback), NULL)
#endif
#ifndef LLNET_SSL_WAIT_WRITE
#define LLNET_SSL_WAIT_WRITE(fd, absolute_timeout_ms, callback)                                               \
		LLNET_SSL_handle_blocking_operation_error((fd), llnet_errno(fd), SELECT_WRITE, (absolute_timeout_ms), \
												  (callback), NULL)
#endif

#endif /* LLNET_SSL_CONFIGURATION_H */
