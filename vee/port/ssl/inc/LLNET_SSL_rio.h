/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#ifndef LLNET_SSL_RIO_H
#define LLNET_SSL_RIO_H

/**
 * @file
 * @brief rio override of the OpenSSL SSL socket wait seams.
 *
 * The SSL counterpart of net's LLNET_rio.h: routes the blocking SSL wait to
 * rio_wait_ready() instead of async_select.  A rio veeport includes this from
 * its LLNET_SSL_configuration.h ahead of the canonical #ifndef async_select
 * defaults so the override wins; the canonical LLNET_SSL_SOCKET_impl.c is reused
 * unchanged (it re-enters itself on resume, so no resume shim is needed).  This
 * seam configures the wait only.
 */

#include <stdint.h>
#include <sni.h>                /* SNI_throwNativeIOException */

#include "rio.h"
#include "rio_util.h"          /* rio_remaining_to_deadline */
#include "rio_selector.h"      /* RIO_EVENT_READABLE / RIO_EVENT_WRITABLE */
#include "LLNET_SSL_ERRORS.h"  /* J_SOCKET_TIMEOUT */

/* rio sockets are always non-blocking → no-op success (0). */
#define llnet_ssl_set_non_blocking(fd)  (0)

/* The worker owns the deadline, so the absolute timeout is converted to the
 * remaining relative timeout; an already-expired finite deadline throws
 * J_SOCKET_TIMEOUT (this seam supplies its own callback, so rio_wait_ready
 * leaves the timeout decision to it rather than throwing itself), matching the
 * async_select default's SocketTimeoutException. */
#define LLNET_SSL_WAIT_READ(fd, absolute_timeout_ms, callback)                          \
		do {                                                                            \
			int32_t _rel = rio_remaining_to_deadline(absolute_timeout_ms);              \
			if (((absolute_timeout_ms) != 0) && (_rel <= 0)) {                          \
				(void)SNI_throwNativeIOException(J_SOCKET_TIMEOUT, "SSL read timeout"); \
			} else {                                                                    \
				rio_wait_ready((fd), RIO_EVENT_READABLE, _rel, (callback), NULL);       \
			}                                                                           \
		} while (0)
#define LLNET_SSL_WAIT_WRITE(fd, absolute_timeout_ms, callback)                          \
		do {                                                                             \
			int32_t _rel = rio_remaining_to_deadline(absolute_timeout_ms);               \
			if (((absolute_timeout_ms) != 0) && (_rel <= 0)) {                           \
				(void)SNI_throwNativeIOException(J_SOCKET_TIMEOUT, "SSL write timeout"); \
			} else {                                                                     \
				rio_wait_ready((fd), RIO_EVENT_WRITABLE, _rel, (callback), NULL);        \
			}                                                                            \
		} while (0)

#endif /* LLNET_SSL_RIO_H */
