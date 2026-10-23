/*
 * C
 *
 * Copyright 2016-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */
#ifndef LLNET_SSL_UTIL
#define LLNET_SSL_UTIL

#include <openssl/ssl.h>
#include <stdint.h>
#include <LLNET_SSL_CONSTANTS.h>
#include "LLNET_Common.h"
#include "veeport_logger.h"
#include "veeport_errors.h"

/**
 * @brief Name of the log module shared by every source file of the SSL Abstraction Layer.
 *
 * Each source file that logs registers the module with VEEPORT_LOGGER_DEFINE_MODULE().
 */
#define LLNET_SSL_LOG_MODULE_NAME "ssl"

/**
 * @brief Verbosity of the SSL Abstraction Layer.
 *
 * Override it in veeport_configuration.h with one of VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF
 * or _DBG.
 */
#ifndef LLNET_SSL_LOG_LEVEL
#define LLNET_SSL_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

/**
 * @file
 * @brief LLNET_SSL_X509_CERT implementation over OpenSSL header.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates an X509 certificate from the given certificate data pointed by cert.
 * Stores in format the format of the certificate (CERT_PEM_FORMAT or CERT_DER_FORMAT).
 *
 * format may be null.
 *
 * Returns the created X509 or null on error.
 */
X509 * LLNET_SSL_X509_CERT_create(const uint8_t *cert, int32_t off, int32_t len, int32_t *format);

/**
 * @brief Logs OpenSSL's error stack, one message per entry, and empties it.
 */
void LLNET_SSL_print_errors(void);

/**
 * @brief Translate error code from OpenSSL to MicroEJ.
 *
 * @param ssl OpenSSL context object.
 * @param error Code returned by OpenSSL.
 * @return int32_t The value of the MicroEJ error code.
 */
int32_t LLNET_SSL_TranslateReturnCode(const SSL *ssl, int32_t error);

/**
 * @brief Handles the error of a non-blocking SSL operation that must wait for the socket.
 *
 * Throws an SNI NativeIOException with the SSL code J_SOCKET_TIMEOUT when the absolute
 * timeout is reached. The SSL library maps only this code to a SocketTimeoutException;
 * the NET code J_ETIMEDOUT that LLNET_handle_blocking_operation_error() throws reaches
 * the application as a generic IOException. Otherwise the wait is delegated to
 * LLNET_handle_blocking_operation_error().
 *
 * @param[in] fd the file descriptor on which the error has occurred.
 * @param[in] fd_errno the error code to be handled.
 * @param[in] operation the async_select operation to wait for.
 * @param[in] absolute_timeout_ms the absolute timeout in milliseconds, or 0 for no timeout.
 * @param[in] callback the SNI callback to call when the operation can be retried.
 * @param[in] callback_suspend_arg the SNI suspend callback argument.
 */
void LLNET_SSL_handle_blocking_operation_error(int32_t fd, int32_t fd_errno, select_operation operation,
                                               int64_t absolute_timeout_ms, SNI_callback callback,
                                               void *callback_suspend_arg);

/**
 * @brief Throws the NativeIOException of a failed SSL operation.
 *
 * The message reaches Java only with the generic code J_UNKNOWN_ERROR. With a specific code, it goes to a
 * debug log instead.
 *
 * @param[in] error_code one of the codes of LLNET_SSL_ERRORS.h.
 * @param[in] message what failed.
 */
void LLNET_SSL_throw_caught_exception(int32_t error_code, const char *message);

/**
 * @brief Throws the NativeException of a failed SSL operation. Same message rule as
 * LLNET_SSL_throw_caught_exception().
 *
 * @param[in] error_code one of the codes of LLNET_SSL_ERRORS.h.
 * @param[in] message what failed.
 */
void LLNET_SSL_throw_runtime_exception(int32_t error_code, const char *message);

#ifdef __cplusplus
}
#endif

#endif // ifndef LLNET_SSL_UTIL
