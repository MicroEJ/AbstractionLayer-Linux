/*
 * C
 *
 * Copyright 2016-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLNET_SSL_UTIL
#define LLNET_SSL_UTIL

#include <openssl/ssl.h>
#include <stdint.h>
#include <LLNET_SSL_CONSTANTS.h>
#include "async_select.h"

/**
 * @file
 * @brief LLNET_SSL_X509_CERT implementation over OpenSSL header.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 25 July 2024
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

#ifdef LLNET_SSL_DEBUG
#define LLNET_SSL_DEBUG_TRACE_INFO printf("[SSL][INFO] %s:%d: ", __func__, __LINE__); printf
/** Print OpenSSL's error stack. */
#define LLNET_SSL_DEBUG_PRINT_ERR  printf("[SSL][ERROR] %s:%d: ", __func__, __LINE__); LLNET_SSL_print_errors
void LLNET_SSL_print_errors();
#else
#define LLNET_SSL_DEBUG_TRACE_INFO(...) ((void)0)
#define LLNET_SSL_DEBUG_PRINT_ERR(...)  ((void)0)
#endif // LLNET_SSL_DEBUG

/**
 * @brief Handle asynchronous operations for SSL sockets.
 *
 * @param[in] fd File descriptor for underlying socket.
 * @param[in] fd_errno File descriptor errno.
 * @param[in] operation Indicates wether the operation is a read or write.
 * @param[in] absolute_timeout_ms Absolute timeout in milliseconds.
 * @param[in] callback SNI callback.
 * @param[in] callback_suspend_arg Pointer to SNI callback argument.
 *
 * @note Throws NativeIOException on error.
 */
void LLNET_SSL_handle_blocking_operation_error(int32_t fd, int32_t fd_errno, select_operation operation,
                                               int64_t absolute_timeout_ms, SNI_callback callback,
                                               void *callback_suspend_arg);

/**
 * @brief Translate error code from OpenSSL to MicroEJ.
 * 
 * @param ssl OpenSSL context object.
 * @param error Code returned by OpenSSL.
 * @return int32_t The value of the MicroEJ error code.
 */
int32_t LLNET_SSL_TranslateReturnCode(const SSL* ssl, int32_t error);

#ifdef __cplusplus
}
#endif

#endif // ifndef LLNET_SSL_UTIL
