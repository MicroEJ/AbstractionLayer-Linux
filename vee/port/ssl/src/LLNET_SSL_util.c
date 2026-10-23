/*
 * C
 *
 * Copyright 2015-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */
#include <stdint.h>
#include <LLNET_SSL_util.h>
#include <LLNET_SSL_CONSTANTS.h>
#include <LLNET_SSL_ERRORS.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

VEEPORT_LOGGER_DEFINE_MODULE(LLNET_SSL_LOG_MODULE_NAME, LLNET_SSL_LOG_LEVEL)

void LLNET_SSL_throw_caught_exception(int32_t error_code, const char *message) {
	if (J_UNKNOWN_ERROR == error_code) {
		VEEPORT_ERRORS_throw_caught_exception_message(error_code, "%s", message);
	} else {
		VEEPORT_LOGGER_LOG_DBG("%s (%d)", message, error_code);
		VEEPORT_ERRORS_throw_caught_exception(error_code);
	}
}

void LLNET_SSL_throw_runtime_exception(int32_t error_code, const char *message) {
	if (J_UNKNOWN_ERROR == error_code) {
		VEEPORT_ERRORS_throw_runtime_exception_message(error_code, "%s", message);
	} else {
		VEEPORT_LOGGER_LOG_DBG("%s (%d)", message, error_code);
		VEEPORT_ERRORS_throw_runtime_exception(error_code);
	}
}

/**
 * @file
 * @brief LLNET_SSL implementation over OpenSSL utility functions.
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
X509 * LLNET_SSL_X509_CERT_create(const uint8_t *cert, int32_t off, int32_t len, int32_t *format) {
	BIO *mem;
	X509 *x509;
	if (format != NULL) {
		*format = J_CERT_PARSE_ERROR; // Error by default
	}

	// Build an InputStream that reads data from the given buffer.
	mem = BIO_new_mem_buf((const uint8_t *)(cert + off), len);

	//check the bio memory buffer
	if (mem == NULL) {
		x509 = NULL;
	} else {
		//try to parse as PEM certificate
		x509 = PEM_read_bio_X509(mem, NULL, NULL, NULL);
		if (x509 != NULL) { //encoded PEM certificate
			if (format != NULL) {
				*format = CERT_PEM_FORMAT;
			}
		} else { //try to parse as DER certificate
			BIO_reset(mem);
			x509 = d2i_X509_bio(mem, NULL);
			if (x509 != NULL) {
				//encoded DER certificate
				if (format != NULL) {
					*format = CERT_DER_FORMAT;
				}
			}
		}
		BIO_vfree(mem);
	}

	return x509;
}

/** @brief Size of the buffer holding one formatted OpenSSL error message. */
#define SSL_ERROR_STRING_SIZE (80U)

void LLNET_SSL_print_errors(void) {
	char buf[SSL_ERROR_STRING_SIZE] = { 0 };
	unsigned long err = ERR_get_error();

	// Empty the OpenSSL error queue, one log message per entry.
	while (0UL != err) {
		ERR_error_string_n(err, buf, sizeof(buf));
		VEEPORT_LOGGER_LOG_ERR("OpenSSL error reason = %s", buf);
		err = ERR_get_error();
	}
}

void LLNET_SSL_handle_blocking_operation_error(int32_t fd, int32_t fd_errno, select_operation operation,
                                               int64_t absolute_timeout_ms, SNI_callback callback,
                                               void *callback_suspend_arg) {
	if ((0 != absolute_timeout_ms) && (absolute_timeout_ms < LLNET_current_time_ms())) {
		(void)SNI_throwNativeIOException(J_SOCKET_TIMEOUT, "timeout");
	} else {
		LLNET_handle_blocking_operation_error(fd, fd_errno, operation, absolute_timeout_ms, callback,
		                                      callback_suspend_arg);
	}
}

#ifdef __cplusplus
}
#endif
