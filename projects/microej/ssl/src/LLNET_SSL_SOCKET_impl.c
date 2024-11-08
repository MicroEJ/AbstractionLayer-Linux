/*
 * C
 *
 * Copyright 2015-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include <LLNET_SSL_SOCKET_impl.h>
#include <LLNET_SSL_CONSTANTS.h>
#include <LLNET_SSL_util.h>
#include <LLNET_CHANNEL_impl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <LLNET_SSL_ERRORS.h>
#include <LLNET_CHANNEL_impl.h>
#include <LLNET_SSL_verifyCallback.h>
#include <LLNET_Common.h>
#include <LLSEC_ERRORS.h>

/**
 * @file
 * @brief LLNET_SSL_SOCKET implementation over OpenSSL.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 25 July 2024
 */

#ifdef __cplusplus
	extern "C" {
#endif

/**
 * Static functions
*/
static void LLNET_SSL_SOCKET_IMPL_initial_handshake(int32_t ssl, int32_t fd, int64_t absolute_java_start_time, int32_t relative_timeout, bool is_client);

void LLNET_SSL_SOCKET_IMPL_initialize(void) {
	LLNET_SSL_DEBUG_TRACE("\n");
	(void)SSL_library_init();
#ifdef LLNET_SSL_DEBUG
	SSL_load_error_strings();
#endif
	return;
}

int32_t LLNET_SSL_SOCKET_IMPL_create(int32_t context, int32_t fd, uint8_t* host_name, int32_t hostname_len, bool auto_close, uint8_t is_client_mode, uint8_t need_client_auth){
	(void)auto_close;
	int32_t ret = SNI_IGNORED_RETURNED_VALUE;
	SSL* ssl;
	SSL_CTX* ctx = (SSL_CTX*)context;

	LLNET_SSL_DEBUG_TRACE("(context=%d, fd=%d)\n", context, fd);

	/* create new SSL session */
	ssl = SSL_new(ctx);
	if (ssl != NULL) {
		if (SSL_set_fd(ssl, fd) != 1) {
			SSL_free(ssl);
			(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "Error setting file descriptor");
		} else {
			//enable peer verification
			if (is_client_mode || need_client_auth) {
				SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, LLNET_SSL_VERIFY_verifyCallback);
			} else {
				SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
			}

			if ((NULL != host_name) && (hostname_len > 0)) {
				(void)SSL_set_tlsext_host_name(ssl, (char*)host_name);
			}
			ret = (int32_t)ssl;
		}
	} else {
		(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "Could not create SSL session");
	}

	return ret;
}

void LLNET_SSL_SOCKET_IMPL_initialServerHandShake(int32_t ssl, int32_t fd, int64_t absolute_java_start_time, int32_t relative_timeout) {
	LLNET_SSL_SOCKET_IMPL_initial_handshake(ssl, fd, absolute_java_start_time, relative_timeout, false);
}

void LLNET_SSL_SOCKET_IMPL_initialClientHandShake(int32_t ssl, int32_t fd, int64_t absolute_java_start_time, int32_t relative_timeout) {
	LLNET_SSL_SOCKET_IMPL_initial_handshake(ssl, fd, absolute_java_start_time, relative_timeout, true);
}

static void LLNET_SSL_SOCKET_IMPL_initial_handshake(int32_t ssl, int32_t fd, int64_t absolute_java_start_time, int32_t relative_timeout, bool is_client) {
	int32_t ret;
	SNI_callback callback = NULL;
	LLNET_SSL_DEBUG_TRACE("(ssl=%d, fd=%d, is_client=%d)\n", ssl, fd, is_client);

	//set non-blocking mode
	if (LLNET_set_non_blocking(fd) < 0) {
		(void)SNI_throwNativeIOException(J_SOCKET_ERROR, "Could not set socket non blocking");
	}

	//initiates handshake in non-blocking mode
	if (is_client) {
		callback = (SNI_callback)LLNET_SSL_SOCKET_IMPL_initialClientHandShake;
		ret = SSL_connect((SSL*)ssl);
	} else {
		callback = (SNI_callback)LLNET_SSL_SOCKET_IMPL_initialServerHandShake;
		ret = SSL_accept((SSL*)ssl);
	}

	//reset non-blocking mode
	if (LLNET_set_non_blocking(fd) < 0) {
		(void)SNI_throwNativeIOException(J_SOCKET_ERROR, "Could not set socket non blocking");
	}

	if (ret != 1) {
		int32_t ssl_error = SSL_get_error((SSL*)ssl, ret);
		int64_t absolute_timeout_ms = 0;
		if (0 != relative_timeout) {
			absolute_timeout_ms = absolute_java_start_time + (int64_t) relative_timeout;
		}

		if (ssl_error == SSL_ERROR_WANT_READ) {
			LLNET_handle_blocking_operation_error(fd, llnet_errno(fd), SELECT_READ, absolute_timeout_ms, callback, NULL);
		} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
			LLNET_handle_blocking_operation_error(fd, llnet_errno(fd), SELECT_WRITE, absolute_timeout_ms, callback, NULL);
		} else {
			LLNET_SSL_DEBUG_PRINT_ERR();
			(void)SNI_throwNativeIOException(LLNET_SSL_TranslateReturnCode((SSL*)ssl, ssl_error), "Initial handshake error");
		}
	}
}

int32_t LLNET_SSL_SOCKET_IMPL_read(int32_t ssl, int32_t fd, int8_t *buffer, int32_t offset, int32_t length,
                                   int64_t absolute_java_start_time, int32_t relative_timeout) {
	int ret = J_SSL_NO_ERROR;
	LLNET_SSL_DEBUG_TRACE("(ssl=0x%x, fd=%d, offset=%d, length=%d)\n", ssl, fd, offset, length);
	//set non-blocking mode
	if (LLNET_set_non_blocking(fd) < 0) {
		(void)SNI_throwNativeIOException(LLNET_SSL_TranslateReturnCode((SSL *)ssl, ret), "Could not set blocking mode");
		ret = J_SOCKET_ERROR;
	}

	// Check the shutdown status.
	int shutdown_status = SSL_get_shutdown((SSL *)ssl);
	//non-blocking read
	if (((SSL *)ssl != NULL) && (shutdown_status == 0)) {
		ret = SSL_read((SSL *)ssl, buffer + offset, length);
	}

	//reset non-blocking mode
	if (LLNET_set_non_blocking(fd) < 0) {
		(void)SNI_throwNativeIOException(LLNET_SSL_TranslateReturnCode((SSL *)ssl, ret), "Could not set blocking mode");
		ret = J_SOCKET_ERROR;
	}

	if ((ret <= 0) && (J_SOCKET_ERROR != ret)) {
		int32_t ssl_error = SSL_get_error((SSL *)ssl, ret);
		int64_t absolute_timeout_ms = 0;
		if (0 != relative_timeout) {
			absolute_timeout_ms = absolute_java_start_time + (int64_t)relative_timeout;
		}

		if (ssl_error == SSL_ERROR_WANT_READ) {
			LLNET_SSL_handle_blocking_operation_error(fd, llnet_errno(fd), SELECT_READ, absolute_timeout_ms,
			                                          (SNI_callback)LLNET_SSL_SOCKET_IMPL_read, NULL);
		} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
			//read operation can also cause write operation when the peer requests a re-negotiation
			LLNET_SSL_handle_blocking_operation_error(fd, llnet_errno(fd), SELECT_WRITE, absolute_timeout_ms,
			                                          (SNI_callback)LLNET_SSL_SOCKET_IMPL_read, NULL);
		} else if ((ssl_error == SSL_ERROR_ZERO_RETURN) || (ssl_error == SSL_ERROR_SSL)) {
			ret = J_EOF;
		} else {
			(void)SNI_throwNativeIOException(LLNET_SSL_TranslateReturnCode((SSL *)ssl, ssl_error), "Read error");
			ret = SNI_IGNORED_RETURNED_VALUE;
		}
	}

	return ret;
}

int32_t LLNET_SSL_SOCKET_IMPL_write(int32_t ssl, int32_t fd, int8_t* buffer, int32_t offset, int32_t length, int64_t absolute_java_start_time, int32_t relative_timeout){
	int ret = SNI_IGNORED_RETURNED_VALUE;
	LLNET_SSL_DEBUG_TRACE("(ssl=0x%x, fd=%d, offset=%d, length=%d)\n", ssl, fd, offset, length);

	//set non-blocking mode
	if (LLNET_set_non_blocking(fd) < 0) {
		(void)SNI_throwNativeIOException(J_SOCKET_ERROR, "Could not set socket non blocking");
	}

	//non-blocking read
	ret = SSL_write((SSL*)ssl, buffer+offset, length);

	//reset non-blocking mode
	if (LLNET_set_non_blocking(fd) < 0) {
		(void)SNI_throwNativeIOException(J_SOCKET_ERROR, "Could not set socket non blocking");
		ret = SNI_IGNORED_RETURNED_VALUE;
	}

	if (ret <= 0) {
		int32_t ssl_error = SSL_get_error((SSL*)ssl, ret);
		int64_t absolute_timeout_ms = 0;
		if (0 != relative_timeout) {
			absolute_timeout_ms = absolute_java_start_time + (int64_t) relative_timeout;
		}

		if (ssl_error == SSL_ERROR_WANT_READ) {
			//write operation can also cause read operation when the peer requests a re-negotiation
			 LLNET_handle_blocking_operation_error(fd, llnet_errno(fd), SELECT_READ, absolute_timeout_ms, (SNI_callback)LLNET_SSL_SOCKET_IMPL_write, NULL);
		} else if (ssl_error == SSL_ERROR_WANT_WRITE) {
			LLNET_handle_blocking_operation_error(fd, llnet_errno(fd), SELECT_WRITE, absolute_timeout_ms, (SNI_callback)LLNET_SSL_SOCKET_IMPL_write, NULL);
		} else if((llnet_errno(fd) == ECONNRESET) || (llnet_errno(fd) == EPIPE)){
			//check if connection reset
			//treat epipe as reset
			(void)SNI_throwNativeIOException(J_CONNECTION_RESET, "Connection reset");
			ret = SNI_IGNORED_RETURNED_VALUE;
		} else {
			(void)SNI_throwNativeIOException(LLNET_SSL_TranslateReturnCode((SSL *)ssl, ssl_error), "Write error");
			ret = SNI_IGNORED_RETURNED_VALUE;
		}
	}

	return ret;
}

int32_t LLNET_SSL_SOCKET_IMPL_available(int32_t ssl){
	LLNET_SSL_DEBUG_TRACE("(ssl=%d)\n", ssl);
	int ret = SSL_pending((SSL*)ssl);
	if(ret < 0) {
		ret = J_UNKNOWN_ERROR;
	}
	return ret;
}

void LLNET_SSL_SOCKET_IMPL_freeSSL(int32_t ssl_id) {
	LLNET_SSL_DEBUG_TRACE("(ssl=0x%x)\n", ssl_id);
	SSL* ssl = (SSL*)ssl_id;
	(void)SSL_free(ssl);
	return;
}

void LLNET_SSL_SOCKET_IMPL_shutdown(int32_t ssl_id, int32_t fd, bool autoclose, int64_t absolute_java_start_time,
                                    int32_t relative_timeout) {
	LLNET_SSL_DEBUG_TRACE(" ssl=0x%x, fd=%d, autoclose=%s, java_start=%lld, timeout=%d\n", ssl_id, fd,
	                      autoclose ? "true" : "false", absolute_java_start_time, relative_timeout);
	SSL *ssl = (SSL *)ssl_id;

	// Send close notify
	int ret = SSL_shutdown(ssl);

	// Wait for peer close notify
	if ((0 == ret) && !autoclose) {
		ret = SSL_shutdown(ssl);
		if (1 != ret) {
			int ssl_error = SSL_get_error(ssl, ret);
			if (SSL_ERROR_WANT_READ == ssl_error) {
				int64_t absolute_timeout_ms = 0;
				if (0 != relative_timeout) {
					absolute_timeout_ms = absolute_java_start_time + (int64_t)relative_timeout;
				}
				LLNET_handle_blocking_operation_error(fd, llnet_errno(fd), SELECT_READ, absolute_timeout_ms,
				                                      (SNI_callback)LLNET_SSL_SOCKET_IMPL_shutdown, NULL);
			} else {
				(void)SNI_throwNativeIOException(LLNET_SSL_TranslateReturnCode(ssl, ret), "Error during shutdown");
			}
		} else {
			LLNET_SSL_DEBUG_TRACE("Shutdown successful\n");
		}
	} else {
		LLNET_SSL_DEBUG_TRACE("Shutdown successful\n");
	}
}

#ifdef __cplusplus
}
#endif
