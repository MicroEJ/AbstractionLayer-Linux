/*
 * C
 *
 * Copyright 2015-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include <LLNET_SSL_SOCKET_impl.h>
#include <LLNET_SSL_CONSTANTS.h>
#include <LLNET_SSL_util.h>
#include <LLNET_CONSTANTS.h>
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

/**
 * @file
 * @brief LLNET_SSL_SOCKET implementation over OpenSSL.
 * @author @CCO_AUTHOR@
 * @version @CCO_VERSION@
 * @date @CCO_DATE@
 */

#ifdef __cplusplus
	extern "C" {
#endif

/* external functions */
extern int32_t LLNET_SSL_TranslateReturnCode(SSL* ssl, int32_t openSSL_error);

static int32_t ssl_asyncOperation(int32_t fd, int32_t operation, uint8_t retry);

int32_t LLNET_SSL_SOCKET_IMPL_initialize(){
	LLNET_SSL_DEBUG_TRACE("%s()\n", __func__);
	SSL_library_init();
#ifdef LLNET_SSL_DEBUG
	SSL_load_error_strings();
#endif
	return J_SSL_NO_ERROR;
}

int32_t LLNET_SSL_SOCKET_IMPL_create(int32_t context, int32_t fd, uint8_t* hostName, int32_t hostnameLen, uint8_t autoclose, uint8_t isClientMode, uint8_t needClientAuth, uint8_t retry){
	LLNET_SSL_DEBUG_TRACE("%s\n", __func__);
	SSL* ssl;
	SSL_CTX* ctx = (SSL_CTX*)context;

	LLNET_SSL_DEBUG_TRACE("%s(context=%d, fd=%d)\n", __func__, context, fd);

    /* create new SSL session */
	ssl = SSL_new(ctx);
	if(ssl != NULL){
		if(SSL_set_fd(ssl, fd) != 1){
			SSL_free(ssl);
			return J_CREATE_SSL_ERROR; //error
		}else{
			// TODO update to use isClientMode and needClientAuth
			//enable peer verification
			if (isClientMode || needClientAuth) {
				SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, LLNET_SSL_VERIFY_verifyCallback);
			} else {
				SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
			}

			if ((NULL != hostName) && (hostnameLen > 0)) {
				SSL_set_tlsext_host_name(ssl, (char*)hostName);
			}
		}
	}else{
		return J_CREATE_SSL_ERROR; //error
	}

	return (int32_t)ssl;
}

int32_t LLNET_SSL_SOCKET_IMPL_close(int32_t jssl, int32_t fd, uint8_t autoclose, uint8_t retry){
	LLNET_SSL_DEBUG_TRACE("%s(ssl=%d, fd=%d, autoclose=%d, retry=%d)\n", __func__, jssl, fd, autoclose, retry);
	SSL* ssl = (SSL*)jssl;

	if(!retry){
		//set non-blocking mode
		if(LLNET_CHANNEL_IMPL_setBlocking(fd, 0, retry) < 0){
			return J_SOCKET_ERROR;
		}

		//shutdown to try sending a close notify alert
		SSL_shutdown(ssl);

		//reset non-blocking mode
		if(LLNET_CHANNEL_IMPL_setBlocking(fd, 1, retry) < 0){
			return J_SOCKET_ERROR;
		}

	}

	if(!autoclose){
		//the close of the underlying socket is not requested
		//read close_notify alert to clear input stream
		int8_t buffer[1];
		int32_t res = LLNET_SSL_SOCKET_IMPL_read(jssl, fd, buffer, 0, 1, retry);

		if(res == J_NATIVE_CODE_BLOCKED_WITHOUT_RESULT || (res >= 0 && !(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))){
			//read operation does not failed and the close notify alert is not yet received
			return J_NATIVE_CODE_BLOCKED_WITHOUT_RESULT;
		}
	}

	return J_SSL_NO_ERROR;
}

int32_t LLNET_SSL_SOCKET_IMPL_initialServerHandShake(int32_t ssl, int32_t fd, uint8_t retry) {
	int32_t ret;
	LLNET_SSL_DEBUG_TRACE("%s(ssl=%d, fd=%d, retry=%d)\n", __func__, ssl, fd, retry);

	//set non-blocking mode
	if(LLNET_CHANNEL_IMPL_setBlocking(fd, 0, retry) < 0){
		return J_SOCKET_ERROR;
	}

	//initiates handshake in non-blocking mode
	ret = SSL_accept((SSL*)ssl);

	//reset non-blocking mode
	if(LLNET_CHANNEL_IMPL_setBlocking(fd, 1, retry) < 0){
		return J_SOCKET_ERROR;
	}

	if(ret != 1){
		int32_t err = SSL_get_error((SSL*)ssl, ret);

		if(err == SSL_ERROR_WANT_READ){
			return ssl_asyncOperation(fd, SELECT_READ, retry);
		}
		else if(err == SSL_ERROR_WANT_WRITE){
			return ssl_asyncOperation(fd, SELECT_WRITE, retry);
		}
		return LLNET_SSL_TranslateReturnCode((SSL*)ssl, ret);
	}
	return J_SSL_NO_ERROR;
}

int32_t LLNET_SSL_SOCKET_IMPL_freeSSL(int32_t jssl, uint8_t retry){
	LLNET_SSL_DEBUG_TRACE("%s\n", __func__);
	SSL* ssl = (SSL*)jssl;

	SSL_free(ssl);
	return J_SSL_NO_ERROR;
}


static int32_t ssl_asyncOperation(int32_t fd, int32_t operation, uint8_t retry){


	int32_t res = asyncOperation(fd, operation, retry);
	if(J_NET_NATIVE_CODE_BLOCKED_WITHOUT_RESULT == res){
		// request added in the queue
		return J_NATIVE_CODE_BLOCKED_WITHOUT_RESULT;
	}
	// requests queue limit reached
	return J_BLOCKING_QUEUE_LIMIT_REACHED;
}


int32_t LLNET_SSL_SOCKET_IMPL_initialClientHandShake(int32_t ssl, int32_t fd, uint8_t retry){
	uint32_t err;
	int ret;
	LLNET_SSL_DEBUG_TRACE("%s(ssl=%d, fd=%d, retry=%d)\n", __func__, ssl, fd, retry);

	//set non-blocking mode
	if(LLNET_CHANNEL_IMPL_setBlocking(fd, 0, retry) < 0){
		return J_SOCKET_ERROR;
	}

	//initiates handshake in non-blocking mode
	ret = SSL_connect((SSL*)ssl);

	if(1 != ret) {
		LLNET_SSL_DEBUG_PRINT_ERR();
	}
	//reset non-blocking mode
	if(LLNET_CHANNEL_IMPL_setBlocking(fd, 1, retry) < 0){
		return J_SOCKET_ERROR;
	}

	if(ret != 1){
		err = SSL_get_error((SSL*)ssl, ret);

		if(err == SSL_ERROR_WANT_READ){
			return ssl_asyncOperation(fd, SELECT_READ, retry);
		}
		else if(err == SSL_ERROR_WANT_WRITE){
			return ssl_asyncOperation(fd, SELECT_WRITE, retry);
		}
		return LLNET_SSL_TranslateReturnCode((SSL*)ssl, ret);
	}
	return J_SSL_NO_ERROR;
}

int32_t LLNET_SSL_SOCKET_IMPL_read(int32_t ssl, int32_t fd, int8_t* buffer, int32_t offset, int32_t length, uint8_t retry){
	int ret;
	LLNET_SSL_DEBUG_TRACE("%s(ssl=%d, fd=%d, offset=%d, length=%d, retry=%d)\n", __func__, ssl, fd, offset, length, retry);
	//set non-blocking mode
	if(LLNET_CHANNEL_IMPL_setBlocking(fd, 0, retry) < 0){
		return J_SOCKET_ERROR;
	}

	//non-blocking read
	ret = SSL_read((SSL*)ssl, buffer+offset, length);

	//reset non-blocking mode
	if(LLNET_CHANNEL_IMPL_setBlocking(fd, 1, retry) < 0){
		return J_SOCKET_ERROR;
	}

	if(ret < 0){
		int32_t err = SSL_get_error((SSL*)ssl, ret);
		if(err == SSL_ERROR_WANT_READ){
			 return ssl_asyncOperation(fd, SELECT_READ, retry);
		}
		else if(err == SSL_ERROR_WANT_WRITE){
			//read operation can also cause write operation when the peer requests a re-negotiation
			return ssl_asyncOperation(fd, SELECT_WRITE, retry);
		}
		return LLNET_SSL_TranslateReturnCode((SSL*)ssl, ret);
	}
	
	if(ret == 0){
		//end-of-file
		return J_EOF;
	}
	
	return ret;
}


int32_t LLNET_SSL_SOCKET_IMPL_write(int32_t ssl, int32_t fd, int8_t* buffer, int32_t offset, int32_t length, uint8_t retry){
	int ret;
	LLNET_SSL_DEBUG_TRACE("%s(ssl=%d, fd=%d, offset=%d, length=%d, retry=%d)\n", __func__, ssl, fd, offset, length, retry);

	//set non-blocking mode
	if(LLNET_CHANNEL_IMPL_setBlocking(fd, 0, retry) < 0){
		return J_SOCKET_ERROR;
	}

	//non-blocking read
	ret = SSL_write((SSL*)ssl, buffer+offset, length);

	//reset non-blocking mode
	if(LLNET_CHANNEL_IMPL_setBlocking(fd, 1, retry) < 0){
		return J_SOCKET_ERROR;
	}

	if(ret < 0){
		int32_t err = SSL_get_error((SSL*)ssl, ret);
		if(err == SSL_ERROR_WANT_READ){
			//write operation can also cause read operation when the peer requests a re-negotiation
			 return ssl_asyncOperation(fd, SELECT_READ, retry);
		}
		else if(err == SSL_ERROR_WANT_WRITE){
			 return ssl_asyncOperation(fd, SELECT_WRITE, retry);
		}
		//check if connection reset
		//treat epipe as reset
		if(errno == ECONNRESET || errno == EPIPE){
			return J_CONNECTION_RESET;
		}
		return LLNET_SSL_TranslateReturnCode((SSL*)ssl, ret);
	}

	if(ret == 0){
		return J_CONNECTION_RESET;
	}

	return ret;
}

int32_t LLNET_SSL_SOCKET_IMPL_available(int32_t ssl, uint8_t retry){
	int ret;
	LLNET_SSL_DEBUG_TRACE("%s(ssl=%d)\n", __func__, ssl);

	if((ret = SSL_pending((SSL*)ssl)) < 0) {
		return J_UNKNOWN_ERROR;
	}
	return ret;
}

#ifdef __cplusplus
	}
#endif
