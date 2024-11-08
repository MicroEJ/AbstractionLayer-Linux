/*
 * C
 *
 * Copyright 2015-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#include <LLNET_SSL_CONTEXT_impl.h>
#include <LLNET_SSL_CONSTANTS.h>
#include <LLNET_SSL_ERRORS.h>
#include <LLNET_SSL_cookie.h>
#include <LLNET_SSL_util.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <stdlib.h>
#include <string.h>

/**
 * @file
 * @brief LLNET_SSL_CONTEXT implementation over OpenSSL.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 25 July 2024
 */

#ifdef __cplusplus
	extern "C" {
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
static int32_t LLNET_SSL_CONTEXT_setContextVersion(SSL_CTX* ctx, int32_t protocol){
	int32_t result = 1;
	// Compute the protocol version based on the protocol argument
	int version = 0;
	switch (protocol) {
		case TLSv1_PROTOCOL:
			version = TLS1_VERSION;
			break;
		case TLSv1_1_PROTOCOL:
			version = TLS1_1_VERSION;
			break;
		case TLSv1_2_PROTOCOL:
			version = TLS1_2_VERSION;
			break;
		case DTLSv1_PROTOCOL:
			version = DTLS1_VERSION;
			break;
		case DTLSv1_2_PROTOCOL:
			version = DTLS1_2_VERSION;
			break;
		case SSLv3_PROTOCOL: //no SSLv3 protocol
		default:
			break;
	}

	// Restrict the range of protocols based on the protocol argument
	if(0 == SSL_CTX_set_min_proto_version(ctx, version)) {
		// Could not set minimum protocol, free the context structure.
		LLNET_SSL_DEBUG_TRACE("%s could not set minimum protocol to %d\n", protocol);
		result = 0;
	} else {
		// Restrict the range of protocols based on the protocol argument
		if(0 == SSL_CTX_set_max_proto_version(ctx, version)) {
			// Could not set maximum protocol, free the context structure.
			LLNET_SSL_DEBUG_TRACE("%s could not set maximum protocol to %d\n", protocol);
			result = 0;
		}
	}
	return result;
}

#endif

static int32_t LLNET_SSL_CONTEXT_IMPL_createClientContext(int32_t protocol) {
	LLNET_SSL_DEBUG_TRACE("(method=%d)\n", protocol);
	int32_t ret = 0;
	SSL_CTX* ctx = NULL;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	switch (protocol) {
		case TLSv1_PROTOCOL:
			ctx = SSL_CTX_new(TLSv1_client_method());
			break;
		case TLSv1_1_PROTOCOL:
			ctx = SSL_CTX_new(TLSv1_1_client_method());
			break;
		case TLSv1_2_PROTOCOL:
			ctx = SSL_CTX_new(TLSv1_2_client_method());
			break;
		case DTLSv1_PROTOCOL:
			ctx = SSL_CTX_new(DTLSv1_client_method());
			break;
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
		case DTLSv1_2_PROTOCOL:
			ctx = SSL_CTX_new(DTLSv1_2_client_method());
			break;
#endif
		case SSLv3_PROTOCOL: //no SSLv3 protocol
		default:
			break;
	}
#else
	// Create an SSL context allowing all protocol versions
	switch (protocol) {
		case TLSv1_PROTOCOL:
		case TLSv1_1_PROTOCOL:
		case TLSv1_2_PROTOCOL:
			ctx = SSL_CTX_new(TLS_client_method());
			break;
		case DTLSv1_PROTOCOL:
		case DTLSv1_2_PROTOCOL:
			ctx = SSL_CTX_new(DTLS_client_method());
			break;
		case SSLv3_PROTOCOL: //no SSLv3 protocol
			break;
		default:
			break;
	}

	if(ctx != NULL){
		ret = LLNET_SSL_CONTEXT_setContextVersion(ctx, protocol);
		if (ret == 0) {
			SSL_CTX_free(ctx);
			ctx = NULL;
		}
	}
#endif

	LLNET_SSL_DEBUG_TRACE("(method=%d) return ctx=%p\n", protocol,ctx);
	if(ctx != NULL){
		ret = (int32_t)ctx;
	} else {
		(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "Unknown error");
		ret = SNI_IGNORED_RETURNED_VALUE;
	}

	return ret;
}

static int32_t LLNET_SSL_CONTEXT_IMPL_createServerContext(int32_t protocol) {
	LLNET_SSL_DEBUG_TRACE("(method=%d)\n", protocol);
	int32_t ret = 0;
	SSL_CTX* ctx = NULL;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	switch (protocol) {
		case TLSv1_PROTOCOL:
			ctx = SSL_CTX_new(TLSv1_server_method());
			break;
		case TLSv1_1_PROTOCOL:
			ctx = SSL_CTX_new(TLSv1_1_server_method());
			break;
		case TLSv1_2_PROTOCOL:
			ctx = SSL_CTX_new(TLSv1_2_server_method());
			break;
		case DTLSv1_PROTOCOL:
			ctx = SSL_CTX_new(DTLSv1_server_method());
			break;
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
		case DTLSv1_2_PROTOCOL:
			ctx = SSL_CTX_new(DTLSv1_2_server_method());
			break;
#endif
		case SSLv3_PROTOCOL: //no SSLv3 protocol
		default:
			break;
	}

	if (protocol == DTLSv1_PROTOCOL
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
			|| protocol == DTLSv1_2_PROTOCOL
#endif
	)
	{
		SSL_CTX_set_cookie_generate_cb(ctx, LLNET_SSL_Generate_Cookie);
		SSL_CTX_set_cookie_verify_cb(ctx, LLNET_SSL_Verify_Cookie);
	}
#else
	// Create an SSL context allowing all protocol versions
	switch (protocol) {
		case TLSv1_PROTOCOL:
		case TLSv1_1_PROTOCOL:
		case TLSv1_2_PROTOCOL:
			ctx = SSL_CTX_new(TLS_server_method());
			break;
		case DTLSv1_PROTOCOL:
		case DTLSv1_2_PROTOCOL:
			ctx = SSL_CTX_new(DTLS_server_method());
			SSL_CTX_set_cookie_generate_cb(ctx, LLNET_SSL_Generate_Cookie);
			SSL_CTX_set_cookie_verify_cb(ctx, LLNET_SSL_Verify_Cookie);
			break;
		case SSLv3_PROTOCOL: //no SSLv3 protocol
			break;
		default:
			break;
	}

	if(ctx != NULL){
		ret = LLNET_SSL_CONTEXT_setContextVersion(ctx, protocol);
		if (ret == 0) {
			SSL_CTX_free(ctx);
			ctx = NULL;
		}
	}
#endif

	LLNET_SSL_DEBUG_TRACE("(method=%d) return ctx=%p\n", protocol,ctx);
	if(ctx != NULL){
		ret = (int32_t)ctx;
	} else {
		(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "Unknown error");
		ret = SNI_IGNORED_RETURNED_VALUE;
	}

	return ret;
}

void LLNET_SSL_CONTEXT_IMPL_addTrustedCertificate(int32_t context, uint8_t *cert, int32_t cert_size, int32_t format) {
	LLNET_SSL_DEBUG_TRACE_INFO("context=%d, cert=0x%x, cert_size=%d, format=%d\n", context, cert, cert_size, format);
	int32_t ret = J_SSL_NO_ERROR;
	SSL_CTX* ssl_context = (SSL_CTX*)context;
	X509* x509 = LLNET_SSL_X509_CERT_create(cert, 0, cert_size, &format);

	if(x509 != NULL){
		// The certificate has been created: add it the store of the context (create the store if needed).
		X509_STORE* store = SSL_CTX_get_cert_store(ssl_context);
		if(store == NULL){
			// No store for the context: create it
			store = X509_STORE_new();
			if (store != NULL) {
				SSL_CTX_set_cert_store(ssl_context, store);
			} else {
				X509_free(x509);
				ret = J_CERT_PARSE_ERROR;
			}
		}

		if (store != NULL) {
			// Store has been created or was retrieved
			int e_add_cert = X509_STORE_add_cert(store, x509);
			// Note: I suppose that X509_STORE_add_cert returns 0 on success.
			// This is specified neither in the man page nor in the header file ???
			if (e_add_cert <= 0) {
				ret = J_CERT_PARSE_ERROR;
			}
		}
	} else {
		ret = J_CERT_PARSE_ERROR;
	}

	if (ret != J_SSL_NO_ERROR) {
		(void)SNI_throwNativeIOException(ret, "Error adding trusted certificate");
	}
}

void LLNET_SSL_CONTEXT_IMPL_setCertificate(int32_t contextID, uint8_t* cert, int32_t len, int32_t format) {
	LLNET_SSL_DEBUG_TRACE("%s\n", __func__);
	int32_t retVal = J_SSL_NO_ERROR;
	int sslRetVal;
	//sslErrorCode;	// If there is an error during an OpenSSL call.
	SSL_CTX* ssl_context = (SSL_CTX*)contextID;

	// decode the certificate
	X509 * newCert = LLNET_SSL_X509_CERT_create(cert, 0, len, &format);
	if(NULL == newCert) {
		LLNET_SSL_DEBUG_PRINT_ERR();
		(void)SNI_throwNativeIOException(J_CERT_PARSE_ERROR, "Could not create certificate");
	} else {
		//load the certificate into the context
		sslRetVal = SSL_CTX_use_certificate(ssl_context, newCert);
		if(1 != sslRetVal) {
			LLNET_SSL_DEBUG_PRINT_ERR();
			(void)SNI_throwNativeIOException(J_CERT_PARSE_ERROR, "Could not use certificate");
		}
	}
}

static int pem_passwd_cb(char *buf, int size, int rwflag, void *password) {
	LLNET_SSL_DEBUG_TRACE("%s\n", __func__);
	(void)rwflag;
	(void)strncpy(buf, (char *) (password), size);
	buf[size - 1] = '\0';
	return (strlen(buf));
}

void LLNET_SSL_CONTEXT_IMPL_setPrivateKey(int32_t contextID, uint8_t* private_key, int32_t private_key_len, uint8_t* key_password, int32_t key_password_len) {
	LLNET_SSL_DEBUG_TRACE("%s private_key_len=%d key_password_len=%d\n", private_key_len, key_password_len);
	SSL_CTX* ssl_context = (SSL_CTX*)contextID;
	void* password = NULL;
	EVP_PKEY *key = NULL;
	BIO *bp = NULL;

	//The format of the private key must be a DER (ASN1) encrypted PKCS#8
	if (key_password_len <= 0) {
		//no password to decrypt the key
		(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "No password provided");
	} else {
		password = key_password;
		SSL_CTX_set_default_passwd_cb(ssl_context, pem_passwd_cb);

		bp = BIO_new_mem_buf(private_key, private_key_len);
		(void)d2i_PKCS8PrivateKey_bio(bp, &key, pem_passwd_cb, password);
		if (NULL == key) {
			LLNET_SSL_DEBUG_PRINT_ERR();
			(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "Could not create key");
		} else if ( SSL_CTX_use_PrivateKey(ssl_context, key) <= 0) {
			LLNET_SSL_DEBUG_PRINT_ERR();
			(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "Could not use key");
		} else {
			LLNET_SSL_DEBUG_TRACE("Success\n");
		}
	}
}

int32_t LLNET_SSL_CONTEXT_IMPL_initChainBuffer(int32_t contextID, int32_t nb_chain_certs, int32_t chain_certs_total_size) {
	LLNET_SSL_DEBUG_TRACE("%s\n", __func__);
	(void)nb_chain_certs;
	(void)chain_certs_total_size;
	int retVal;
	int32_t ret = J_SSL_NO_ERROR;

	SSL_CTX* ssl_context = (SSL_CTX*)contextID;
#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
	retVal = SSL_CTX_clear_extra_chain_certs(ssl_context);
#else
	retVal = SSL_CTX_clear_chain_certs(ssl_context);
#endif
	if(1 != retVal) {
		(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "Init chain buffer failed");
		ret = J_UNKNOWN_ERROR;
	}

	return ret;
}

void LLNET_SSL_CONTEXT_IMPL_addChainCertificate(int32_t contextID, uint8_t* cert, int32_t len, int32_t format, int32_t chain_buffer_size) {
	LLNET_SSL_DEBUG_TRACE("%s\n", __func__);
	(void)chain_buffer_size;
	int retVal = 0;

	SSL_CTX* ssl_context = (SSL_CTX*)contextID;
	X509* x509 = LLNET_SSL_X509_CERT_create(cert, 0, len, &format);
	if (x509 == NULL) {
		LLNET_SSL_DEBUG_PRINT_ERR();
		(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "Error creating certificate chain");
	} else {
#if (OPENSSL_VERSION_NUMBER < 0x10002000L)
		retVal = SSL_CTX_add_extra_chain_cert(ssl_context, x509);
#else
		retVal = SSL_CTX_add0_chain_cert(ssl_context, x509);
#endif
		if (1 != retVal) {
			LLNET_SSL_DEBUG_PRINT_ERR();
			(void)SNI_throwNativeIOException(J_UNKNOWN_ERROR, "Error creating certificate chain");
		}
	}
}

void LLNET_SSL_CONTEXT_IMPL_clearKeyStore(int32_t contextID) {
	LLNET_SSL_DEBUG_TRACE("%s\n", __func__);
	(void)contextID;
}

int32_t LLNET_SSL_CONTEXT_IMPL_createContext(int32_t protocol, uint8_t is_client_context) {
	LLNET_SSL_DEBUG_TRACE("(protocol=%d, useClientMode=%d)\n", protocol, is_client_context);
	int32_t ret = 0;
	if (is_client_context == (uint8_t)1) {
		ret = LLNET_SSL_CONTEXT_IMPL_createClientContext(protocol);
	} else {
		ret = LLNET_SSL_CONTEXT_IMPL_createServerContext(protocol);
	}
	return ret;
}

void LLNET_SSL_CONTEXT_IMPL_clearTrustStore(int32_t context){
	LLNET_SSL_DEBUG_TRACE("%s\n", __func__);
	SSL_CTX* ssl_context = (SSL_CTX*)context;
	// Set an empty store to the context.
	// The function SSL_CTX_set_cert_store() frees previously allocated
	// store if any.
	SSL_CTX_set_cert_store(ssl_context, X509_STORE_new());
	return;
}

void LLNET_SSL_CONTEXT_IMPL_freeContext(int32_t context) {
	LLNET_SSL_DEBUG_TRACE("(context=%p)\n", (SSL_CTX*) context);
	(void)SSL_CTX_free((SSL_CTX*) context);
}

#ifdef __cplusplus
	}
#endif
