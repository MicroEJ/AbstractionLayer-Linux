/*
 * C
 *
 * Copyright 2015-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#include <LLNET_SSL_ERRORS.h>
#include "LLNET_SSL_util.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <err.h>
#include <sni.h>

/**
 * @file
 * @brief LLNET_SSL error management for OpenSSL.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 25 July 2024
 */

#ifdef __cplusplus
	extern "C" {
#endif

static int32_t	LLNET_SSL_LIB_Error(void);
static int32_t LLNET_SSL_Error(int32_t reason);
static int32_t LLNET_SSL_RSA_Error(int32_t reason);
static int32_t LLNET_SSL_PEM_Error(int32_t reason);
static int32_t LLNET_SSL_ASN_Error(int32_t reason);

int32_t LLNET_SSL_TranslateReturnCode(const SSL* ssl, int32_t error) {
	int32_t ret = 0;
	int32_t err = SSL_get_error(ssl, error);

	switch (err) {
		case SSL_ERROR_NONE:
			ret = J_SSL_NO_ERROR;
			break;
		case SSL_ERROR_SSL:
			ret = LLNET_SSL_LIB_Error();
			break;
		case SSL_ERROR_SYSCALL:
			ret = J_SOCKET_ERROR;
			break;
		case SSL_ERROR_WANT_READ:
			ret = J_WANT_READ;
			break;
		case SSL_ERROR_WANT_WRITE:
			ret = J_WANT_WRITE;
			break;
		case SSL_ERROR_ZERO_RETURN:
			ret = J_ZERO_RETURN;
			break;
		default:
			ret = J_UNKNOWN_ERROR;
			break;
	}

	return ret;
}

static int32_t LLNET_SSL_LIB_Error(void) {
	int32_t ret = J_UNKNOWN_ERROR;
	int64_t error = ERR_peek_error();
	int32_t reason = ERR_GET_REASON(error);

	//check general error
	switch (reason) {
		case ERR_R_FATAL:
			ret = J_FATAL_ERROR;
			break;
		case ERR_R_MALLOC_FAILURE:
			ret = J_MEMORY_ERROR;
			break;
		case ERR_R_PASSED_NULL_PARAMETER:
			ret = J_BAD_FUNC_ARG;
			break;
		case ERR_R_NESTED_ASN1_ERROR:
		case ERR_R_MISSING_ASN1_EOS:
			ret = J_CERT_PARSE_ERROR;
			break;
		default:
			//no general error
			break;
	}

	if (ret != J_UNKNOWN_ERROR) {
		//check specific library error
		int error_lib = ERR_GET_LIB(error);

		switch (error_lib) {
			case ERR_LIB_SSL:
				ret = LLNET_SSL_Error(reason);
				break;
			case ERR_LIB_SYS:
				ret = J_SOCKET_ERROR;
				break;
			case ERR_LIB_RSA:
				ret = LLNET_SSL_RSA_Error(reason);
				break;
			case ERR_LIB_DH:
				ret = J_ASN_DH_KEY_ERROR;
				break;
			case ERR_LIB_BUF:
				ret = J_MEMORY_ERROR;
				break;
			case ERR_LIB_PEM:
				ret = LLNET_SSL_PEM_Error(reason);
				break;
			case ERR_LIB_ASN1:
				ret = LLNET_SSL_ASN_Error(reason);
				break;
			default:
				break;
		}
	}

	return ret;
}

static int32_t LLNET_SSL_RSA_Error(int32_t reason){
	int32_t ret = 0;

	switch (reason) {
		case RSA_R_BAD_SIGNATURE:
			ret = J_VERIFY_SIGN_ERROR;
			break;
		case RSA_R_INVALID_HEADER:
			ret = J_HEADER_PARSE_ERROR;
			break;
		case RSA_R_BLOCK_TYPE_IS_NOT_01:
		case RSA_R_BLOCK_TYPE_IS_NOT_02:
			ret = J_RSA_WRONG_TYPE_ERROR;
			break;
		case RSA_R_DATA_GREATER_THAN_MOD_LEN:
		case RSA_R_DATA_TOO_LARGE:
		case RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE:
		case RSA_R_DATA_TOO_LARGE_FOR_MODULUS:
		case RSA_R_DATA_TOO_SMALL:
		case RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE:
		case RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY:
		case RSA_R_KEY_SIZE_TOO_SMALL:
		case RSA_R_MODULUS_TOO_LARGE:
			ret = J_RSA_BUFFER_ERROR;
			break;
		case RSA_R_BAD_PAD_BYTE_COUNT:
		case RSA_R_INVALID_PADDING:
		case RSA_R_PADDING_CHECK_FAILED:
		case RSA_R_UNKNOWN_PADDING_TYPE:
			ret = J_RSA_PAD_ERROR;
			break;
		default:
			ret = J_UNKNOWN_ERROR;
			break;
	}

	return ret;
}

static int32_t LLNET_SSL_PEM_Error(int32_t reason){
	int32_t ret = 0;

	switch (reason) {
		case PEM_R_BAD_DECRYPT:
			ret = J_DECRYPT_ERROR;
			break;
		case PEM_R_UNSUPPORTED_CIPHER:
			ret = J_UNSUPPORTED_SUITE;
			break;
		default:
			ret = J_CERT_PARSE_ERROR;
			break;
	}

	return ret;
}

static int32_t LLNET_SSL_ASN_Error(int32_t reason){
	int32_t ret = 0;

	switch (reason) {
		case ASN1_R_ERROR_GETTING_TIME:
			ret = J_ASN_TIME_ERROR;
			break;
		case ASN1_R_EXPECTING_AN_INTEGER:
			ret = J_ASN_GETINT_ERROR;
			break;
		default:
			ret = J_CERT_PARSE_ERROR;
			break;
	}

	return ret;
}

static int32_t LLNET_SSL_Error(int32_t reason){
	int32_t ret = 0;

	switch (reason) {
		case SSL_R_BAD_HELLO_REQUEST:
			ret = J_BAD_HELLO;
			break;
		case SSL_R_BAD_LENGTH:
		case SSL_R_BAD_PACKET_LENGTH:
		case SSL_R_CERT_LENGTH_MISMATCH	:
		case SSL_R_CIPHER_CODE_WRONG_LENGTH	:
		case SSL_R_DATA_LENGTH_TOO_LONG:
		case SSL_R_ENCRYPTED_LENGTH_TOO_LONG:
		case SSL_R_LENGTH_MISMATCH:
		case SSL_R_LENGTH_TOO_SHORT:
		case SSL_R_PACKET_LENGTH_TOO_LONG:
		case SSL_R_RECORD_LENGTH_MISMATCH:
		case SSL_R_RECORD_TOO_SMALL:
			ret = J_LENGTH_ERROR;
			break;
		case SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE:
		case SSL_R_UNKNOWN_ALERT_TYPE:
			ret = J_FATAL_ERROR;
			break;
		case SSL_R_BAD_PROTOCOL_VERSION_NUMBER:
			ret = J_VERSION_ERROR;
			break;
		case SSL_R_TLSV1_ALERT_DECODE_ERROR:
		case SSL_R_TLSV1_ALERT_DECRYPTION_FAILED:
		case SSL_R_TLSV1_ALERT_DECRYPT_ERROR:
			ret = J_DECRYPT_ERROR;
			break;
		case SSL_R_BAD_RSA_ENCRYPT:
			ret = J_ENCRYPT_ERROR;
			break;
		case SSL_R_BAD_SIGNATURE:
			ret = J_VERIFY_SIGN_ERROR;
			break;
		case SSL_R_BAD_SSL_FILETYPE:
			ret = J_BAD_CERTTYPE;
			break;
		case SSL_R_BLOCK_CIPHER_PAD_IS_WRONG:
			ret = J_BAD_PADDING_ERROR;
			break;
		case SSL_R_CERTIFICATE_VERIFY_FAILED:
		case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
			ret = J_VERIFY_CERT_ERROR;
			break;
		case SSL_R_DATA_BETWEEN_CCS_AND_FINISHED:
			ret = J_NO_CHANGE_CIPHER_ERROR;
			break;
		case SSL_R_DECRYPTION_FAILED:
		case SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC:
			ret = J_DECRYPT_ERROR;
			break;
		case SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST:
		case SSL_R_LIBRARY_HAS_NO_CIPHERS:
		case SSL_R_NO_CIPHERS_AVAILABLE:
		case SSL_R_NO_CIPHERS_SPECIFIED:
		case SSL_R_REQUIRED_CIPHER_MISSING:
		case SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS:
			ret = J_SANITY_CIPHER_ERROR;
			break;
		case SSL_R_MISSING_RSA_CERTIFICATE:
		case SSL_R_MISSING_RSA_ENCRYPTING_CERT:
		case SSL_R_MISSING_RSA_SIGNING_CERT:
		case SSL_R_NO_CERTIFICATES_RETURNED:
		case SSL_R_NO_CERTIFICATE_ASSIGNED:
		case SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE:
			ret = J_NO_PEER_CERT;
			break;
		case SSL_R_NO_CIPHER_MATCH:
			ret = J_MATCH_SUITE_ERROR;
			break;
		case SSL_R_NO_PRIVATE_KEY_ASSIGNED:
			ret = J_NO_PRIVATE_KEY;
			break;
		case SSL_R_NULL_SSL_CTX	:
		case SSL_R_NULL_SSL_METHOD_PASSED:
			ret = J_BAD_FUNC_ARG;
			break;
		case SSL_R_SSLV3_ALERT_BAD_RECORD_MAC:
			ret = J_VERIFY_MAC_ERROR;
			break;
		case SSL_R_READ_TIMEOUT_EXPIRED:
			ret = J_SOCKET_TIMEOUT;
			break;
		case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:
			ret = J_ASN_AFTER_DATE_ERROR;
			break;
		case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:
			ret = J_CRL_CERT_REVOKED;
			break;
		case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
		case SSL_R_SSLV3_ALERT_NO_CERTIFICATE:
			ret = J_NO_TRUSTED_CERT;
			break;
		case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE:
			ret = J_BAD_ENCODED_CERT_FORMAT;
			break;
		case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
			ret = J_ASN_NO_SIGNER_ERROR;
			break;
		case SSL_R_UNKNOWN_CERTIFICATE_TYPE:
			ret = J_BAD_CERTTYPE;
			break;
		case SSL_R_UNKNOWN_CIPHER_RETURNED:
		case SSL_R_UNKNOWN_CIPHER_TYPE:
		case SSL_R_WRONG_CIPHER_RETURNED:
		case SSL_R_UNKNOWN_SSL_VERSION:
		case SSL_R_UNSUPPORTED_SSL_VERSION:
		case SSL_R_WRONG_SSL_VERSION:
		case SSL_R_WRONG_VERSION_NUMBER:
			ret = J_VERSION_ERROR;
			break;
		default:
			ret = J_UNKNOWN_ERROR;
			break;
	}

	return ret;
}

#ifdef __cplusplus
	}
#endif
