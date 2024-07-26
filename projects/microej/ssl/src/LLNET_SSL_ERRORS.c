/*
 * C
 *
 * Copyright 2015-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#include <LLNET_SSL_ERRORS.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <err.h>
#include <sni.h>

/**
 * @file
 * @brief LLNET_SSL error management for OpenSSL.
 * @author MicroEJ Developer Team
 * @version 1.0.1
 * @date 27 November 2020
 */

#ifdef __cplusplus
	extern "C" {
#endif

int32_t	LLNET_SSL_LIB_Error();
int32_t LLNET_SSL_Error(int32_t reason);
int32_t LLNET_SSL_RSA_Error(int32_t reason);
int32_t LLNET_SSL_PEM_Error(int32_t reason);
int32_t LLNET_SSL_ASN_Error(int32_t reason);


int32_t LLNET_SSL_TranslateReturnCode(SSL* ssl, int32_t error) {
	int32_t err = SSL_get_error(ssl, error);

	switch (err) {
		case SSL_ERROR_NONE:
			return J_SSL_NO_ERROR;
		case SSL_ERROR_SSL:
			return LLNET_SSL_LIB_Error();
		case SSL_ERROR_SYSCALL:
			return J_SOCKET_ERROR;
		case SSL_ERROR_WANT_READ:
			return J_WANT_READ;
		case SSL_ERROR_WANT_WRITE:
			return J_WANT_WRITE;
		case SSL_ERROR_ZERO_RETURN:
			return J_ZERO_RETURN;
		default:
			return J_UNKNOWN_ERROR;
	}
}

int32_t LLNET_SSL_LIB_Error() {
	int64_t error = ERR_peek_error();
	int32_t reason = ERR_GET_REASON(error);

	//check general error
	switch (reason) {
		case ERR_R_FATAL:
			return J_FATAL_ERROR;
		case ERR_R_MALLOC_FAILURE:
			return J_MEMORY_ERROR;
		case ERR_R_PASSED_NULL_PARAMETER:
			return J_BAD_FUNC_ARG;
		case ERR_R_NESTED_ASN1_ERROR:
		case ERR_R_MISSING_ASN1_EOS:
			return J_CERT_PARSE_ERROR;
		default:
			//no general error
			break;
	}

	//check specific library error
	int error_lib = ERR_GET_LIB(error);

	switch (error_lib) {
		case ERR_LIB_SSL:
			return LLNET_SSL_Error(reason);
		case ERR_LIB_SYS:
			return J_SOCKET_ERROR;
		case ERR_LIB_RSA:
			return LLNET_SSL_RSA_Error(reason);
		case ERR_LIB_DH:
			return J_ASN_DH_KEY_ERROR;
		case ERR_LIB_BUF:
			return J_MEMORY_ERROR;
		case ERR_LIB_PEM:
			return LLNET_SSL_PEM_Error(reason);
		//case ERR_LIB_FIPS:
			//return LLNET_SSL_FIPS_Error(reason);
		case ERR_LIB_ASN1:
			return LLNET_SSL_ASN_Error(reason);
		default:
			return J_UNKNOWN_ERROR;
	}
}

int32_t LLNET_SSL_RSA_Error(int32_t reason){
	switch (reason) {
		case RSA_R_BAD_SIGNATURE:
			return J_VERIFY_SIGN_ERROR;
		case RSA_R_INVALID_HEADER:
			return J_HEADER_PARSE_ERROR;
		case RSA_R_BLOCK_TYPE_IS_NOT_01:
		case RSA_R_BLOCK_TYPE_IS_NOT_02:
			return J_RSA_WRONG_TYPE_ERROR;
		case RSA_R_DATA_GREATER_THAN_MOD_LEN:
		case RSA_R_DATA_TOO_LARGE:
		case RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE:
		case RSA_R_DATA_TOO_LARGE_FOR_MODULUS:
		case RSA_R_DATA_TOO_SMALL:
		case RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE:
		case RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY:
		case RSA_R_KEY_SIZE_TOO_SMALL:
		case RSA_R_MODULUS_TOO_LARGE:
			return J_RSA_BUFFER_ERROR;
		case RSA_R_BAD_PAD_BYTE_COUNT:
		case RSA_R_INVALID_PADDING:
		case RSA_R_PADDING_CHECK_FAILED:
		case RSA_R_UNKNOWN_PADDING_TYPE:
			return J_RSA_PAD_ERROR;
		default:
			return J_UNKNOWN_ERROR;
	}
}

int32_t LLNET_SSL_PEM_Error(int32_t reason){
	switch (reason) {
		case PEM_R_BAD_DECRYPT:
			return J_DECRYPT_ERROR;
		case PEM_R_UNSUPPORTED_CIPHER:
			return J_UNSUPPORTED_SUITE;
		default:
			return J_CERT_PARSE_ERROR;
	}
}

int32_t LLNET_SSL_ASN_Error(int32_t reason){
	switch (reason) {
		case ASN1_R_ERROR_GETTING_TIME:
			return J_ASN_TIME_ERROR;
		case ASN1_R_EXPECTING_AN_INTEGER:
			return J_ASN_GETINT_ERROR;
		default:
			return J_CERT_PARSE_ERROR;
	}
}
int32_t LLNET_SSL_Error(int32_t reason){
	switch (reason) {
		case SSL_R_BAD_HELLO_REQUEST:
			return J_BAD_HELLO;
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
			return J_LENGTH_ERROR;
		case SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE:
		case SSL_R_UNKNOWN_ALERT_TYPE:
			return J_FATAL_ERROR;
		case SSL_R_BAD_PROTOCOL_VERSION_NUMBER:
			return J_VERSION_ERROR;
		case SSL_R_TLSV1_ALERT_DECODE_ERROR:
		case SSL_R_TLSV1_ALERT_DECRYPTION_FAILED:
		case SSL_R_TLSV1_ALERT_DECRYPT_ERROR:
			return J_DECRYPT_ERROR;
		case SSL_R_BAD_RSA_ENCRYPT:
			return J_ENCRYPT_ERROR;
		case SSL_R_BAD_SIGNATURE:
			return J_VERIFY_SIGN_ERROR;
		case SSL_R_BAD_SSL_FILETYPE:
			return J_BAD_CERTTYPE;
		case SSL_R_BLOCK_CIPHER_PAD_IS_WRONG:
			return J_BAD_PADDING_ERROR;
		case SSL_R_CERTIFICATE_VERIFY_FAILED:
		case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
			return J_VERIFY_CERT_ERROR;
		case SSL_R_DATA_BETWEEN_CCS_AND_FINISHED:
			return J_NO_CHANGE_CIPHER_ERROR;
		case SSL_R_DECRYPTION_FAILED:
		case SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC:
			return J_DECRYPT_ERROR;
		case SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST:
		case SSL_R_LIBRARY_HAS_NO_CIPHERS:
		case SSL_R_NO_CIPHERS_AVAILABLE:
		case SSL_R_NO_CIPHERS_SPECIFIED:
		case SSL_R_REQUIRED_CIPHER_MISSING:
		case SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS:
			return J_SANITY_CIPHER_ERROR;
		case SSL_R_MISSING_RSA_CERTIFICATE:
		case SSL_R_MISSING_RSA_ENCRYPTING_CERT:
		case SSL_R_MISSING_RSA_SIGNING_CERT:
		case SSL_R_NO_CERTIFICATES_RETURNED:
		case SSL_R_NO_CERTIFICATE_ASSIGNED:
		case SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE:
			return J_NO_PEER_CERT;
		case SSL_R_NO_CIPHER_MATCH:
			return J_MATCH_SUITE_ERROR;
		case SSL_R_NO_PRIVATE_KEY_ASSIGNED:
			return J_NO_PRIVATE_KEY;
		case SSL_R_NULL_SSL_CTX	:
		case SSL_R_NULL_SSL_METHOD_PASSED:
			return J_BAD_FUNC_ARG;
		case SSL_R_SSLV3_ALERT_BAD_RECORD_MAC:
			return J_VERIFY_MAC_ERROR;
		case SSL_R_READ_TIMEOUT_EXPIRED:
			return J_SOCKET_TIMEOUT;
		case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:
			return J_ASN_AFTER_DATE_ERROR;
		case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:
			return J_CRL_CERT_REVOKED;
		case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
		case SSL_R_SSLV3_ALERT_NO_CERTIFICATE:
			return J_NO_TRUSTED_CERT;
		case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE:
			return J_BAD_ENCODED_CERT_FORMAT;
		case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
			return J_ASN_NO_SIGNER_ERROR;
		case SSL_R_UNKNOWN_CERTIFICATE_TYPE:
			return J_BAD_CERTTYPE;
		case SSL_R_UNKNOWN_CIPHER_RETURNED:
		case SSL_R_UNKNOWN_CIPHER_TYPE:
		case SSL_R_WRONG_CIPHER_RETURNED:
		case SSL_R_UNKNOWN_SSL_VERSION:
		case SSL_R_UNSUPPORTED_SSL_VERSION:
		case SSL_R_WRONG_SSL_VERSION:
		case SSL_R_WRONG_VERSION_NUMBER:
			return J_VERSION_ERROR;
		default:
			return J_UNKNOWN_ERROR;
	}
}

#ifdef __cplusplus
	}
#endif
