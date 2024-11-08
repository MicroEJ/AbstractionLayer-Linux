/*
* C
*
* Copyright 2019-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

/**
 * @file
 * @brief MicroEJ Security low level API implementation for OpenSSL Library
 * @author MicroEJ Developer Team
 * @version 3.0.0
 * @date 20 August 2024
 */

#include "LLSEC_configuration.h"
#include "LLSEC_openssl.h"
#include "LLSEC_X509_CERT_impl.h"
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <stdint.h>
#include <string.h>
#include <openssl/pem.h>

#define MICROEJ_LLSECU_X509_SUCCESS 1
#define MICROEJ_LLSECU_X509_ERROR   0

#define MICROEJ_LLSECU_X509_DER_FORMAT      (int)(1)
#define MICROEJ_LLSECU_X509_PEM_FORMAT      (int)(0)
#define MICROEJ_LLSECU_X509_UNKNOWN_FORMAT  (int)(-1)

// #define LLSEC_X509_DEBUG_TRACE

#ifdef LLSEC_X509_DEBUG_TRACE
#define LLSEC_X509_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLSEC_X509_DEBUG_PRINTF(...) ((void)0)
#endif

static X509* get_x509_certificate(int8_t* cert_data, int32_t len, int* cert_format);
static int32_t LLSEC_X509_CERT_openssl_close_key(int32_t native_id);

static X509* get_x509_certificate(int8_t* cert_data, int32_t len, int* cert_format)
{
	LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
	X509 *x509;
	x509 = d2i_X509(NULL, (const unsigned char**)&cert_data, len);
	if (NULL != x509) {
		if (NULL != cert_format) {
			*cert_format = MICROEJ_LLSECU_X509_DER_FORMAT;
		}
	} else {
		BIO *bp = BIO_new_mem_buf(cert_data, len);
		// Can we generate a x509 certificate with pem parsing
		x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);
		if (NULL != cert_format) {
			if(x509 != NULL) {
				*cert_format = MICROEJ_LLSECU_X509_PEM_FORMAT;
			} else 	{
				*cert_format = MICROEJ_LLSECU_X509_UNKNOWN_FORMAT;
			}
		}
		// x509 is NULL if PEM_read_bio failed
		BIO_free_all(bp);

	}
	// Will return a NULL pointer if failed
	// Return a valid certificate on success
	return x509;
}

static int32_t LLSEC_X509_CERT_openssl_close_key(int32_t native_id) {

	LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_pub_key* pub_key = (LLSEC_pub_key*) native_id;
	EVP_PKEY_free(pub_key->key);
	free(pub_key);
	return 1;
}

int32_t LLSEC_X509_CERT_IMPL_parse(int8_t* cert, int32_t off, int32_t len) {
	LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
	int cert_format = MICROEJ_LLSECU_X509_UNKNOWN_FORMAT;
	X509* x509 = get_x509_certificate(&cert[off], len, &cert_format);
	if(x509 != NULL)
	{
		X509_free(x509);
	}
	return cert_format;
}

int32_t LLSEC_X509_CERT_IMPL_get_key(int8_t* cert_data, int32_t cert_data_length) {
	LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
	X509 *x509 = NULL;
	int return_code = MICROEJ_LLSECU_X509_SUCCESS;
	LLSEC_pub_key* pub_key = (LLSEC_pub_key*) LLSEC_calloc(1, sizeof(LLSEC_pub_key));


	if (NULL == pub_key) {
		 (void)SNI_throwNativeException(SNI_ERROR, "Can't allocate LLSEC_pub_key structure");
		 return_code = MICROEJ_LLSECU_X509_ERROR;
	}

	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
		x509 = get_x509_certificate(cert_data, cert_data_length, NULL);
		if (NULL == x509) {
			(void)SNI_throwNativeException(SNI_ERROR, "Bad x509 certificate");
			return_code = MICROEJ_LLSECU_X509_ERROR;
		}
	}

	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
		// Careful about memory leak here
		pub_key->key = X509_get_pubkey(x509);
		if (NULL == pub_key->key) {
			(void)SNI_throwNativeException(SNI_ERROR, "Invalid public key from x509 certificate");
			return_code = MICROEJ_LLSECU_X509_ERROR;
		}
		X509_free(x509);
	}

	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		int32_t native_id = (int32_t) pub_key;
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		if (SNI_registerResource((void*)native_id, (SNI_closeFunction)LLSEC_X509_CERT_openssl_close_key, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			return_code = MICROEJ_LLSECU_X509_ERROR;
		}
	}

	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
		return_code = (int32_t) pub_key;
	} else {
		EVP_PKEY_free(pub_key->key);
		free(pub_key);
	}
	// cppcheck-suppress memleak // pub_key is freed by LLSEC_X509_CERT_openssl_close_key
	return return_code;
}

int32_t LLSEC_X509_CERT_IMPL_verify(int8_t* cert_data, int32_t cert_data_length, int32_t native_id)
{
	LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_pub_key* pub_key = (LLSEC_pub_key*)native_id;
	int return_code = MICROEJ_LLSECU_X509_SUCCESS;

	X509 *x509 = get_x509_certificate(cert_data, cert_data_length, NULL);
	if (NULL == x509) {
		(void)SNI_throwNativeException(SNI_ERROR, "Bad x509 certificate");
		return_code = MICROEJ_LLSECU_X509_ERROR;
	}

	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
		int rc = X509_verify(x509, pub_key->key);
		if (rc != MICROEJ_LLSECU_X509_SUCCESS) {
			// Error
			X509_free(x509);
			LLSEC_X509_DEBUG_PRINTF("LLSEC_X509 > verify error");
			(void)SNI_throwNativeException(SNI_ERROR, "Error x509 verify failed");
			return_code = MICROEJ_LLSECU_X509_ERROR;
		}
	}

	X509_free(x509);
	return return_code;
}

int32_t LLSEC_X509_CERT_IMPL_get_x500_principal_data(int8_t* cert_data, int32_t cert_data_length, uint8_t* principal_data, int32_t principal_data_length, uint8_t get_issuer) {
	LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
	const X509_NAME * name = NULL;
	char * data = NULL;
	size_t length = 0;
	int return_code = MICROEJ_LLSECU_X509_SUCCESS;

	const X509 *x509 = get_x509_certificate(cert_data, cert_data_length, NULL);
	if (NULL == x509) {
		(void)SNI_throwNativeException(SNI_ERROR, "Bad x509 certificate");
		return_code = MICROEJ_LLSECU_X509_ERROR;
	}
	
	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
		if ((uint8_t)1 == get_issuer) {
			name = X509_get_issuer_name(x509);
		} else {
			name = X509_get_subject_name(x509);
		}
	}

	if(NULL == name) {
		(void)SNI_throwNativeException(SNI_ERROR, "Null name.");
		return_code = MICROEJ_LLSECU_X509_ERROR;
	}


	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#ifndef OPENSSL_NO_BUFFER
		data = (char*)name->bytes->data;
		length = name->bytes->length;
#else
		data = name->bytes;
		length = strlen(data);
#endif //OPENSSL_NO_BUFFER
#else
		if(X509_NAME_get0_der((X509_NAME*)name, (const unsigned char**)&data, &length) != 1) {
			(void)SNI_throwNativeException(SNI_ERROR, "Null or bad encoding name.");
			return_code = MICROEJ_LLSECU_X509_ERROR;
		}
#endif //OPENSSL_VERSION_NUMBER < 0x10100000L
	}

	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
		if (length > (size_t)principal_data_length){
			(void)SNI_throwNativeException(SNI_ERROR, "The principal data buffer is too small");
			return_code = MICROEJ_LLSECU_X509_ERROR;
		}
	}

	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
		(void)memcpy(principal_data, data, length);
		return_code = length;
	}
	return return_code;
}

int32_t LLSEC_X509_CERT_IMPL_get_close_key() {

	LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
	return (int32_t) LLSEC_X509_CERT_openssl_close_key;
}

int32_t LLSEC_X509_CERT_IMPL_check_validity(int8_t* cert_data, int32_t cert_data_length) {
	LLSEC_X509_DEBUG_PRINTF("%s \n", __func__);
	int return_code = MICROEJ_LLSECU_X509_SUCCESS;

	int cert_format = MICROEJ_LLSECU_X509_UNKNOWN_FORMAT;
	X509 *x509 = get_x509_certificate(cert_data, cert_data_length, &cert_format);
	if(NULL == x509) {
		(void)SNI_throwNativeException(SNI_ERROR, "Bad x509 certificate");
		return_code = MICROEJ_LLSECU_X509_ERROR;
	}

	if (MICROEJ_LLSECU_X509_SUCCESS == return_code) {
		const ASN1_TIME *notBefore = X509_get_notBefore(x509);
		const ASN1_TIME *notAfter = X509_get_notAfter(x509);

		if (X509_cmp_current_time(notBefore) > 0) {
			LLSEC_X509_DEBUG_PRINTF("%s: certificate not yet valid\n", __func__);
			return_code = J_X509_CERT_NOT_YET_VALID_ERROR;
		} else if (X509_cmp_current_time(notAfter) < 0) {
			LLSEC_X509_DEBUG_PRINTF("%s: certificate expired\n", __func__);
			return_code = J_X509_CERT_EXPIRED_ERROR;
		} else {
			return_code = J_SEC_NO_ERROR;
		}
	}

	if (NULL != x509) {
		X509_free(x509);
	}

	return return_code;
}
