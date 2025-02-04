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

#include <sni.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <LLSEC_KEY_FACTORY_impl.h>

#include "LLSEC_configuration.h"
#include "LLSEC_openssl.h"

#define MICROEJ_LLSECU_KEY_FACTORY_SUCCESS 1
#define MICROEJ_LLSECU_KEY_FACTORY_ERROR   0

// #define LLSEC_KEY_FACTORY_DEBUG_TRACE

#ifdef LLSEC_KEY_FACTORY_DEBUG_TRACE
#define LLSEC_KEY_FACTORY_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLSEC_KEY_FACTORY_PRINTF(...) ((void)0)
#endif

static const char* pkcs8_format = "PKCS#8";
static const char* x509_format = "X.509";

typedef int32_t(*LLSEC_KEY_FACTORY_get_private_key_data)(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length);
typedef int32_t(*LLSEC_KEY_FACTORY_get_public_key_data)(LLSEC_pub_key* pub_key, uint8_t* encoded_key, int32_t encoded_key_length);
typedef void(*LLSEC_KEY_FACTORY_key_close)(void* native_id);

typedef struct {
	char* name;
	LLSEC_KEY_FACTORY_get_private_key_data get_private_key_data;
	LLSEC_KEY_FACTORY_get_public_key_data  get_public_key_data;
	LLSEC_KEY_FACTORY_key_close            private_key_close;
	LLSEC_KEY_FACTORY_key_close            public_key_close;
} LLSEC_KEY_FACTORY_algorithm;

static int32_t LLSEC_KEY_FACTORY_RSA_openssl_get_private_key_data(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length);
static int32_t LLSEC_KEY_FACTORY_RSA_openssl_get_public_key_data(LLSEC_pub_key* pub_key, uint8_t* encoded_key, int32_t encoded_key_length);
static int32_t LLSEC_KEY_FACTORY_EC_openssl_get_private_key_data(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length);
static int32_t LLSEC_KEY_FACTORY_EC_openssl_get_public_key_data(LLSEC_pub_key* pub_key, uint8_t* encoded_key, int32_t encoded_key_length);
static void LLSEC_KEY_FACTORY_openssl_private_key_close(void* native_id);
static void LLSEC_KEY_FACTORY_openssl_public_key_close(void* native_id);

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file
static LLSEC_KEY_FACTORY_algorithm available_algorithms[2] =
{
	{
		.name = "RSA",
		.get_private_key_data = LLSEC_KEY_FACTORY_RSA_openssl_get_private_key_data,
		.get_public_key_data  = LLSEC_KEY_FACTORY_RSA_openssl_get_public_key_data,
		.private_key_close    = LLSEC_KEY_FACTORY_openssl_private_key_close,
		.public_key_close     = LLSEC_KEY_FACTORY_openssl_public_key_close
	},
	{
		.name = "EC",
		.get_private_key_data = LLSEC_KEY_FACTORY_EC_openssl_get_private_key_data,
		.get_public_key_data = LLSEC_KEY_FACTORY_EC_openssl_get_public_key_data,
		.private_key_close    = LLSEC_KEY_FACTORY_openssl_private_key_close,
		.public_key_close     = LLSEC_KEY_FACTORY_openssl_public_key_close
	}
};

static int32_t LLSEC_KEY_FACTORY_RSA_openssl_get_private_key_data(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length)
{
	LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);
	int32_t return_code = MICROEJ_LLSECU_KEY_FACTORY_SUCCESS;

	priv_key->type = TYPE_RSA;
	priv_key->key = d2i_PrivateKey(EVP_PKEY_RSA, (NULL) , (const unsigned char **)&encoded_key, encoded_key_length);
	if (NULL == priv_key->key) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		LLSEC_free(priv_key);
		return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		int32_t native_id = (int32_t) priv_key;
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		if (SNI_registerResource((void*)native_id, (SNI_closeFunction)LLSEC_KEY_FACTORY_openssl_private_key_close, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			EVP_PKEY_free(priv_key->key);
			LLSEC_free(priv_key);
			return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
		}
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t) priv_key;
	}
	return return_code;
}

static int32_t LLSEC_KEY_FACTORY_RSA_openssl_get_public_key_data(LLSEC_pub_key* pub_key, uint8_t* encoded_key, int32_t encoded_key_length){

	LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);
	int32_t return_code = MICROEJ_LLSECU_KEY_FACTORY_SUCCESS;

	pub_key->type = TYPE_RSA;
	pub_key->key = d2i_PUBKEY((EVP_PKEY**) (NULL) , (const unsigned char **)&encoded_key, encoded_key_length);
	if (NULL == pub_key->key) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		LLSEC_free(pub_key);
		return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		int32_t native_id = (int32_t) pub_key;
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		if (SNI_registerResource((void*)native_id, (SNI_closeFunction)LLSEC_KEY_FACTORY_openssl_public_key_close, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			EVP_PKEY_free(pub_key->key);
			LLSEC_free(pub_key);
			return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
		}
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t) pub_key;
	}
	return return_code;
}

static int LLSEC_KEY_FACTORY_EC_openssl_get_private_key_data(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length)
{
	LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);
	int32_t return_code = MICROEJ_LLSECU_KEY_FACTORY_SUCCESS;

	priv_key->type = TYPE_ECDSA;
	priv_key->key  = d2i_PrivateKey(EVP_PKEY_EC, (NULL) , (const unsigned char **)&encoded_key, encoded_key_length);
	if (NULL == priv_key->key) {
		// Error
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		LLSEC_free(priv_key);
		return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		int32_t native_id = (int32_t) priv_key;
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		if (SNI_registerResource((void*)native_id, (SNI_closeFunction)LLSEC_KEY_FACTORY_openssl_private_key_close, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			EVP_PKEY_free(priv_key->key);
			LLSEC_free(priv_key);
			return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
		}
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t) priv_key;
	}
	return return_code;
}

static int32_t LLSEC_KEY_FACTORY_EC_openssl_get_public_key_data(LLSEC_pub_key* pub_key, uint8_t* encoded_key, int32_t encoded_key_length){

	LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);
	int32_t return_code = MICROEJ_LLSECU_KEY_FACTORY_SUCCESS;

	pub_key->type = TYPE_ECDSA;
	// with no call to EVP_PKEY_free this will leak memory
	// A mean to free native memory upon gargbage collection of the associated Java object is required
	pub_key->key = d2i_PUBKEY((EVP_PKEY**) (NULL) , (const unsigned char **)&encoded_key, encoded_key_length);
	if (NULL == pub_key->key) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		LLSEC_free(pub_key);
		return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		int32_t native_id = (int32_t) pub_key;
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		if (SNI_registerResource((void*)native_id, (SNI_closeFunction)LLSEC_KEY_FACTORY_openssl_public_key_close, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			EVP_PKEY_free(pub_key->key);
			LLSEC_free(pub_key);
			return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
		}
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t) pub_key;
	}
	return return_code;
}

static void LLSEC_KEY_FACTORY_openssl_private_key_close(void* native_id) {
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	LLSEC_priv_key* key = (LLSEC_priv_key*) native_id;
	EVP_PKEY_free(key->key);
	LLSEC_free(key);
}

static void LLSEC_KEY_FACTORY_openssl_public_key_close(void* native_id) {
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	LLSEC_pub_key* key = (LLSEC_pub_key*) native_id;
	EVP_PKEY_free(key->key);
	LLSEC_free(key);
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLSEC_KEY_FACTORY_IMPL_get_private_key_data(int32_t algorithm_id, uint8_t* format_name, uint8_t* encoded_key, int32_t encoded_key_length) {
	LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);
	int32_t return_code = MICROEJ_LLSECU_KEY_FACTORY_SUCCESS;
	LLSEC_priv_key* private_key = NULL;

	if (0 != strcmp(format_name, pkcs8_format)) {
		(void)SNI_throwNativeException(SNI_ERROR, NULL);
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		private_key = (LLSEC_priv_key*) LLSEC_calloc(1, sizeof(LLSEC_priv_key));
		if (NULL == private_key) {
			(void)SNI_throwNativeException(SNI_ERROR, "Can't allocate LLSEC_priv_key structure");
			return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
		}
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		LLSEC_KEY_FACTORY_algorithm* algorithm = (LLSEC_KEY_FACTORY_algorithm*)algorithm_id;
		return_code = algorithm->get_private_key_data(private_key, encoded_key, encoded_key_length);
	}
	return return_code;
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLSEC_KEY_FACTORY_IMPL_get_public_key_data(int32_t algorithm_id, uint8_t* format_name, uint8_t* encoded_key, int32_t encoded_key_length) {
	LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);
	int32_t return_code = MICROEJ_LLSECU_KEY_FACTORY_SUCCESS;
	LLSEC_pub_key* public_key = NULL;

	if (strcmp(format_name, x509_format) != 0) {
		(void)SNI_throwNativeException(SNI_ERROR, NULL);
		return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		public_key = (LLSEC_pub_key*) LLSEC_calloc(1, sizeof(LLSEC_pub_key));
		if (NULL == public_key) {
			(void)SNI_throwNativeException(SNI_ERROR, "Can't allocate LLSEC_pub_key structure");
			return_code = MICROEJ_LLSECU_KEY_FACTORY_ERROR;
		}
	}

	if (MICROEJ_LLSECU_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		LLSEC_KEY_FACTORY_algorithm* algorithm = (LLSEC_KEY_FACTORY_algorithm*)algorithm_id;
		return_code = algorithm->get_public_key_data(public_key, encoded_key, encoded_key_length);
	}
	return return_code;
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLSEC_KEY_FACTORY_IMPL_get_algorithm_description(uint8_t* algorithm_name) {
	LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLSEC_KEY_FACTORY_algorithm);
	LLSEC_KEY_FACTORY_algorithm* algorithm = &available_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp(algorithm_name, algorithm->name)) {
			break;
		}
		algorithm++;
	}

	if (nb_algorithms >= 0) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t)algorithm;
	}
	return return_code;
}

int32_t LLSEC_KEY_FACTORY_IMPL_get_private_key_close_id(int32_t algorithm_id) {
	LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_KEY_FACTORY_algorithm* algorithm = (LLSEC_KEY_FACTORY_algorithm*)algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t) algorithm->private_key_close;
}

int32_t LLSEC_KEY_FACTORY_IMPL_get_public_key_close_id(int32_t algorithm_id) {
	LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_KEY_FACTORY_algorithm* algorithm = (LLSEC_KEY_FACTORY_algorithm*)algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t) algorithm->public_key_close;
}
