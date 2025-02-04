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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include "LLSEC_MAC_impl.h"

#define MICROEJ_LLSECU_MAC_SUCCESS 1
#define MICROEJ_LLSECU_MAC_ERROR   0

// #define LLSECU_MAC_DEBUG_TRACE

#ifdef LLSECU_MAC_DEBUG_TRACE
#define LLSECU_MAC_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLSECU_MAC_DEBUG_PRINTF(...) ((void)0)
#endif

typedef int (*LLSEC_MAC_init)(void** native_id, const uint8_t* key, int32_t key_length);
typedef int (*LLSEC_MAC_update)(void* native_id, const uint8_t* buffer, int32_t buffer_length);
typedef int (*LLSEC_MAC_do_final)(void* native_id, uint8_t* out, int32_t out_length);
typedef int (*LLSEC_MAC_reset)(void* native_id);
typedef void (*LLSEC_MAC_close)(void* native_id);

typedef struct {
	char* name;
	LLSEC_MAC_init init;
	LLSEC_MAC_update update;
	LLSEC_MAC_do_final do_final;
	LLSEC_MAC_reset reset;
	LLSEC_MAC_close close;
	LLSEC_MAC_algorithm_desc description;
} LLSEC_MAC_algorithm;

static int LLSEC_MAC_openssl_HmacSha256_init(void** native_id, const uint8_t* key, int32_t key_length);
static int LLSEC_MAC_openssl_update(void* native_id, const uint8_t* buffer, int32_t buffer_length);
static int LLSEC_MAC_openssl_do_final(void* native_id, uint8_t* out, int32_t out_length);
static int LLSEC_MAC_openssl_reset(void* native_id);
static void LLSEC_MAC_openssl_close(void* native_id);

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file
static LLSEC_MAC_algorithm available_algorithms[1] = {
	{
		.name = "HmacSHA256",
		.init = LLSEC_MAC_openssl_HmacSha256_init,
		.update = LLSEC_MAC_openssl_update,
		.do_final = LLSEC_MAC_openssl_do_final,
		.reset = LLSEC_MAC_openssl_reset,
		.close = LLSEC_MAC_openssl_close,
		{
			.mac_length = 32
		}
	}
};

static int LLSEC_MAC_openssl_HmacSha256_init(void** native_id, const uint8_t* key, int32_t key_length) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	HMAC_CTX* ctx = NULL;
#else
	EVP_MAC_CTX* ctx = NULL;
#endif
	int return_code = MICROEJ_LLSECU_MAC_SUCCESS;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	ctx = (HMAC_CTX*)OPENSSL_malloc(sizeof(HMAC_CTX));
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
	ctx = HMAC_CTX_new();
#else
	EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (NULL != mac) {
		ctx = EVP_MAC_CTX_new(mac);
		EVP_MAC_free(mac);
	}
#endif

	if (NULL == ctx) {
		return_code = MICROEJ_LLSECU_MAC_ERROR;
	}

	if (MICROEJ_LLSECU_MAC_SUCCESS == return_code) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		HMAC_CTX_init(ctx);
#endif

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
		return_code = HMAC_Init_ex(ctx, key, key_length, EVP_sha256(), NULL);
#else
		OSSL_PARAM params[2];
		// https://github.com/openssl/openssl/issues/20956
		// cppcheck-suppress misra-c2012-7.4
		// cppcheck-suppress misra-c2012-11.8
		params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
		params[1] = OSSL_PARAM_construct_end();
		return_code = EVP_MAC_init(ctx, key, key_length, params);
#endif
	}

	if (MICROEJ_LLSECU_MAC_SUCCESS != return_code) {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
		HMAC_CTX_cleanup(ctx);
		OPENSSL_free((void*)ctx);
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
		HMAC_CTX_free(ctx);
#else
		EVP_MAC_CTX_free(ctx);
#endif
	} else {
		//set the context as native id
		(*native_id) = (void*)ctx;
	}

	return return_code;
}

static int LLSEC_MAC_openssl_update(void* native_id, const uint8_t* buffer, int32_t buffer_length) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	HMAC_CTX* ctx = (HMAC_CTX*)(native_id);
	int rc = HMAC_Update(ctx, buffer, buffer_length);
#else
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)(native_id);
	int rc = EVP_MAC_update(ctx, buffer, buffer_length);
#endif
	return rc;
}

static int LLSEC_MAC_openssl_do_final(void* native_id, uint8_t* out, int32_t out_length) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

	unsigned int len;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	HMAC_CTX* ctx = (HMAC_CTX*)(native_id);
	int rc = HMAC_Final(ctx, out, &len);
#else
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)(native_id);
	int rc = EVP_MAC_final(ctx, out, &len, out_length);
#endif
	return rc;
}

static int LLSEC_MAC_openssl_reset(void* native_id) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	HMAC_CTX* ctx = (HMAC_CTX*)(native_id);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	HMAC_CTX_cleanup(ctx); //HMAC_CTX_cleanup() cleans the ctx and set its memory to 0
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
	HMAC_CTX_reset(ctx);
#else
	// not implemented
#endif
	return MICROEJ_LLSECU_MAC_SUCCESS;
}

static void LLSEC_MAC_openssl_close(void* native_id) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	HMAC_CTX* ctx = (HMAC_CTX*)(native_id);
#else
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)(native_id);
#endif
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	HMAC_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
	HMAC_CTX_free(ctx);
#else
	EVP_MAC_CTX_free(ctx);
#endif
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLSEC_MAC_IMPL_get_algorithm_description(uint8_t* algorithm_name, LLSEC_MAC_algorithm_desc* algorithm_desc) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLSEC_MAC_algorithm);
	const LLSEC_MAC_algorithm* algorithm = &available_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (strcmp(algorithm_name, algorithm->name) == 0)
		{
			(void)memcpy(algorithm_desc, &(algorithm->description), sizeof(LLSEC_MAC_algorithm_desc));
			// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
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

int32_t LLSEC_MAC_IMPL_init(int32_t algorithm_id, uint8_t* key, int32_t key_length) {

	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

	void* native_id = NULL;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

	int return_code = algorithm->init(&native_id, key, key_length);

	if (MICROEJ_LLSECU_MAC_SUCCESS != return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return_code = MICROEJ_LLSECU_MAC_ERROR;
	}

	if (MICROEJ_LLSECU_MAC_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_registerResource(native_id, algorithm->close, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			algorithm->close((void*)native_id);
			return_code = MICROEJ_LLSECU_MAC_ERROR;
		}
	}

	if (MICROEJ_LLSECU_MAC_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		return_code = (int32_t)native_id;
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

void LLSEC_MAC_IMPL_update(int32_t algorithm_id, int32_t native_id, uint8_t* buffer, int32_t buffer_offset, int32_t buffer_length) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int return_code = algorithm->update((void*)native_id, &buffer[buffer_offset], buffer_length);

	if (return_code != MICROEJ_LLSECU_MAC_SUCCESS) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
}

void LLSEC_MAC_IMPL_do_final(int32_t algorithm_id, int32_t native_id, uint8_t* out, int32_t out_offset, int32_t out_length) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int return_code = algorithm->do_final((void*)native_id, &out[out_offset], out_length);

	if (return_code != MICROEJ_LLSECU_MAC_SUCCESS) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
}

void LLSEC_MAC_IMPL_reset(int32_t algorithm_id, int32_t native_id) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int return_code = algorithm->reset((void*)native_id);

	if (return_code != MICROEJ_LLSECU_MAC_SUCCESS) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
}

void LLSEC_MAC_IMPL_close(int32_t algorithm_id, int32_t native_id) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	algorithm->close((void*)native_id);
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	if(SNI_unregisterResource((void*)native_id, (SNI_closeFunction) algorithm->close) != SNI_OK) {
			 (void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource\n");
	}
}

int32_t LLSEC_MAC_IMPL_get_close_id(int32_t algorithm_id) {
	LLSECU_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t) algorithm->close;
}
