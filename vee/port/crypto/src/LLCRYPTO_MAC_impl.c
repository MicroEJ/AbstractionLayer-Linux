/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

#include "LLCRYPTO_configuration.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include "LLCRYPTO_MAC_impl.h"
#include <LLCRYPTO_CONSTANTS.h>

#define MICROEJ_LLCRYPTO_MAC_SUCCESS 1
#define MICROEJ_LLCRYPTO_MAC_ERROR   0

// #define LLCRYPTO_MAC_DEBUG_TRACE

#ifdef LLCRYPTO_MAC_DEBUG_TRACE
#define LLCRYPTO_MAC_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_MAC_DEBUG_PRINTF(...) ((void)0)
#endif

typedef int (*LLCRYPTO_MAC_init)(void **native_id, const uint8_t *key, int32_t key_length);
typedef int (*LLCRYPTO_MAC_update)(void *native_id, const uint8_t *buffer, int32_t buffer_length);
typedef int (*LLCRYPTO_MAC_do_final)(void *native_id, uint8_t *out, int32_t out_length);
typedef int (*LLCRYPTO_MAC_reset)(void *native_id);
typedef void (*LLCRYPTO_MAC_close)(void *native_id);

typedef struct {
	char *name;
	LLCRYPTO_MAC_init init;
	LLCRYPTO_MAC_update update;
	LLCRYPTO_MAC_do_final do_final;
	LLCRYPTO_MAC_reset reset;
	LLCRYPTO_MAC_close close;
	LLCRYPTO_MAC_algorithm_desc description;
} LLCRYPTO_MAC_algorithm;

static int LLCRYPTO_MAC_openssl_hmac_init(void **native_id, const uint8_t *key, int32_t key_length, const char *md);
static int LLCRYPTO_MAC_openssl_hmacSha256_init(void **native_id, const uint8_t *key, int32_t key_length);
static int LLCRYPTO_MAC_openssl_hmacSha1_init(void **native_id, const uint8_t *key, int32_t key_length);
static int LLCRYPTO_MAC_openssl_hmacMd5_init(void **native_id, const uint8_t *key, int32_t key_length);
static int LLCRYPTO_MAC_openssl_update(void *native_id, const uint8_t *buffer, int32_t buffer_length);
static int LLCRYPTO_MAC_openssl_do_final(void *native_id, uint8_t *out, int32_t out_length);
static int LLCRYPTO_MAC_openssl_reset(void *native_id);
static void LLCRYPTO_MAC_openssl_close(void *native_id);

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file
static LLCRYPTO_MAC_algorithm available_algorithms[3] = {
	{
		.name = "HmacSHA256",
		.init = LLCRYPTO_MAC_openssl_hmacSha256_init,
		.update = LLCRYPTO_MAC_openssl_update,
		.do_final = LLCRYPTO_MAC_openssl_do_final,
		.reset = LLCRYPTO_MAC_openssl_reset,
		.close = LLCRYPTO_MAC_openssl_close,
		.description = {
			.mac_length = 32
		}
	},
	{
		.name = "HmacSHA1",
		.init = LLCRYPTO_MAC_openssl_hmacSha1_init,
		.update = LLCRYPTO_MAC_openssl_update,
		.do_final = LLCRYPTO_MAC_openssl_do_final,
		.reset = LLCRYPTO_MAC_openssl_reset,
		.close = LLCRYPTO_MAC_openssl_close,
		.description = {
			.mac_length = 20
		}
	},
	{
		.name = "HmacMD5",
		.init = LLCRYPTO_MAC_openssl_hmacMd5_init,
		.update = LLCRYPTO_MAC_openssl_update,
		.do_final = LLCRYPTO_MAC_openssl_do_final,
		.reset = LLCRYPTO_MAC_openssl_reset,
		.close = LLCRYPTO_MAC_openssl_close,
		.description = {
			.mac_length = 16
		}
	}
};

static int LLCRYPTO_MAC_openssl_hmac_init(void **native_id, const uint8_t *key, int32_t key_length, const char *md) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);
	EVP_MAC_CTX *ctx = NULL;
	int return_code = MICROEJ_LLCRYPTO_MAC_SUCCESS;

	EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (NULL != mac) {
		ctx = EVP_MAC_CTX_new(mac);
		EVP_MAC_free(mac);
	}

	if (NULL == ctx) {
		return_code = MICROEJ_LLCRYPTO_MAC_ERROR;
	}

	if (MICROEJ_LLCRYPTO_MAC_SUCCESS == return_code) {
		OSSL_PARAM params[2];
		// https://github.com/openssl/openssl/issues/20956
		// cppcheck-suppress misra-c2012-7.4
		// cppcheck-suppress misra-c2012-11.8
		params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)md, 0);
		params[1] = OSSL_PARAM_construct_end();
		return_code = EVP_MAC_init(ctx, key, key_length, params);
	}

	if (MICROEJ_LLCRYPTO_MAC_SUCCESS != return_code) {
		EVP_MAC_CTX_free(ctx);
	} else {
		(*native_id) = (void *)ctx;
	}

	return return_code;
}

static int LLCRYPTO_MAC_openssl_hmacSha256_init(void **native_id, const uint8_t *key, int32_t key_length) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);
	return LLCRYPTO_MAC_openssl_hmac_init(native_id, key, key_length, "SHA256");
}

static int LLCRYPTO_MAC_openssl_hmacSha1_init(void **native_id, const uint8_t *key, int32_t key_length) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);
	return LLCRYPTO_MAC_openssl_hmac_init(native_id, key, key_length, "SHA1");
}

static int LLCRYPTO_MAC_openssl_hmacMd5_init(void **native_id, const uint8_t *key, int32_t key_length) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);
	return LLCRYPTO_MAC_openssl_hmac_init(native_id, key, key_length, "MD5");
}

static int LLCRYPTO_MAC_openssl_update(void *native_id, const uint8_t *buffer, int32_t buffer_length) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_MAC_CTX *ctx = (EVP_MAC_CTX *)(native_id);
	int rc = EVP_MAC_update(ctx, buffer, buffer_length);
	return rc;
}

static int LLCRYPTO_MAC_openssl_do_final(void *native_id, uint8_t *out, int32_t out_length) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_MAC_CTX *ctx = (EVP_MAC_CTX *)(native_id);
	size_t len = 0;
	int rc = EVP_MAC_final(ctx, out, &len, out_length);
	return rc;
}

static int LLCRYPTO_MAC_openssl_reset(void *native_id) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(native_id);
	/* EVP_MAC_CTX has no reset API; the context is re-initialized on next init call */
	return MICROEJ_LLCRYPTO_MAC_SUCCESS;
}

static void LLCRYPTO_MAC_openssl_close(void *native_id) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_MAC_CTX *ctx = (EVP_MAC_CTX *)(native_id);
	EVP_MAC_CTX_free(ctx);
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_MAC_IMPL_get_algorithm_description(uint8_t *algorithm_name,
                                                    LLCRYPTO_MAC_algorithm_desc *algorithm_desc) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLCRYPTO_MAC_algorithm);
	const LLCRYPTO_MAC_algorithm *algorithm = &available_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (strcmp((char *)algorithm_name, algorithm->name) == 0) {
			(void)memcpy(algorithm_desc, &(algorithm->description), sizeof(LLCRYPTO_MAC_algorithm_desc));
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

int32_t LLCRYPTO_MAC_IMPL_init(int32_t algorithm_id, uint8_t *key, int32_t key_length) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);

	void *native_id = NULL;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	int return_code = algorithm->init(&native_id, key, key_length);

	if (MICROEJ_LLCRYPTO_MAC_SUCCESS != return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return_code = MICROEJ_LLCRYPTO_MAC_ERROR;
	}

	if (MICROEJ_LLCRYPTO_MAC_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_registerResource(native_id, algorithm->close, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			algorithm->close((void *)native_id);
			return_code = MICROEJ_LLCRYPTO_MAC_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_MAC_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		return_code = (int32_t)native_id;
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

void LLCRYPTO_MAC_IMPL_update(int32_t algorithm_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                              int32_t buffer_length) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int return_code = algorithm->update((void *)native_id, &buffer[buffer_offset], buffer_length);

	if (return_code != MICROEJ_LLCRYPTO_MAC_SUCCESS) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
}

void LLCRYPTO_MAC_IMPL_do_final(int32_t algorithm_id, int32_t native_id, uint8_t *out, int32_t out_offset,
                                int32_t out_length) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int return_code = algorithm->do_final((void *)native_id, &out[out_offset], out_length);

	if (return_code != MICROEJ_LLCRYPTO_MAC_SUCCESS) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
}

void LLCRYPTO_MAC_IMPL_reset(int32_t algorithm_id, int32_t native_id) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int return_code = algorithm->reset((void *)native_id);

	if (return_code != MICROEJ_LLCRYPTO_MAC_SUCCESS) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
}

void LLCRYPTO_MAC_IMPL_close(int32_t algorithm_id, int32_t native_id) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	algorithm->close((void *)native_id);
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	if (SNI_unregisterResource((void *)native_id, (SNI_closeFunction)algorithm->close) != SNI_OK) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource\n");
	}
}

int32_t LLCRYPTO_MAC_IMPL_get_close_id(int32_t algorithm_id) {
	LLCRYPTO_MAC_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)algorithm->close;
}
