/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <LLCRYPTO_MAC_impl.h>
#include <LLCRYPTO_CONSTANTS.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_utils.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

#define MICROEJ_LLCRYPTO_MAC_SUCCESS 1
#define MICROEJ_LLCRYPTO_MAC_ERROR   0

typedef int (*LLCRYPTO_MAC_init)(EVP_MAC_CTX **native_id, const uint8_t *key, int32_t key_length);
typedef int (*LLCRYPTO_MAC_update)(EVP_MAC_CTX *ctx, const uint8_t *buffer, int32_t buffer_length);
typedef int (*LLCRYPTO_MAC_do_final)(EVP_MAC_CTX *ctx, uint8_t *out, int32_t out_length);
typedef int (*LLCRYPTO_MAC_reset)(EVP_MAC_CTX *ctx);
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

static int llcrypto_openssl_mac_hmac_init(EVP_MAC_CTX **native_id, const uint8_t *key, int32_t key_length,
                                          const char *md);
static int llcrypto_openssl_mac_hmac_sha256_init(EVP_MAC_CTX **native_id, const uint8_t *key, int32_t key_length);
static int llcrypto_openssl_mac_hmac_sha1_init(EVP_MAC_CTX **native_id, const uint8_t *key, int32_t key_length);
static int llcrypto_openssl_mac_hmac_md5_init(EVP_MAC_CTX **native_id, const uint8_t *key, int32_t key_length);
static int llcrypto_openssl_mac_update(EVP_MAC_CTX *ctx, const uint8_t *buffer, int32_t buffer_length);
static int llcrypto_openssl_mac_do_final(EVP_MAC_CTX *ctx, uint8_t *out, int32_t out_length);
static int llcrypto_openssl_mac_reset(EVP_MAC_CTX *ctx);
static void llcrypto_openssl_mac_close(void *native_id);

static int llcrypto_openssl_mac_hmac_init(EVP_MAC_CTX **native_id, const uint8_t *key, int32_t key_length,
                                          const char *md) {
	VEEPORT_LOGGER_LOG_DBG("");
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
		/* cppcheck-suppress misra-c2012-11.8 ; OSSL_PARAM_construct_utf8_string declares its buffer
		 * as a non-const char*, and only reads it for an input parameter. */
		params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)md, 0);
		params[1] = OSSL_PARAM_construct_end();
		return_code = EVP_MAC_init(ctx, key, key_length, params);
	}

	if (MICROEJ_LLCRYPTO_MAC_SUCCESS != return_code) {
		EVP_MAC_CTX_free(ctx);
	} else {
		(*native_id) = ctx;
	}

	return return_code;
}

static int llcrypto_openssl_mac_hmac_sha256_init(EVP_MAC_CTX **native_id, const uint8_t *key, int32_t key_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	return llcrypto_openssl_mac_hmac_init(native_id, key, key_length, "SHA256");
}

static int llcrypto_openssl_mac_hmac_sha1_init(EVP_MAC_CTX **native_id, const uint8_t *key, int32_t key_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	return llcrypto_openssl_mac_hmac_init(native_id, key, key_length, "SHA1");
}

static int llcrypto_openssl_mac_hmac_md5_init(EVP_MAC_CTX **native_id, const uint8_t *key, int32_t key_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	return llcrypto_openssl_mac_hmac_init(native_id, key, key_length, "MD5");
}

static int llcrypto_openssl_mac_update(EVP_MAC_CTX *ctx, const uint8_t *buffer, int32_t buffer_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	return EVP_MAC_update(ctx, buffer, buffer_length);
}

static int llcrypto_openssl_mac_do_final(EVP_MAC_CTX *ctx, uint8_t *out, int32_t out_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	size_t len = 0;
	return EVP_MAC_final(ctx, out, &len, out_length);
}

static int llcrypto_openssl_mac_reset(EVP_MAC_CTX *ctx) {
	VEEPORT_LOGGER_LOG_DBG("");

	/* A null key with null parameters restores the state the last full initialization left:
	 * the key stays, the buffered message is dropped. That holds for HMAC, the only algorithm
	 * fetched here. A MAC that cannot recover its cipher state, such as GMAC, would instead need
	 * init to be called again with the original IV. */
	return EVP_MAC_init(ctx, NULL, 0, NULL);
}

static void llcrypto_openssl_mac_close(void *native_id) {
	VEEPORT_LOGGER_LOG_DBG("");

	EVP_MAC_CTX *ctx = (EVP_MAC_CTX *)native_id;
	EVP_MAC_CTX_free(ctx);
}

int32_t LLCRYPTO_MAC_IMPL_get_algorithm_description(uint8_t *algorithm_name,
                                                    LLCRYPTO_MAC_algorithm_desc *algorithm_desc) {
	static const LLCRYPTO_MAC_algorithm available_algorithms[3] = {
		{
			.name = "HmacSHA256",
			.init = llcrypto_openssl_mac_hmac_sha256_init,
			.update = llcrypto_openssl_mac_update,
			.do_final = llcrypto_openssl_mac_do_final,
			.reset = llcrypto_openssl_mac_reset,
			.close = llcrypto_openssl_mac_close,
			.description = {
				.mac_length = SHA256_DIGEST_LENGTH
			}
		},
		{
			.name = "HmacSHA1",
			.init = llcrypto_openssl_mac_hmac_sha1_init,
			.update = llcrypto_openssl_mac_update,
			.do_final = llcrypto_openssl_mac_do_final,
			.reset = llcrypto_openssl_mac_reset,
			.close = llcrypto_openssl_mac_close,
			.description = {
				.mac_length = SHA_DIGEST_LENGTH
			}
		},
		{
			.name = "HmacMD5",
			.init = llcrypto_openssl_mac_hmac_md5_init,
			.update = llcrypto_openssl_mac_update,
			.do_final = llcrypto_openssl_mac_do_final,
			.reset = llcrypto_openssl_mac_reset,
			.close = llcrypto_openssl_mac_close,
			.description = {
				.mac_length = MD5_DIGEST_LENGTH
			}
		}
	};

	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = SNI_ERROR;
	size_t nb_algorithms = sizeof(available_algorithms) / sizeof(available_algorithms[0]);
	const LLCRYPTO_MAC_algorithm *algorithm = &available_algorithms[0];

	/* The description struct is mapped on a Java byte array whose length the caller chooses, so
	 * it is checked against the struct it must hold before the copy below. */
	if (!sni_array_contains_range(algorithm_desc, 0, (int32_t)sizeof(LLCRYPTO_MAC_algorithm_desc))) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		for (size_t i = 0; i < nb_algorithms; i++) {
			if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
				(void)memcpy(algorithm_desc, &(algorithm->description), sizeof(LLCRYPTO_MAC_algorithm_desc));
				return_code = (int32_t)algorithm;
				break;
			}
			algorithm++;
		}
	}
	return return_code;
}

int32_t LLCRYPTO_MAC_IMPL_init(int32_t algorithm_id, uint8_t *key, int32_t key_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	EVP_MAC_CTX *native_id = NULL;
	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	int return_code = MICROEJ_LLCRYPTO_MAC_SUCCESS;

	/* An empty MAC key is meaningless, and the length reaches the EVP key setup as a size_t. */
	if ((key_length <= 0) || !sni_array_contains_range(key, 0, key_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		return_code = MICROEJ_LLCRYPTO_MAC_ERROR;
	} else {
		return_code = algorithm->init(&native_id, key, key_length);

		if (MICROEJ_LLCRYPTO_MAC_SUCCESS != return_code) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
			return_code = MICROEJ_LLCRYPTO_MAC_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_MAC_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_OK != SNI_registerResource(native_id, algorithm->close, NULL)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Can't register SNI native resource");
			algorithm->close(native_id);
			return_code = MICROEJ_LLCRYPTO_MAC_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_MAC_SUCCESS == return_code) {
		return_code = (int32_t)native_id;
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

void LLCRYPTO_MAC_IMPL_update(int32_t algorithm_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                              int32_t buffer_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	if (!sni_array_contains_range(buffer, buffer_offset, buffer_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		int return_code = algorithm->update((EVP_MAC_CTX *)native_id, &buffer[buffer_offset], buffer_length);

		if (MICROEJ_LLCRYPTO_MAC_SUCCESS != return_code) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		}
	}
}

void LLCRYPTO_MAC_IMPL_do_final(int32_t algorithm_id, int32_t native_id, uint8_t *out, int32_t out_offset,
                                int32_t out_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	if (!sni_array_contains_range(out, out_offset, out_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		int return_code = algorithm->do_final((EVP_MAC_CTX *)native_id, &out[out_offset], out_length);

		if (MICROEJ_LLCRYPTO_MAC_SUCCESS != return_code) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		}
	}
}

void LLCRYPTO_MAC_IMPL_reset(int32_t algorithm_id, int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");

	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	int return_code = algorithm->reset((EVP_MAC_CTX *)native_id);

	if (MICROEJ_LLCRYPTO_MAC_SUCCESS != return_code) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
	}
}

void LLCRYPTO_MAC_IMPL_close(int32_t algorithm_id, int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");

	LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;

	llcrypto_unregister_and_close((EVP_MAC_CTX *)native_id, algorithm->close);
}

int32_t LLCRYPTO_MAC_IMPL_get_close_id(int32_t algorithm_id) {
	VEEPORT_LOGGER_LOG_DBG("");

	const LLCRYPTO_MAC_algorithm *algorithm = (LLCRYPTO_MAC_algorithm *)algorithm_id;
	return sni_close_id(algorithm->close);
}
