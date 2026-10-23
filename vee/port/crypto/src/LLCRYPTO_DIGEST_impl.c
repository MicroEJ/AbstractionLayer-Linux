/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 *
 */

#include <stdint.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <LLCRYPTO_DIGEST_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_utils.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

#define MICROEJ_LLCRYPTO_DIGEST_SUCCESS 1
#define MICROEJ_LLCRYPTO_DIGEST_ERROR   0

typedef int (*LLCRYPTO_DIGEST_init)(EVP_MD_CTX **native_id);
typedef int (*LLCRYPTO_DIGEST_update)(EVP_MD_CTX *ctx, const uint8_t *buffer, int32_t buffer_length);
typedef int (*LLCRYPTO_DIGEST_digest)(EVP_MD_CTX *ctx, uint8_t *out);
typedef void (*LLCRYPTO_DIGEST_close)(void *native_id);

/*
 * LL-API related functions & struct
 */
typedef struct {
	char *name;
	LLCRYPTO_DIGEST_init init;
	LLCRYPTO_DIGEST_update update;
	LLCRYPTO_DIGEST_digest digest;
	LLCRYPTO_DIGEST_close close;
	LLCRYPTO_DIGEST_algorithm_desc description;
} LLCRYPTO_DIGEST_algorithm;

static int llcrypto_openssl_digest_update(EVP_MD_CTX *ctx, const uint8_t *buffer, int32_t buffer_length);
static int llcrypto_openssl_digest_digest(EVP_MD_CTX *ctx, uint8_t *out);
static int llcrypto_openssl_digest_md5_init(EVP_MD_CTX **native_id);
static int llcrypto_openssl_digest_sha1_init(EVP_MD_CTX **native_id);
static int llcrypto_openssl_digest_sha256_init(EVP_MD_CTX **native_id);
static int llcrypto_openssl_digest_sha512_init(EVP_MD_CTX **native_id);
static void llcrypto_openssl_digest_close(void *native_id);

/*
 * Generic openssl function
 */
static int llcrypto_openssl_digest_update(EVP_MD_CTX *ctx, const uint8_t *buffer, int32_t buffer_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	int rc = EVP_DigestUpdate(ctx, buffer, buffer_length);

	return rc;
}

static int llcrypto_openssl_digest_digest(EVP_MD_CTX *ctx, uint8_t *out) {
	VEEPORT_LOGGER_LOG_DBG("");

	/* The digest length is fixed per algorithm and known from description.digest_length, so there
	 * is nothing for EVP_DigestFinal_ex to report back. */
	int rc = EVP_DigestFinal_ex(ctx, out, NULL);

	return rc;
}

static void llcrypto_openssl_digest_close(void *native_id) {
	VEEPORT_LOGGER_LOG_DBG("");

	EVP_MD_CTX *ctx = (EVP_MD_CTX *)native_id;
	EVP_MD_CTX_free(ctx);
}

/*
 * Specific sha-1 function
 */
static int llcrypto_openssl_digest_md5_init(EVP_MD_CTX **native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	int return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;

	// Memory allocation
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if (NULL == ctx) {
		return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		return_code = EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		*native_id = ctx;
	} else {
		EVP_MD_CTX_free(ctx);
	}

	return return_code;
}

/*
 * Specific sha-1 function
 */
static int llcrypto_openssl_digest_sha1_init(EVP_MD_CTX **native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	int return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;

	// Memory allocation
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if (NULL == ctx) {
		return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		return_code = EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		*native_id = ctx;
	} else {
		EVP_MD_CTX_free(ctx);
	}

	return return_code;
}

/*
 * Specific sha-256 function
 */
static int llcrypto_openssl_digest_sha256_init(EVP_MD_CTX **native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	int return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;

	// Memory allocation
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if (NULL == ctx) {
		return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		return_code = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		*native_id = ctx;
	} else {
		EVP_MD_CTX_free(ctx);
	}

	return return_code;
}

/*
 * Specific sha-512 function
 */
static int llcrypto_openssl_digest_sha512_init(EVP_MD_CTX **native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	int return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;

	// Memory allocation
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if (NULL == ctx) {
		return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		return_code = EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		*native_id = ctx;
	} else {
		EVP_MD_CTX_free(ctx);
	}

	return return_code;
}

int32_t LLCRYPTO_DIGEST_IMPL_get_algorithm_description(uint8_t *algorithm_name,
                                                       LLCRYPTO_DIGEST_algorithm_desc *algorithm_desc) {
	static const LLCRYPTO_DIGEST_algorithm available_algorithms[4] = {
		{
			.name = "MD5",
			.init = llcrypto_openssl_digest_md5_init,
			.update = llcrypto_openssl_digest_update,
			.digest = llcrypto_openssl_digest_digest,
			.close = llcrypto_openssl_digest_close,
			.description = {
				.digest_length = MD5_DIGEST_LENGTH
			}
		},
		{
			.name = "SHA-1",
			.init = llcrypto_openssl_digest_sha1_init,
			.update = llcrypto_openssl_digest_update,
			.digest = llcrypto_openssl_digest_digest,
			.close = llcrypto_openssl_digest_close,
			.description = {
				.digest_length = SHA_DIGEST_LENGTH
			}
		},
		{
			.name = "SHA-256",
			.init = llcrypto_openssl_digest_sha256_init,
			.update = llcrypto_openssl_digest_update,
			.digest = llcrypto_openssl_digest_digest,
			.close = llcrypto_openssl_digest_close,
			.description = {
				.digest_length = SHA256_DIGEST_LENGTH
			}
		},
		{
			.name = "SHA-512",
			.init = llcrypto_openssl_digest_sha512_init,
			.update = llcrypto_openssl_digest_update,
			.digest = llcrypto_openssl_digest_digest,
			.close = llcrypto_openssl_digest_close,
			.description = {
				.digest_length = SHA512_DIGEST_LENGTH
			}
		}
	};

	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = SNI_ERROR;
	size_t nb_algorithms = sizeof(available_algorithms) / sizeof(available_algorithms[0]);
	const LLCRYPTO_DIGEST_algorithm *algorithm = &available_algorithms[0];

	/* The description struct is mapped on a Java byte array whose length the caller chooses, so
	 * it is checked against the struct it must hold before the copy below. */
	if (!sni_array_contains_range(algorithm_desc, 0, (int32_t)sizeof(LLCRYPTO_DIGEST_algorithm_desc))) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		for (size_t i = 0; i < nb_algorithms; i++) {
			if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
				(void)memcpy(algorithm_desc, &(algorithm->description), sizeof(LLCRYPTO_DIGEST_algorithm_desc));
				return_code = (int32_t)algorithm;
				break;
			}
			algorithm++;
		}
	}
	return return_code;
}

int32_t LLCRYPTO_DIGEST_IMPL_init(int32_t algorithm_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	EVP_MD_CTX *native_id = NULL;
	int32_t return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;
	LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;

	return_code = algorithm->init(&native_id);
	if (MICROEJ_LLCRYPTO_DIGEST_ERROR == return_code) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_OK != SNI_registerResource(native_id, algorithm->close, NULL)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Can't register SNI native resource");
			algorithm->close(native_id);
			return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		return_code = (int32_t)native_id;
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

void LLCRYPTO_DIGEST_IMPL_close(int32_t algorithm_id, int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;
	llcrypto_unregister_and_close((EVP_MD_CTX *)native_id, algorithm->close);
}

int32_t LLCRYPTO_DIGEST_IMPL_get_close_id(int32_t algorithm_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	const LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;
	return sni_close_id(algorithm->close);
}

void LLCRYPTO_DIGEST_IMPL_digest(int32_t algorithm_id, int32_t native_id, uint8_t *out, int32_t out_offset,
                                 int32_t out_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;
	int32_t digest_length = (int32_t)algorithm->description.digest_length;
	/* EVP_DigestFinal_ex always writes digest_length bytes and never reads out_length, so
	 * out_length is a capacity here: the window the caller granted has to be inside the array and
	 * large enough for the digest. */
	if (!sni_array_contains_range(out, out_offset, out_length) || (out_length < digest_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		int return_code = algorithm->digest((EVP_MD_CTX *)native_id, &out[out_offset]);
		if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS != return_code) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		}
	}
}

void LLCRYPTO_DIGEST_IMPL_update(int32_t algorithm_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                                 int32_t buffer_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;
	if (!sni_array_contains_range(buffer, buffer_offset, buffer_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		int return_code = algorithm->update((EVP_MD_CTX *)native_id, &buffer[buffer_offset], buffer_length);
		if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS != return_code) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		}
	}
}
