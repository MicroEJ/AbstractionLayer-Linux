/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

#include <LLCRYPTO_DIGEST_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/err.h>
#include <string.h>
#include <sni.h>
#include <stdint.h>

#define MICROEJ_LLCRYPTO_DIGEST_SUCCESS 1
#define MICROEJ_LLCRYPTO_DIGEST_ERROR   0

// #define LLCRYPTO_DIGEST_DEBUG_TRACE

#ifdef LLCRYPTO_DIGEST_DEBUG_TRACE
#define LLCRYPTO_DIGEST_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_DIGEST_DEBUG_PRINTF(...) ((void)0)
#endif

typedef int (*LLCRYPTO_DIGEST_init)(void **native_id);
typedef int (*LLCRYPTO_DIGEST_update)(void *native_id, const uint8_t *buffer, int32_t buffer_length);
typedef int (*LLCRYPTO_DIGEST_digest)(void *native_id, uint8_t *out, int32_t *out_length);
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

static int openssl_digest_update(void *native_id, const uint8_t *buffer, int32_t buffer_length);
static int openssl_digest_digest(void *native_id, uint8_t *out, int32_t *out_length);
static int LLCRYPTO_DIGEST_MD5_init(void **native_id);
static int LLCRYPTO_DIGEST_SHA1_init(void **native_id);
static int LLCRYPTO_DIGEST_SHA256_init(void **native_id);
static int LLCRYPTO_DIGEST_SHA512_init(void **native_id);
static void openssl_digest_close(void *native_id);

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file.
static LLCRYPTO_DIGEST_algorithm available_algorithms[4] = {
	{
		.name = "MD5",
		.init = LLCRYPTO_DIGEST_MD5_init,
		.update = openssl_digest_update,
		.digest = openssl_digest_digest,
		.close = openssl_digest_close,
		{
			.digest_length = MD5_DIGEST_LENGTH
		}
	},
	{
		.name = "SHA-1",
		.init = LLCRYPTO_DIGEST_SHA1_init,
		.update = openssl_digest_update,
		.digest = openssl_digest_digest,
		.close = openssl_digest_close,
		{
			.digest_length = SHA_DIGEST_LENGTH
		}
	},
	{
		.name = "SHA-256",
		.init = LLCRYPTO_DIGEST_SHA256_init,
		.update = openssl_digest_update,
		.digest = openssl_digest_digest,
		.close = openssl_digest_close,
		{
			.digest_length = SHA256_DIGEST_LENGTH
		}
	},
	{
		.name = "SHA-512",
		.init = LLCRYPTO_DIGEST_SHA512_init,
		.update = openssl_digest_update,
		.digest = openssl_digest_digest,
		.close = openssl_digest_close,
		{
			.digest_length = SHA512_DIGEST_LENGTH
		}
	}
};

/*
 * Generic openssl function
 */
static int openssl_digest_update(void *native_id, const uint8_t *buffer, int32_t buffer_length) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)native_id;
	int rc = EVP_DigestUpdate(md_ctx, buffer, buffer_length);

	return rc;
}

static int openssl_digest_digest(void *native_id, uint8_t *out, int32_t *out_length) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)native_id;
	int rc = EVP_DigestFinal_ex(md_ctx, out, (unsigned int *)out_length);

	return rc;
}

static void openssl_digest_close(void *native_id) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_MD_CTX *md_ctx = (EVP_MD_CTX *)native_id;
	EVP_MD_CTX_free(md_ctx);
}

/*
 * Specific sha-1 function
 */
static int LLCRYPTO_DIGEST_MD5_init(void **native_id) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	int return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;

	// Memory allocation
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
	if (NULL == md_ctx) {
		return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		return_code = EVP_DigestInit_ex(md_ctx, EVP_md5(), NULL);
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		*native_id = md_ctx;
	} else {
		EVP_MD_CTX_free(md_ctx);
	}

	return return_code;
}

/*
 * Specific sha-1 function
 */
static int LLCRYPTO_DIGEST_SHA1_init(void **native_id) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	int return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;

	// Memory allocation
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
	if (NULL == md_ctx) {
		return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		return_code = EVP_DigestInit_ex(md_ctx, EVP_sha1(), NULL);
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		*native_id = md_ctx;
	} else {
		EVP_MD_CTX_free(md_ctx);
	}

	return return_code;
}

/*
 * Specific sha-256 function
 */
static int LLCRYPTO_DIGEST_SHA256_init(void **native_id) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	int return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;

	// Memory allocation
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
	if (NULL == md_ctx) {
		return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		return_code = EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		*native_id = md_ctx;
	} else {
		EVP_MD_CTX_free(md_ctx);
	}

	return return_code;
}

/*
 * Specific sha-512 function
 */
static int LLCRYPTO_DIGEST_SHA512_init(void **native_id) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	int return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;

	// Memory allocation
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
	if (NULL == md_ctx) {
		return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		return_code = EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL);
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		*native_id = md_ctx;
	} else {
		EVP_MD_CTX_free(md_ctx);
	}

	return return_code;
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_DIGEST_IMPL_get_algorithm_description(uint8_t *algorithm_name,
                                                       LLCRYPTO_DIGEST_algorithm_desc *algorithm_desc) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLCRYPTO_DIGEST_algorithm);
	LLCRYPTO_DIGEST_algorithm *algorithm = &available_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			(void)memcpy(algorithm_desc, &(algorithm->description), sizeof(LLCRYPTO_DIGEST_algorithm_desc));
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

int32_t LLCRYPTO_DIGEST_IMPL_init(int32_t algorithm_id) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	void *native_id = NULL;
	int32_t return_code = MICROEJ_LLCRYPTO_DIGEST_SUCCESS;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;

	return_code = algorithm->init((void **)&native_id);
	if (MICROEJ_LLCRYPTO_DIGEST_ERROR == return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_registerResource(native_id, algorithm->close, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			algorithm->close((void *)native_id);
			return_code = MICROEJ_LLCRYPTO_DIGEST_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		return_code = (int32_t)(native_id);
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

void LLCRYPTO_DIGEST_IMPL_close(int32_t algorithm_id, int32_t native_id) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	algorithm->close((void *)native_id);
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	if (SNI_unregisterResource((void *)native_id, (SNI_closeFunction)algorithm->close) != SNI_OK) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource\n");
	}
}

int32_t LLCRYPTO_DIGEST_IMPL_get_close_id(int32_t algorithm_id) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)algorithm->close;
}

void LLCRYPTO_DIGEST_IMPL_digest(int32_t algorithm_id, int32_t native_id, uint8_t *out, int32_t out_offset,
                                 int32_t out_length) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int return_code = algorithm->digest((void *)native_id, &out[out_offset], &out_length);
	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS != return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
}

void LLCRYPTO_DIGEST_IMPL_update(int32_t algorithm_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                                 int32_t buffer_length) {
	LLCRYPTO_DIGEST_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_DIGEST_algorithm *algorithm = (LLCRYPTO_DIGEST_algorithm *)algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int return_code = algorithm->update((void *)native_id, &buffer[buffer_offset], buffer_length);
	if (MICROEJ_LLCRYPTO_DIGEST_SUCCESS != return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
}
