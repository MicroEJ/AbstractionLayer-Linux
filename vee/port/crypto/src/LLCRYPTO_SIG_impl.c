/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <LLCRYPTO_SIG_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include "LLCRYPTO_key.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sni.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define MICROEJ_LLCRYPTO_SIGNATURE_INVALID 2
#define MICROEJ_LLCRYPTO_SIG_SUCCESS 1
#define MICROEJ_LLCRYPTO_SIG_ERROR   0

// #define LLCRYPTO_SIG_DEBUG_TRACE

#ifdef LLCRYPTO_SIG_DEBUG_TRACE
#define LLCRYPTO_SIG_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_SIG_DEBUG_PRINTF(...) ((void)0)
#endif

typedef struct LLCRYPTO_SIG_algorithm LLCRYPTO_SIG_algorithm;
typedef int (*LLCRYPTO_SIG_verify)(const LLCRYPTO_SIG_algorithm *algorithm, const uint8_t *signature,
                                   int32_t signature_length, const struct llcrypto_key *pub_key, const uint8_t *digest,
                                   int32_t digest_length);

typedef int (*LLCRYPTO_SIG_sign)(const LLCRYPTO_SIG_algorithm *algorithm, uint8_t *signature, int32_t *signature_length,
                                 const struct llcrypto_key *priv_key, const uint8_t *digest, int32_t digest_length);

struct LLCRYPTO_SIG_algorithm {
	char *name;
	char *digest_name;
	char *digest_native_name;
	char *oid;
	LLCRYPTO_SIG_verify verify;
	LLCRYPTO_SIG_sign sign;
};

static int LLCRYPTO_SIG_openssl_verify(const LLCRYPTO_SIG_algorithm *algorithm, const uint8_t *signature,
                                       int32_t signature_length, const struct llcrypto_key *pub_key,
                                       const uint8_t *digest,
                                       int32_t digest_length);
static int LLCRYPTO_SIG_openssl_sign(const LLCRYPTO_SIG_algorithm *algorithm, uint8_t *signature,
                                     int32_t *signature_length,
                                     const struct llcrypto_key *priv_key, const uint8_t *digest, int32_t digest_length);

static LLCRYPTO_SIG_algorithm available_algorithms[] = {
	{
		.name = "SHA256withRSA",
		.digest_name = "SHA-256",
		.digest_native_name = "SHA256",
		.oid = "1.2.840.113549.1.1.11",
		.verify = LLCRYPTO_SIG_openssl_verify,
		.sign = LLCRYPTO_SIG_openssl_sign
	},
	{
		.name = "SHA256withECDSA",
		.digest_name = "SHA-256",
		.digest_native_name = "SHA256",
		.oid = "1.2.840.10045.4.3.2",
		.verify = LLCRYPTO_SIG_openssl_verify,
		.sign = LLCRYPTO_SIG_openssl_sign
	}
};

static int LLCRYPTO_SIG_openssl_verify(const LLCRYPTO_SIG_algorithm *algorithm, const uint8_t *signature,
                                       int32_t signature_length, const struct llcrypto_key *pub_key,
                                       const uint8_t *digest,
                                       int32_t digest_length) {
	LLCRYPTO_SIG_DEBUG_PRINTF("%s \n", __func__);

	EVP_PKEY_CTX *ctx = NULL;
	int return_code = MICROEJ_LLCRYPTO_SIG_SUCCESS;

	ctx = EVP_PKEY_CTX_new(pub_key->evp_key, NULL);
	if (NULL == ctx) {
		LLCRYPTO_SIG_DEBUG_PRINTF("EVP_PKEY_CTX_new failed");
		return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_verify_init(ctx) <= 0) {
			LLCRYPTO_SIG_DEBUG_PRINTF("EVP_PKEY_verify_init failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(algorithm->digest_native_name)) <= 0) {
			LLCRYPTO_SIG_DEBUG_PRINTF("EVP_PKEY_CTX_set_signature_md failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		int rc = EVP_PKEY_verify(ctx, signature, signature_length, digest, digest_length);
		if (1 == rc) {
			return_code = MICROEJ_LLCRYPTO_SIG_SUCCESS;
		} else {
			return_code = MICROEJ_LLCRYPTO_SIGNATURE_INVALID;
		}
	}
	if (NULL != ctx) {
		EVP_PKEY_CTX_free(ctx);
	}

	return return_code;
}

static int LLCRYPTO_SIG_openssl_sign(const LLCRYPTO_SIG_algorithm *algorithm, uint8_t *signature,
                                     int32_t *signature_length,
                                     const struct llcrypto_key *priv_key, const uint8_t *digest,
                                     int32_t digest_length) {
	LLCRYPTO_SIG_DEBUG_PRINTF("%s \n", __func__);

	EVP_PKEY_CTX *ctx;
	int return_code = MICROEJ_LLCRYPTO_SIG_SUCCESS;

	ctx = EVP_PKEY_CTX_new(priv_key->evp_key, NULL);
	if (NULL == ctx) {
		LLCRYPTO_SIG_DEBUG_PRINTF("EVP_PKEY_CTX_new failed");
		return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_sign_init(ctx) <= 0) {
			LLCRYPTO_SIG_DEBUG_PRINTF("EVP_PKEY_sign_init failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(algorithm->digest_native_name)) <= 0) {
			LLCRYPTO_SIG_DEBUG_PRINTF("EVP_PKEY_CTX_set_signature_md failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_sign(ctx, NULL, (size_t *)signature_length, digest, digest_length) <= 0) {
			LLCRYPTO_SIG_DEBUG_PRINTF("First EVP_PKEY_sign failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_sign(ctx, signature, (size_t *)signature_length, digest, digest_length) <= 0) {
			LLCRYPTO_SIG_DEBUG_PRINTF("Second EVP_PKEY_sign failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (NULL != ctx) {
		EVP_PKEY_CTX_free(ctx);
	}

	return return_code;
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_SIG_IMPL_get_algorithm_description(uint8_t *algorithm_name, uint8_t *digest_algorithm_name,
                                                    int32_t digest_algorithm_name_length) {
	LLCRYPTO_SIG_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;

	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLCRYPTO_SIG_algorithm);
	LLCRYPTO_SIG_algorithm *algorithm = &available_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (strcmp((char *)algorithm_name, algorithm->name) == 0) {
			(void)strncpy((char *)digest_algorithm_name, algorithm->digest_name, digest_algorithm_name_length);
			digest_algorithm_name[digest_algorithm_name_length - 1] = '\0';
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

// cppcheck-suppress constParameterPointer // SNI type conflict
void LLCRYPTO_SIG_IMPL_get_algorithm_oid(uint8_t *algorithm_name, uint8_t *oid, int32_t oid_length) {
	LLCRYPTO_SIG_DEBUG_PRINTF("%s \n", __func__);

	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLCRYPTO_SIG_algorithm);
	LLCRYPTO_SIG_algorithm *algorithm = &available_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			int32_t length = strlen(algorithm->oid);
			if (length > (oid_length - 1)) {
				(void)SNI_throwNativeException(SNI_ERROR, "native oid length is bigger that the output byte array");
			} else {
				(void)strncpy((char *)oid, algorithm->oid, oid_length - 1);
				oid[length + 1] = '\0';
			}
			break;
		}
		algorithm++;
	}
	if (0 == nb_algorithms) {
		(void)SNI_throwNativeException(SNI_ERROR, "Algorithm not found");
	}
}

uint8_t LLCRYPTO_SIG_IMPL_verify(int32_t algorithm_id, uint8_t *signature, int32_t signature_length, int32_t nativeId,
                                 uint8_t *digest, int32_t digest_length) {
	LLCRYPTO_SIG_DEBUG_PRINTF("%s \n", __func__);
	int return_jcode = SNI_ERROR;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_SIG_algorithm *algorithm = (LLCRYPTO_SIG_algorithm *)algorithm_id;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	int return_code = algorithm->verify(algorithm, signature, signature_length, (const struct llcrypto_key *)nativeId,
	                                    digest, digest_length);

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		return_jcode = JTRUE;
	} else if (MICROEJ_LLCRYPTO_SIGNATURE_INVALID == return_code) {
		return_jcode = JFALSE;
	} else {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return_jcode = SNI_ERROR;
	}
	return return_jcode;
}

int32_t LLCRYPTO_SIG_IMPL_sign(int32_t algorithm_id, uint8_t *signature, int32_t signature_length, int32_t nativeId,
                               uint8_t *digest, int32_t digest_length) {
	LLCRYPTO_SIG_DEBUG_PRINTF("%s \n", __func__);
	int return_jcode = SNI_ERROR;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_SIG_algorithm *algorithm = (LLCRYPTO_SIG_algorithm *)algorithm_id;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	int return_code = algorithm->sign(algorithm, signature, &signature_length, (const struct llcrypto_key *)nativeId,
	                                  digest, digest_length);

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS != return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return_jcode = JFALSE;
	} else {
		return_jcode = signature_length;
	}
	return return_jcode;
}
