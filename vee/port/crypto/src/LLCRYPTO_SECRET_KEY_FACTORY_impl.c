/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "sni.h"
#include "LLCRYPTO_SECRET_KEY_FACTORY_impl.h"
#include <LLCRYPTO_CONSTANTS.h>
#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_openssl.h"
#include "LLCRYPTO_key.h"

#define MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_SUCCESS 1
#define MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_ERROR 0

// #define LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE

#ifdef LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE
#define LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF(...) ((void)0)
#endif

typedef int32_t (*LLCRYPTO_SECRET_KEY_FACTORY_get_key_data)(LLCRYPTO_md_type md_type,
                                                            uint8_t *password, int32_t password_length, uint8_t *salt,
                                                            int32_t salt_length, int32_t iterations, int32_t key_length,
                                                            uint8_t *algorithm_name);

typedef struct {
	const char *name;
	LLCRYPTO_md_type md_type;
	LLCRYPTO_SECRET_KEY_FACTORY_get_key_data get_key_data;
} LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm;

static int32_t LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data(LLCRYPTO_md_type md_type,
                                                                       uint8_t *password, int32_t password_length,
                                                                       uint8_t *salt, int32_t salt_length,
                                                                       int32_t iterations, int32_t key_length,
                                                                       uint8_t *algorithm_name);

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file.
static LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm available_algorithms[5] = {
	{
		.name = "PBKDF2WithHmacSHA1",
		.md_type = LLCRYPTO_MD_SHA1,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
	},
	{
		.name = "PBKDF2WithHmacSHA224",
		.md_type = LLCRYPTO_MD_SHA224,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
	},
	{
		.name = "PBKDF2WithHmacSHA256",
		.md_type = LLCRYPTO_MD_SHA256,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
	},
	{
		.name = "PBKDF2WithHmacSHA384",
		.md_type = LLCRYPTO_MD_SHA384,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
	},
	{
		.name = "PBKDF2WithHmacSHA512",
		.md_type = LLCRYPTO_MD_SHA512,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
	}
};

static int32_t LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data(LLCRYPTO_md_type md_type,
                                                                       uint8_t *password, int32_t password_length,
                                                                       uint8_t *salt, int32_t salt_length,
                                                                       int32_t iterations, int32_t key_length,
                                                                       uint8_t *algorithm_name) {
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s \n", __func__);

	int32_t return_code = MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_SUCCESS;
	const EVP_MD *md = NULL;

	/* Temporary buffer for derived key bytes */
	unsigned char *derived = (unsigned char *)LLCRYPTO_calloc(key_length, sizeof(unsigned char));
	if (NULL == derived) {
		(void)SNI_throwNativeException(SNI_ERROR, "LLCRYPTO_calloc() failed");
		goto end;
	}

	/* Set MD to be used */
	switch (md_type) {
	case LLCRYPTO_MD_SHA1:
		md = EVP_sha1();
		break;
	case LLCRYPTO_MD_SHA224:
		md = EVP_sha224();
		break;
	case LLCRYPTO_MD_SHA256:
		md = EVP_sha256();
		break;
	case LLCRYPTO_MD_SHA384:
		md = EVP_sha384();
		break;
	case LLCRYPTO_MD_SHA512:
		md = EVP_sha512();
		break;
	default:
		(void)SNI_throwNativeException(SNI_ERROR, "invalid MD");
		return_code = MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_ERROR;
		break;
	}

	/* PKCS#5 PBKDF2 using HMAC */
	if (MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_SUCCESS == return_code) {
		int openssl_rc = PKCS5_PBKDF2_HMAC((const char *)password,
		                                   (int)password_length,
		                                   (const unsigned char *)salt,
		                                   (int)salt_length,
		                                   (int)iterations,
		                                   (const EVP_MD *)md,
		                                   (int)key_length,
		                                   derived);
		if (1 != openssl_rc) {
			LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s PKCS5_PBKDF2_HMAC() failed\n", __func__);
			(void)SNI_throwNativeException(SNI_ERROR, "PKCS5_PBKDF2_HMAC() failed");
			return_code = MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_ERROR;
		}
	}

	/* Wrap derived bytes in an llcrypto_key (copies the buffer) */
	if (MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_SUCCESS == return_code) {
		struct llcrypto_key *key = llcrypto_key_from_secret_key(derived, (size_t)key_length, algorithm_name);
		if (NULL == key) {
			(void)SNI_throwNativeException(SNI_ERROR, "Can't create llcrypto_key");
			return_code = MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_ERROR;
		} else {
			LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s PKCS5_PBKDF2_HMAC() success. (native_id = %p)\n", __func__,
			                                         (void *)key);
			// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
			return_code = (int32_t)key;
		}
	}

	LLCRYPTO_free(derived);
end:
	return return_code;
}

/**
 * @brief Get the supported algorithm native ID.
 *
 * @param[in] algorithm_name        Null terminated string that describes the algorithm.
 *
 * @return The algorithm ID on success or -1 on error.
 */
int32_t LLCRYPTO_SECRET_KEY_FACTORY_IMPL_get_algorithm(uint8_t *algorithm_name) {
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm);
	LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm *algorithm = &available_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (strcmp((char *)algorithm_name, algorithm->name) == 0) {
			LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s Algorithm %s found\n", __func__, algorithm->name);
			break;
		}
		algorithm++;
	}

	if (0 <= nb_algorithms) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t)algorithm;
	}
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s Return handler = %d\n", __func__, (int)return_code);

	return return_code;
}

/**
 * @brief Generate a secret key from the encoded key format.
 *
 * @param[in] algorithm_id    algorithm pointer
 * @param[in] password        the password to encode
 * @param[in] password_length the length of password (in bytes)
 * @param[in] salt            salt
 * @param[in] salt_length     salt length (in bytes)
 * @param[in] iterations      number of iterations
 * @param[in] key_length      the length of key to generate (in bits)
 *
 * @return the pointer of the C structure holding the key data
 *
 * @throws NativeException on error
 */
int32_t LLCRYPTO_SECRET_KEY_FACTORY_IMPL_get_key_data(int32_t algorithm_id, uint8_t *password, int32_t password_length,
                                                      uint8_t *salt, int32_t salt_length, int32_t iterations,
                                                      int32_t key_length) {
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF(
		"%s password length = %d, salt length = %d, key length = %d (handler = %d)\n",
		__func__, (int)password_length, (int)salt_length, (int)key_length,
		(int)algorithm_id);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm *algorithm = (LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm *)algorithm_id;
	return algorithm->get_key_data(algorithm->md_type, password, password_length, salt, salt_length, iterations,
	                               key_length / 8, (uint8_t *)"AES");
}

/**
 * Gets the id of the native close function.
 *
 * @param [in] nativeAlgorithmId    the algorithm ID
 *
 * @return the id of the static native close function
 * @throws NativeException on error
 */
int32_t LLCRYPTO_SECRET_KEY_FACTORY_IMPL_get_close_id(int32_t algorithm_id) {
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s (handler = %d)\n", __func__, (int)algorithm_id);
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)llcrypto_key_free;
}
