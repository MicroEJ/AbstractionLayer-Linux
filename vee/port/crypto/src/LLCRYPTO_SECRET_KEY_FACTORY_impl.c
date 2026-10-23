/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <LLCRYPTO_SECRET_KEY_FACTORY_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

#define MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_SUCCESS 1
#define MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_ERROR 0

/** Digest algorithms selectable for PBKDF2 derivation. */
typedef enum {
	LLCRYPTO_MD_SHA1,
	LLCRYPTO_MD_SHA224,
	LLCRYPTO_MD_SHA256,
	LLCRYPTO_MD_SHA384,
	LLCRYPTO_MD_SHA512
} llcrypto_md_type;

typedef int32_t (*LLCRYPTO_SECRET_KEY_FACTORY_get_key_data)(llcrypto_md_type md_type,
                                                            uint8_t *password, int32_t password_length, uint8_t *salt,
                                                            int32_t salt_length, int32_t iterations, int32_t key_length,
                                                            const uint8_t *algorithm_name);

typedef struct {
	const char *name;
	llcrypto_md_type md_type;
	LLCRYPTO_SECRET_KEY_FACTORY_get_key_data get_key_data;
} LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm;

static int32_t llcrypto_openssl_secret_key_factory_pbkdf2_get_key_data(llcrypto_md_type md_type,
                                                                       uint8_t *password, int32_t password_length,
                                                                       uint8_t *salt, int32_t salt_length,
                                                                       int32_t iterations, int32_t key_length,
                                                                       const uint8_t *algorithm_name);

static int32_t llcrypto_openssl_secret_key_factory_pbkdf2_get_key_data(llcrypto_md_type md_type,
                                                                       uint8_t *password, int32_t password_length,
                                                                       uint8_t *salt, int32_t salt_length,
                                                                       int32_t iterations, int32_t key_length,
                                                                       const uint8_t *algorithm_name) {
	VEEPORT_LOGGER_LOG_DBG("");

	int32_t return_code = MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_SUCCESS;
	const EVP_MD *md = NULL;

	/* Temporary buffer for derived key bytes */
	unsigned char *derived = (unsigned char *)LLCRYPTO_calloc(key_length, sizeof(unsigned char));
	if (NULL == derived) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_OOM_EXCEPTION, "LLCRYPTO_calloc() failed");
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
	{
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "invalid MD");
		return_code = MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_ERROR;
		break;
	}
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
			VEEPORT_LOGGER_LOG_ERR("PKCS5_PBKDF2_HMAC() failed");
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "PKCS5_PBKDF2_HMAC() failed");
			return_code = MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_ERROR;
		}
	}

	/* Wrap derived bytes in an llcrypto_key (copies the buffer) */
	if (MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_SUCCESS == return_code) {
		struct llcrypto_key *key = llcrypto_key_from_secret_key(derived, (size_t)key_length, algorithm_name);
		if (NULL == key) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_OOM_EXCEPTION, "Can't create llcrypto_key");
			return_code = MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_ERROR;
		} else {
			VEEPORT_LOGGER_LOG_DBG("PKCS5_PBKDF2_HMAC() success. (native_id = %p)", (void *)key);
			return_code = (int32_t)key;
		}
	}

	/* Holds the derived key: llcrypto_key_from_secret_key copied it out. */
	OPENSSL_cleanse(derived, (size_t)key_length);
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
	static const LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm available_algorithms[5] = {
		{
			.name = "PBKDF2WithHmacSHA1",
			.md_type = LLCRYPTO_MD_SHA1,
			.get_key_data = llcrypto_openssl_secret_key_factory_pbkdf2_get_key_data,
		},
		{
			.name = "PBKDF2WithHmacSHA224",
			.md_type = LLCRYPTO_MD_SHA224,
			.get_key_data = llcrypto_openssl_secret_key_factory_pbkdf2_get_key_data,
		},
		{
			.name = "PBKDF2WithHmacSHA256",
			.md_type = LLCRYPTO_MD_SHA256,
			.get_key_data = llcrypto_openssl_secret_key_factory_pbkdf2_get_key_data,
		},
		{
			.name = "PBKDF2WithHmacSHA384",
			.md_type = LLCRYPTO_MD_SHA384,
			.get_key_data = llcrypto_openssl_secret_key_factory_pbkdf2_get_key_data,
		},
		{
			.name = "PBKDF2WithHmacSHA512",
			.md_type = LLCRYPTO_MD_SHA512,
			.get_key_data = llcrypto_openssl_secret_key_factory_pbkdf2_get_key_data,
		}
	};

	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = SNI_ERROR;
	size_t nb_algorithms = sizeof(available_algorithms) / sizeof(available_algorithms[0]);
	const LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm *algorithm = &available_algorithms[0];

	for (size_t i = 0; i < nb_algorithms; i++) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			VEEPORT_LOGGER_LOG_DBG("Algorithm %s found", algorithm->name);
			return_code = (int32_t)algorithm;
			break;
		}
		algorithm++;
	}
	VEEPORT_LOGGER_LOG_DBG("Return handler = %d", (int)return_code);

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
	VEEPORT_LOGGER_LOG_DBG("password length = %d, salt length = %d, key length = %d (handler = %d)",
	                       (int)password_length, (int)salt_length, (int)key_length, (int)algorithm_id);

	LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm *algorithm = (LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm *)algorithm_id;
	int32_t return_code = MICROEJ_LLCRYPTO_SECRET_KEY_FACTORY_ERROR;

	/* Bound both inputs here rather than in the PBKDF2 implementation: this is where the
	 * arrays are still in scope with their lengths, and PKCS5_PBKDF2_HMAC reads a negative
	 * password length as a request to measure the buffer with strlen. */
	if (!sni_array_contains_range(password, 0, password_length) ||
	    !sni_array_contains_range(salt, 0, salt_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		return_code = algorithm->get_key_data(algorithm->md_type, password, password_length, salt, salt_length,
		                                      iterations, key_length / 8, (const uint8_t *)"AES");
	}

	return return_code;
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
	VEEPORT_LOGGER_LOG_DBG("(handler = %d)", (int)algorithm_id);
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	return (int32_t)llcrypto_key_free;
}
