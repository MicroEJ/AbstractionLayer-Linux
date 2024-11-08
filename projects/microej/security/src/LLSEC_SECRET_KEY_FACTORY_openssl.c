/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
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

#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>

#include "sni.h"
#include "LLSEC_SECRET_KEY_FACTORY_impl.h"
#include "LLSEC_configuration.h"
#include "LLSEC_openssl.h"

#define MICROEJ_LLSECU_SECRET_KEY_FACTORY_SUCCESS 1
#define MICROEJ_LLSECU_SECRET_KEY_FACTORY_ERROR 0

// #define LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE

#ifdef LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE
#define LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF(...) ((void)0)
#endif

typedef int32_t (*LLSEC_SECRET_KEY_FACTORY_get_key_data)(LLSEC_secret_key* secret_key, LLSEC_md_type md_type, uint8_t* password, int32_t password_length, uint8_t* salt, int32_t salt_length, int32_t iterations, int32_t key_length);
typedef void    (*LLSEC_SECRET_KEY_FACTORY_key_close)(void* native_id);

int32_t     LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data(LLSEC_secret_key* secret_key, LLSEC_md_type md_type, uint8_t* password, int32_t password_length, uint8_t* salt, int32_t salt_length, int32_t iterations, int32_t key_length);
static void LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_key_close(void* native_id);
void        LLSEC_SECRET_KEY_FACTORY_openssl_free_secret_key(LLSEC_secret_key* secret_key);

typedef struct {
	const char*                           name;
	LLSEC_md_type                         md_type;
	LLSEC_SECRET_KEY_FACTORY_get_key_data get_key_data;
	LLSEC_SECRET_KEY_FACTORY_key_close    key_close;

} LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm;

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file.
static LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm available_algorithms[5] = {
	{
		.name         = "PBKDF2WithHmacSHA1",
		.md_type      = LLSEC_MD_SHA1,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
		.key_close    = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_key_close
	},
	{
		.name         = "PBKDF2WithHmacSHA224",
		.md_type      = LLSEC_MD_SHA224,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
		.key_close    = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_key_close
	},
	{
		.name         = "PBKDF2WithHmacSHA256",
		.md_type      = LLSEC_MD_SHA256,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
		.key_close    = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_key_close
	},
	{
		.name         = "PBKDF2WithHmacSHA384",
		.md_type      = LLSEC_MD_SHA384,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
		.key_close    = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_key_close
	},
	{
		.name         = "PBKDF2WithHmacSHA512",
		.md_type      = LLSEC_MD_SHA512,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data,
		.key_close    = LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_key_close
	}
};

void LLSEC_SECRET_KEY_FACTORY_openssl_free_secret_key(LLSEC_secret_key* secret_key) {
	if(NULL != secret_key->key) {
		LLSEC_free(secret_key->key);
	}
	if(NULL != secret_key) {
		LLSEC_free(secret_key);
	}
}

int32_t LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_get_key_data(LLSEC_secret_key* secret_key, LLSEC_md_type md_type, uint8_t* password, int32_t password_length, uint8_t* salt, int32_t salt_length, int32_t iterations, int32_t key_length) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s \n", __func__);

	int32_t return_code = MICROEJ_LLSECU_SECRET_KEY_FACTORY_SUCCESS;
	const EVP_MD *md = NULL;

	/* Allocate resources */
	secret_key->key = (unsigned char*)LLSEC_calloc(key_length, sizeof(unsigned char));
	if (NULL == secret_key->key) {
		(void)SNI_throwNativeException(SNI_ERROR, "LLSEC_calloc() failed");
		return_code = MICROEJ_LLSECU_SECRET_KEY_FACTORY_ERROR;
	}

	/* Set MD to be used */
	switch (md_type) {
		case LLSEC_MD_SHA1:
			md = EVP_sha1();
			break;
		case LLSEC_MD_SHA224:
			md = EVP_sha224();
			break;
		case LLSEC_MD_SHA256:
			md = EVP_sha256();
			break;
		case LLSEC_MD_SHA384:
			md = EVP_sha384();
			break;
		case LLSEC_MD_SHA512:
			md = EVP_sha512();
			break;
		default:
			(void)SNI_throwNativeException(SNI_ERROR, "invalid MD");
			return_code = MICROEJ_LLSECU_SECRET_KEY_FACTORY_ERROR;
			break;
	}

	/* PKCS#5 PBKDF2 using HMAC */
	if (MICROEJ_LLSECU_SECRET_KEY_FACTORY_SUCCESS == return_code) {
		secret_key->key_length = key_length;
		int openssl_rc = PKCS5_PBKDF2_HMAC((const char*) password,
										   (int) password_length,
										   (const unsigned char *) salt,
										   (int) salt_length,
										   (int) iterations,
										   (const EVP_MD*) md,
										   (int) secret_key->key_length,
										   (unsigned char*) secret_key->key);
		if (1 != openssl_rc) {
			LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s PKCS5_PBKDF2_HMAC() failed\n", __func__);
			(void)SNI_throwNativeException(SNI_ERROR, "PKCS5_PBKDF2_HMAC() failed");
			return_code = MICROEJ_LLSECU_SECRET_KEY_FACTORY_ERROR;
		}
	}

	/* Register SNI close callback */
	if (MICROEJ_LLSECU_SECRET_KEY_FACTORY_SUCCESS == return_code) {
		if (SNI_OK != SNI_registerResource((void* )secret_key, (SNI_closeFunction)LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_key_close, NULL)) {
			(void)SNI_throwNativeException(SNI_ERROR, "Can't register SNI native resource");
			return_code = MICROEJ_LLSECU_SECRET_KEY_FACTORY_ERROR;
		}
	}

	/* Return key struct addr (native_id) */
	if (MICROEJ_LLSECU_SECRET_KEY_FACTORY_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t)secret_key;
		LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s PKCS5_PBKDF2_HMAC() success. (native_id = %d)\n", __func__, (int)return_code);
	} else {
		LLSEC_SECRET_KEY_FACTORY_openssl_free_secret_key(secret_key);
	}

	return return_code;
}

static void LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_key_close(void* native_id) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s (native_id = %p)\n", __func__, native_id);
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	LLSEC_secret_key* secret_key = (LLSEC_secret_key*)native_id;

	/* Release resources */
	LLSEC_SECRET_KEY_FACTORY_openssl_free_secret_key(secret_key);

	/* Unregister SNI close callback */
	if (SNI_OK != SNI_unregisterResource((void*)native_id, (SNI_closeFunction)LLSEC_SECRET_KEY_FACTORY_PBKDF2_openssl_key_close)) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource");
	}
}

/**
 * @brief Get the supported algorithm native ID.
 *
 * @param[in] algorithm_name        Null terminated string that describes the algorithm.
 *
 * @return The algorithm ID on success or -1 on error.
 */
int32_t LLSEC_SECRET_KEY_FACTORY_IMPL_get_algorithm(uint8_t *algorithm_name) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm);
	LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm* algorithm = &available_algorithms[0];

	/* Check corresponding algorithm */
	while (--nb_algorithms >= 0) {
		if (strcmp((char*)algorithm_name, algorithm->name) == 0) {
			LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s Algorithm %s found\n", __func__, algorithm->name);
			break;
		}
		algorithm++;
	}

	if (0 <= nb_algorithms) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t)algorithm;
	}
	LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s Return handler = %d\n", __func__, (int)return_code);

	return return_code;
}

/**
 * @brief Generate a secret key from the encoded key format.
 *
 * @param[in] algorithm_id    algorithm pointer
 * @param[in] password        the password to encode, a null terminated '\0' byte array representation of the format in String
 * @param[in] password_length the length of password (in bytes)
 * @param[in] salt            salt
 * @param[in] salt_length     salt length (in bytes)
 * @param[in] iterations      number of iterations
 * @param[in] key_length      the length of encodedKey to generate (in bits)
 *
 * @return the pointer of the C structure holding the key data
 *
 * @throws NativeException on error
 */
int32_t LLSEC_SECRET_KEY_FACTORY_IMPL_get_key_data(int32_t algorithm_id, uint8_t *password, int32_t password_length,
												   uint8_t *salt, int32_t salt_length, int32_t iterations,
												   int32_t key_length) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s password length = %d, salt length = %d, key length = %d (handler = %d)\n", __func__, (int)password_length, (int)salt_length, (int)key_length, (int)algorithm_id);
	int32_t return_code = SNI_ERROR;

	/* Allocate secret key structure */
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	LLSEC_secret_key* secret_key = (LLSEC_secret_key*)LLSEC_calloc(1, sizeof(LLSEC_secret_key));
	if (NULL == secret_key) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't allocate LLSEC_secret_key structure");
	} else {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm* algorithm = (LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm*)algorithm_id;
		return_code = algorithm->get_key_data(secret_key, algorithm->md_type, password, password_length, salt, salt_length, iterations, key_length/8);
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
int32_t LLSEC_SECRET_KEY_FACTORY_IMPL_get_close_id(int32_t algorithm_id) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_PRINTF("%s (handler = %d)\n", __func__, (int)algorithm_id);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm* algorithm = (LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm*)algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)algorithm->key_close;
}
