/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdint.h>
#include <string.h>

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"
#include "LLCRYPTO_SECRET_KEY_impl.h"
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

// #define LLCRYPTO_SECRET_KEY_DEBUG_TRACE

#ifdef LLCRYPTO_SECRET_KEY_DEBUG_TRACE
#define LLCRYPTO_SECRET_KEY_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_SECRET_KEY_DEBUG_PRINTF(...) ((void)0)
#endif

/**
 * @brief return the max size of the encoded key.
 *
 * @param[in] native_id the C structure pointer holding the key data
 *
 * @return max encoded size for the secret key in bytes
 *
 * @note Throws NativeException on error.
 */
int32_t LLCRYPTO_SECRET_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLCRYPTO_SECRET_KEY_DEBUG_PRINTF("%s (native_id = %d)\n", __func__, (int)native_id);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int32_t max_size = llcrypto_key_get_encoded_max_size(key);

	LLCRYPTO_SECRET_KEY_DEBUG_PRINTF("%s Return size = %d\n", __func__, (int)max_size);
	return max_size;
}

/**
 * @brief encode the secret key.
 *
 * @param[in]  native_id      the C structure pointer holding the key data
 * @param[out] output         a byte array to hold the encoded key data
 * @param[in]  output_length  the length of the output array (in bytes)
 *
 * @return the real size of the encoded key (in bytes).
 *
 * @note Throws NativeException on error.
 */
int32_t LLCRYPTO_SECRET_KEY_IMPL_get_encoded(int32_t native_id, uint8_t *output, int32_t output_length) {
	LLCRYPTO_SECRET_KEY_DEBUG_PRINTF("%s (native_id = %d)\n", __func__, (int)native_id);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int32_t key_length = llcrypto_key_get_encoded(key, output, output_length);

	LLCRYPTO_SECRET_KEY_DEBUG_PRINTF("%s Return size = %d\n", __func__, (int)key_length);
	return key_length;
}

/**
 * @brief Create an opaque secret key from raw bytes.
 *
 * @param[in] raw_key        raw key material
 * @param[in] raw_key_length length of raw_key in bytes
 * @param[in] algorithm      null-terminated Java algorithm name (e.g. "AES")
 *
 * @return native_id (pointer to struct llcrypto_key cast to int32_t)
 *
 * @note Throws NativeException on error.
 */
int32_t LLCRYPTO_SECRET_KEY_IMPL_create(uint8_t *raw_key, int32_t raw_key_length, uint8_t *algorithm) {
	LLCRYPTO_SECRET_KEY_DEBUG_PRINTF("%s\n", __func__);

	int32_t return_code = SNI_ERROR;
	struct llcrypto_key *key = llcrypto_key_from_secret_key(raw_key, (size_t)raw_key_length, algorithm);
	if (key == NULL) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't create secret key");
	} else {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t)key;
	}

	return return_code;
}

/**
 * @brief Return the id of the native close function for secret keys.
 *
 * @return function pointer to llcrypto_key_free cast to int32_t
 */
int32_t LLCRYPTO_SECRET_KEY_IMPL_nativeGetCloseId(void) {
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)llcrypto_key_free;
}
