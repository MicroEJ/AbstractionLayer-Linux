/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdint.h>
#include <string.h>
#include <LLCRYPTO_SECRET_KEY_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

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
	VEEPORT_LOGGER_LOG_DBG("(native_id = %d)", (int)native_id);

	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int32_t max_size = llcrypto_key_get_encoded_max_size(key);

	VEEPORT_LOGGER_LOG_DBG("Return size = %d", (int)max_size);
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
	VEEPORT_LOGGER_LOG_DBG("(native_id = %d)", (int)native_id);

	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int32_t key_length = SNI_ERROR;

	/* llcrypto_key_get_encoded compares the key size against output_length as a size_t, so a
	 * negative length would read as an enormous capacity and let the copy through. */
	if (!sni_array_contains_range(output, 0, output_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		key_length = llcrypto_key_get_encoded(key, output, output_length);
	}

	VEEPORT_LOGGER_LOG_DBG("Return size = %d", (int)key_length);
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
	VEEPORT_LOGGER_LOG_DBG("");

	int32_t return_code = SNI_ERROR;

	/* An empty key is meaningless, and the length reaches llcrypto_key_from_secret_key as the
	 * size_t it allocates and copies with. */
	if ((raw_key_length <= 0) || !sni_array_contains_range(raw_key, 0, raw_key_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		struct llcrypto_key *key = llcrypto_key_from_secret_key(raw_key, (size_t)raw_key_length, algorithm);
		if (NULL == key) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Can't create secret key");
		} else {
			return_code = (int32_t)key;
		}
	}

	return return_code;
}

/**
 * @brief Return the id of the native close function for secret keys.
 *
 * @return function pointer to llcrypto_key_free cast to int32_t
 */
int32_t LLCRYPTO_SECRET_KEY_IMPL_nativeGetCloseId(void) {
	return (int32_t)llcrypto_key_free;
}
