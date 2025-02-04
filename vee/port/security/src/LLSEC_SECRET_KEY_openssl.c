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

#include <LLSEC_openssl.h>
#include "LLSEC_SECRET_KEY_impl.h"

// #define LLSEC_SECRET_KEY_DEBUG_TRACE

#ifdef LLSEC_SECRET_KEY_DEBUG_TRACE
#define LLSEC_SECRET_KEY_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLSEC_SECRET_KEY_DEBUG_PRINTF(...) ((void)0)
#endif

/**
 * @brief return the max size of the encoded key.
 *
 * @param[in] native_id the C structure pointer holding the key data
 *
 * @return max encoded size for the secret key in DER format
 *
 * @note Throws NativeException on error.
 */
int32_t LLSEC_SECRET_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLSEC_SECRET_KEY_DEBUG_PRINTF("%s (native_id = %d)\n", __func__, (int)native_id);
	int32_t max_size = 0;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_secret_key* secret_key = (LLSEC_secret_key*)native_id;
	if(NULL != secret_key) {
		max_size = secret_key->key_length;
	}

	LLSEC_SECRET_KEY_DEBUG_PRINTF("%s Return size = %d\n", __func__, (int)max_size);
	return max_size;
}

/**
 * @brief encode the secret key.
 *
 * @param[in]  native_id      the C structure pointer holding the key data
 * @param[out] output         a byte array to hold the encoded key data
 * @param[in]  output_length  the length of the output array (in bytes)
 *
 * @return the reel size of the encoded key (in bytes).
 *
 * @note Throws NativeException on error.
 */
int32_t LLSEC_SECRET_KEY_IMPL_get_encoded(int32_t native_id, uint8_t *output, int32_t output_length) {
	LLSEC_SECRET_KEY_DEBUG_PRINTF("%s (native_id = %d)\n", __func__, (int)native_id);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_secret_key* secret_key = (LLSEC_secret_key*)native_id;
	if(NULL != secret_key) {
		(void)memcpy(output, secret_key->key, output_length);
	}

	LLSEC_SECRET_KEY_DEBUG_PRINTF("%s Return size = %d\n", __func__, (int)output_length);
	return output_length;
}
