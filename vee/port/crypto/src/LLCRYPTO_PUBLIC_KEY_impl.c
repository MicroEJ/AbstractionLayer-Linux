/*
 * C
 *
 * Copyright 2021-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include "LLCRYPTO_configuration.h"
#include <LLCRYPTO_PUBLIC_KEY_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include "LLCRYPTO_key.h"
#include <sni.h>
#include <openssl/x509.h>
#include <openssl/err.h>

// #define LLCRYPTO_PUBLIC_KEY_DEBUG_TRACE

#ifdef LLCRYPTO_PUBLIC_KEY_DEBUG_TRACE
#define LLCRYPTO_PUBLIC_KEY_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_PUBLIC_KEY_PRINTF(...) ((void)0)
#endif

int32_t LLCRYPTO_PUBLIC_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLCRYPTO_PUBLIC_KEY_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int length = i2d_PUBKEY(key->evp_key, NULL);
	if (length < 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}

	return length;
}

int32_t LLCRYPTO_PUBLIC_KEY_IMPL_get_encode(int32_t native_id, uint8_t *output, int32_t outputLength) {
	LLCRYPTO_PUBLIC_KEY_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(outputLength);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	/*
	 * Please don't use i2d_PublicKey() method here,
	 * we need the key encoded in ASN.1 format which is returned by i2d_PUBKEY().
	 * see openssl documentation for more details
	 */
	int length = i2d_PUBKEY(key->evp_key, &output);
	if (length < 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}

	return length;
}

int32_t LLCRYPTO_PUBLIC_KEY_IMPL_get_output_size(int32_t native_id) {
	LLCRYPTO_PUBLIC_KEY_PRINTF("%s \n", __func__);
	int32_t ret = 0;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;

	ret = EVP_PKEY_size(key->evp_key);
	if (0 == ret) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
	return ret;
}
