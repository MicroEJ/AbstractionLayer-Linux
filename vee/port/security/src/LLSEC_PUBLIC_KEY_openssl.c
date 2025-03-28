/*
 * C
 *
 * Copyright 2021-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

#include <LLSEC_PUBLIC_KEY_impl.h>
#include <LLSEC_openssl.h>
#include <sni.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/**
 * @file
 * @brief MicroEJ Security low level API implementation for OpenSSL Library
 * @author MicroEJ Developer Team
 * @version 3.0.0
 * @date 20 August 2024
 */

// #define LLSEC_PUBLIC_KEY_DEBUG_TRACE

#ifdef LLSEC_PUBLIC_KEY_DEBUG_TRACE
#define LLSEC_PUBLIC_KEY_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLSEC_PUBLIC_KEY_PRINTF(...) ((void)0)
#endif

int32_t LLSEC_PUBLIC_KEY_IMPL_get_encoded_max_size(int32_t native_id) {

	LLSEC_PUBLIC_KEY_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_pub_key* key = (LLSEC_pub_key*) native_id;
	int length = i2d_PUBKEY(key->key, NULL);
	if (length < 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}

	return length;
}

int32_t LLSEC_PUBLIC_KEY_IMPL_get_encode(int32_t native_id, uint8_t* output, int32_t outputLength) {

	LLSEC_PUBLIC_KEY_PRINTF("%s \n", __func__);
	(void)outputLength;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_pub_key* key = (LLSEC_pub_key*) native_id;
	/*
	 * Please don't use i2d_PublicKey() method here,
	 * we need the key encoded in ASN.1 format which is returned by i2d_PUBKEY().
	 * see openssl documentation for more details
	 */
	int length = i2d_PUBKEY(key->key, &output);
	if (length < 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}

	return length;
}

int32_t LLSEC_PUBLIC_KEY_IMPL_get_output_size(int32_t native_id) {
	LLSEC_PUBLIC_KEY_PRINTF("%s \n", __func__);
	int32_t ret = 0;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_pub_key* key = (LLSEC_pub_key*) native_id;

	ret = EVP_PKEY_size(key->key);
	if (0 == ret) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}
	return ret;
}
