/*
 * C
 *
 * Copyright 2021-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include "LLCRYPTO_configuration.h"
#include <LLCRYPTO_PRIVATE_KEY_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include "LLCRYPTO_key.h"
#include <sni.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

// #define LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE

#ifdef LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE
#define LLCRYPTO_PRIVATE_KEY_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_PRIVATE_KEY_PRINTF(...) ((void)0)
#endif

int32_t LLCRYPTO_PRIVATE_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLCRYPTO_PRIVATE_KEY_PRINTF("%s \n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int32_t return_code = SNI_ERROR;

	/* Encode as PKCS#8 PrivateKeyInfo (unencrypted) to match Java's Key.getEncoded() contract.
	 * For provider-backed keys (e.g. PKCS#11 non-extractable keys), EVP_PKEY2PKCS8 will fail
	 * because the private key material cannot be exported. Return 0 in that case (no encoded
	 * form available), which is correct security behavior.
	 *
	 * pkcs11-provider returns NULL without pushing any OpenSSL error onto the stack, so
	 * err == 0 must be treated the same as EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE. */
	PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(key->evp_key);
	if (NULL == p8) {
		int err = ERR_peek_last_error();
		if ((err == 0) || (ERR_GET_REASON(err) == EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE)) {
			ERR_clear_error();
			return_code = 0; /* Non-extractable key — no encoded form. */
		} else {
			err = ERR_get_error();
			(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		}
	} else {
		return_code = (int32_t)i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
		PKCS8_PRIV_KEY_INFO_free(p8);

		if (return_code < 0) {
			int err = ERR_get_error();
			(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		}
	}

	return return_code;
}

int32_t LLCRYPTO_PRIVATE_KEY_IMPL_get_encode(int32_t native_id, uint8_t *output, int32_t outputLength) {
	LLCRYPTO_PRIVATE_KEY_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(outputLength);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int32_t return_code = SNI_ERROR;

	/* See get_encoded_max_size for non-extractable key handling. */
	PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(key->evp_key);
	if (NULL == p8) {
		int err = ERR_peek_last_error();
		if ((err == 0) || (ERR_GET_REASON(err) == EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE)) {
			ERR_clear_error();
			return_code = 0;
		} else {
			err = ERR_get_error();
			(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		}
	} else {
		return_code = (int32_t)i2d_PKCS8_PRIV_KEY_INFO(p8, &output);
		PKCS8_PRIV_KEY_INFO_free(p8);

		if (return_code < 0) {
			int err = ERR_get_error();
			(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		}
	}

	return return_code;
}

int32_t LLCRYPTO_PRIVATE_KEY_IMPL_get_output_size(int32_t native_id) {
	LLCRYPTO_PRIVATE_KEY_PRINTF("%s \n", __func__);
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
