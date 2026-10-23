/*
 * C
 *
 * Copyright 2021-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <LLCRYPTO_PRIVATE_KEY_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

int32_t LLCRYPTO_PRIVATE_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");

	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int32_t return_code = SNI_ERROR;

	/* Encode as PKCS#8 PrivateKeyInfo (unencrypted) to match Java's Key.getEncoded() contract.
	 * For provider-backed keys (e.g. PKCS#11 non-extractable keys), EVP_PKEY2PKCS8 will fail
	 * because the private key material cannot be exported. Return 0 in that case (no encoded
	 * form available), which is correct security behavior.
	 *
	 * pkcs11-provider returns NULL without pushing any OpenSSL error onto the stack, so
	 * err == 0 must be treated the same as EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE.
	 * The stack is cleared first: an earlier call can leave an error that it did not report,
	 * such as the failed key cache copy of pkcs11-provider on a read-only token session. */
	ERR_clear_error();
	PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(key->evp_key);
	if (NULL == p8) {
		int err = ERR_peek_last_error();
		if ((0 == err) || (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE == ERR_GET_REASON(err))) {
			ERR_clear_error();
			return_code = 0; /* Non-extractable key — no encoded form. */
		} else {
			err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		}
	} else {
		return_code = (int32_t)i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
		PKCS8_PRIV_KEY_INFO_free(p8);

		if (return_code < 0) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		}
	}

	return return_code;
}

int32_t LLCRYPTO_PRIVATE_KEY_IMPL_get_encode(int32_t native_id, uint8_t *output, int32_t outputLength) {
	VEEPORT_LOGGER_LOG_DBG("");

	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int32_t return_code = SNI_ERROR;

	if (!sni_array_contains_range(output, 0, outputLength)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		/* See get_encoded_max_size for non-extractable key handling. */
		ERR_clear_error();
		PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(key->evp_key);
		if (NULL == p8) {
			int err = ERR_peek_last_error();
			if ((0 == err) || (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE == ERR_GET_REASON(err))) {
				ERR_clear_error();
				return_code = 0;
			} else {
				err = ERR_get_error();
				VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
				                                               ERR_error_string(err, NULL));
			}
		} else {
			/* i2d_PKCS8_PRIV_KEY_INFO writes the whole encoding and takes no capacity, so ask
			 * how long it will be and refuse before writing when the array cannot hold it. */
			int required = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
			if (required < 0) {
				int err = ERR_get_error();
				VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
				                                               ERR_error_string(err, NULL));
			} else if (required > outputLength) {
				VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
				                                               "Output buffer too small");
			} else {
				return_code = (int32_t)i2d_PKCS8_PRIV_KEY_INFO(p8, &output);
				if (return_code < 0) {
					int err = ERR_get_error();
					VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
					                                               ERR_error_string(err, NULL));
				}
			}
			PKCS8_PRIV_KEY_INFO_free(p8);
		}
	}

	return return_code;
}

int32_t LLCRYPTO_PRIVATE_KEY_IMPL_get_output_size(int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	int32_t ret = 0;

	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;

	ret = EVP_PKEY_size(key->evp_key);
	if (0 == ret) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
	}
	return ret;
}
