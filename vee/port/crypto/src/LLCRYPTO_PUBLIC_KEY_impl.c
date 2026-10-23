/*
 * C
 *
 * Copyright 2021-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <openssl/err.h>
#include <openssl/x509.h>
#include <LLCRYPTO_PUBLIC_KEY_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

int32_t LLCRYPTO_PUBLIC_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");

	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int length = i2d_PUBKEY(key->evp_key, NULL);
	if (length < 0) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
	}

	return length;
}

int32_t LLCRYPTO_PUBLIC_KEY_IMPL_get_encode(int32_t native_id, uint8_t *output, int32_t outputLength) {
	VEEPORT_LOGGER_LOG_DBG("");

	const struct llcrypto_key *key = (const struct llcrypto_key *)native_id;
	int32_t return_code = SNI_ERROR;

	if (!sni_array_contains_range(output, 0, outputLength)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		/*
		 * Please don't use i2d_PublicKey() method here,
		 * we need the key encoded in ASN.1 format which is returned by i2d_PUBKEY().
		 * see openssl documentation for more details
		 */
		/* i2d_PUBKEY writes the whole encoding and takes no capacity, so ask how long it
		 * will be and refuse before writing when the array cannot hold it. */
		int required = i2d_PUBKEY(key->evp_key, NULL);
		if (required < 0) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		} else if (required > outputLength) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Output buffer too small");
		} else {
			int length = i2d_PUBKEY(key->evp_key, &output);
			if (length < 0) {
				int err = ERR_get_error();
				VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
				                                               ERR_error_string(err, NULL));
			} else {
				return_code = length;
			}
		}
	}

	return return_code;
}

int32_t LLCRYPTO_PUBLIC_KEY_IMPL_get_output_size(int32_t native_id) {
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
