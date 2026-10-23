/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <LLCRYPTO_AES_KEY_WRAP_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"
#include "LLCRYPTO_utils.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

/* RFC 3394 wraps n 64-bit blocks into n+1: the extra block carries the integrity check value
 * obtained from the initial value. */
#define LLCRYPTO_AES_KEY_WRAP_ICV_SIZE (8)

typedef struct {
	char *name;
} LLCRYPTO_AES_KEY_WRAP_transformation;

static void llcrypto_openssl_aes_key_wrap_close(void *native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)native_id;
	EVP_CIPHER_CTX_free(ctx);
}

int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_get_transformation(uint8_t *transformation) {
	static const LLCRYPTO_AES_KEY_WRAP_transformation available_transformations[1] = {
		{
			.name = "AESWrap"
		}
	};

	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = LLCRYPTO_ERROR;
	size_t nb_transformations = sizeof(available_transformations) / sizeof(available_transformations[0]);
	const LLCRYPTO_AES_KEY_WRAP_transformation *t = &available_transformations[0];

	for (size_t i = 0; i < nb_transformations; i++) {
		if (0 == strcmp((const char *)transformation, t->name)) {
			return_code = (int32_t)t;
			break;
		}
		t++;
	}

	return return_code;
}

int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, int32_t secret_key_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(transformation_id);

	const struct llcrypto_key *key = (const struct llcrypto_key *)secret_key_id;
	const EVP_CIPHER *cipher_type = NULL;
	int32_t return_code = SNI_ERROR;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (NULL == ctx) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_OOM_EXCEPTION, "Can't allocate EVP_CIPHER_CTX");
		goto end;
	}

	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	switch (key->secret_key.length * 8u) {
	case LLCRYPTO_AES_128_KEY_BITS:
		cipher_type = EVP_aes_128_wrap();
		break;
	case LLCRYPTO_AES_192_KEY_BITS:
		cipher_type = EVP_aes_192_wrap();
		break;
	case LLCRYPTO_AES_256_KEY_BITS:
		cipher_type = EVP_aes_256_wrap();
		break;
	default:
	{
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_AES_KEY_WRAP_INVALID_KEY,
		                                               "Invalid AES key size for key wrap");
		goto cleanup;
	}
	}

	int rc = 0;
	if ((uint8_t)1 == is_decrypting) {
		rc = EVP_DecryptInit_ex(ctx, cipher_type, NULL, key->secret_key.buffer, NULL);
	} else {
		rc = EVP_EncryptInit_ex(ctx, cipher_type, NULL, key->secret_key.buffer, NULL);
	}

	if (1 != rc) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
		goto cleanup;
	}

	if (SNI_OK != SNI_registerResource(ctx, llcrypto_openssl_aes_key_wrap_close, NULL)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Can't register SNI native resource");
		goto cleanup;
	}

	return_code = (int32_t)ctx;
	goto end;

cleanup:
	EVP_CIPHER_CTX_free(ctx);
end:
	return return_code;
}

int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_wrap(int32_t transformation_id, int32_t native_id, int32_t key_id, uint8_t *output,
                                        int32_t output_offset, int32_t output_length, uint8_t *algorithm) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	LLCRYPTO_UNUSED_PARAM(algorithm);

	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)native_id;
	const struct llcrypto_key *key_to_wrap = (const struct llcrypto_key *)key_id;

	int32_t return_code = SNI_ERROR;
	const uint8_t *plaintext = NULL;
	int32_t plaintext_len = 0;

	if (!sni_array_contains_range(output, output_offset, output_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		goto end;
	}

	if (LLCRYPTO_KEY_TYPE_SECRET_KEY != key_to_wrap->type) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_AES_KEY_WRAP_INVALID_KEY,
		                                               "AES Key Wrap only supports secret keys");
		goto end;
	}

	plaintext = key_to_wrap->secret_key.buffer;
	plaintext_len = (int32_t)key_to_wrap->secret_key.length;

	/* The wrap writes plaintext_len + LLCRYPTO_AES_KEY_WRAP_ICV_SIZE bytes whatever the caller
	 * declared, so bound the array against that before EVP_EncryptUpdate writes into it. */
	if (!sni_array_contains_range(output, output_offset, plaintext_len + LLCRYPTO_AES_KEY_WRAP_ICV_SIZE)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Output buffer too small for the wrapped key");
		goto end;
	}

	int outl = 0;
	if (1 != EVP_EncryptUpdate(ctx, &output[output_offset], &outl, plaintext, plaintext_len)) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
		goto end;
	}

	int finl = 0;
	if (1 != EVP_EncryptFinal_ex(ctx, &output[output_offset + outl], &finl)) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
		goto end;
	}

	return_code = (int32_t)(outl + finl);

end:
	return return_code;
}

int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_unwrap(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                          int32_t buffer_offset, int32_t buffer_length, uint8_t *algorithm) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(transformation_id);

	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)native_id;
	int32_t return_code = SNI_ERROR;

	if (!sni_array_contains_range(buffer, buffer_offset, buffer_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		goto end;
	}

	/* Allocate temporary buffer for unwrapped key material */
	uint8_t *unwrapped = LLCRYPTO_calloc(1, (size_t)buffer_length);
	if (NULL == unwrapped) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_OOM_EXCEPTION, "Out of memory");
		goto end;
	}

	int outl = 0;
	if (1 != EVP_DecryptUpdate(ctx, unwrapped, &outl, &buffer[buffer_offset], buffer_length)) {
		/* Constant message: the RFC 3394 integrity check must not report why. */
		VEEPORT_LOGGER_LOG_ERR("failed: %s", ERR_error_string(ERR_get_error(), NULL));
		ERR_clear_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_AES_KEY_WRAP_INTEGRITY_CHECK_FAILED,
		                                               "key unwrap failed");
		goto cleanup;
	}

	int finl = 0;
	if (1 != EVP_DecryptFinal_ex(ctx, &unwrapped[outl], &finl)) {
		VEEPORT_LOGGER_LOG_ERR("failed: %s", ERR_error_string(ERR_get_error(), NULL));
		ERR_clear_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_AES_KEY_WRAP_INTEGRITY_CHECK_FAILED,
		                                               "key unwrap failed");
		goto cleanup;
	}

	{
		int32_t key_len = outl + finl;
		struct llcrypto_key *key = llcrypto_key_from_secret_key(unwrapped, (size_t)key_len, algorithm);
		if (NULL == key) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_OOM_EXCEPTION, "Can't create unwrapped secret key");
		} else {
			return_code = (int32_t)key;
		}
	}

cleanup:
	/* Holds the plaintext key: llcrypto_key_from_secret_key copied it out. */
	OPENSSL_cleanse(unwrapped, (size_t)buffer_length);
	LLCRYPTO_free(unwrapped);
end:
	return return_code;
}

void LLCRYPTO_AES_KEY_WRAP_IMPL_close(int32_t transformation_id, int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	llcrypto_unregister_and_close((EVP_CIPHER_CTX *)native_id, llcrypto_openssl_aes_key_wrap_close);
}

int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_get_close_id(int32_t transformation_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	return sni_close_id(llcrypto_openssl_aes_key_wrap_close);
}
