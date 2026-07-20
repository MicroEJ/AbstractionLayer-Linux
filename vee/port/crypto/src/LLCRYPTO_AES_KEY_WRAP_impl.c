/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"
#include <LLCRYPTO_AES_KEY_WRAP_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>
#include <sni.h>
#include <stdint.h>

// #define LLCRYPTO_AES_KEY_WRAP_DEBUG_TRACE

#ifdef LLCRYPTO_AES_KEY_WRAP_DEBUG_TRACE
#define LLCRYPTO_AES_KEY_WRAP_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_AES_KEY_WRAP_DEBUG_PRINTF(...) ((void)0)
#endif

typedef struct {
	char *name;
} LLCRYPTO_AES_KEY_WRAP_transformation;

static void LLCRYPTO_AES_KEY_WRAP_openssl_close(void *native_id);

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file.
static LLCRYPTO_AES_KEY_WRAP_transformation available_transformations[1] = {
	{
		.name = "AESWrap"
	}
};

static void LLCRYPTO_AES_KEY_WRAP_openssl_close(void *native_id) {
	LLCRYPTO_AES_KEY_WRAP_DEBUG_PRINTF("%s\n", __func__);
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)native_id;
	EVP_CIPHER_CTX_free(ctx);
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_get_transformation(uint8_t *transformation) {
	LLCRYPTO_AES_KEY_WRAP_DEBUG_PRINTF("%s\n", __func__);
	int32_t return_code = LLCRYPTO_ERROR;
	int32_t nb_transformations = (int32_t)(sizeof(available_transformations) /
	                                       sizeof(LLCRYPTO_AES_KEY_WRAP_transformation));
	LLCRYPTO_AES_KEY_WRAP_transformation *t = &available_transformations[0];

	while (--nb_transformations >= 0) {
		if (0 == strcmp((const char *)transformation, t->name)) {
			// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
			return_code = (int32_t)t;
			break;
		}
		t++;
	}

	return return_code;
}

int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, int32_t secret_key_id) {
	LLCRYPTO_AES_KEY_WRAP_DEBUG_PRINTF("%s\n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key = (const struct llcrypto_key *)secret_key_id;
	const EVP_CIPHER *cipher_type = NULL;
	int32_t return_code = SNI_ERROR;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (NULL == ctx) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't allocate EVP_CIPHER_CTX");
		goto end;
	}

	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	switch (key->secret_key.length * 8u) {
	case 128u:
		cipher_type = EVP_aes_128_wrap();
		break;
	case 192u:
		cipher_type = EVP_aes_192_wrap();
		break;
	case 256u:
		cipher_type = EVP_aes_256_wrap();
		break;
	default:
		(void)SNI_throwNativeException(SNI_ERROR, "Invalid AES key size for key wrap");
		goto cleanup;
	}

	int rc;
	if ((uint8_t)1 == is_decrypting) {
		rc = EVP_DecryptInit_ex(ctx, cipher_type, NULL, key->secret_key.buffer, NULL);
	} else {
		rc = EVP_EncryptInit_ex(ctx, cipher_type, NULL, key->secret_key.buffer, NULL);
	}

	if (1 != rc) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto cleanup;
	}

	if (SNI_registerResource((void *)ctx, LLCRYPTO_AES_KEY_WRAP_openssl_close, NULL) != SNI_OK) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't register SNI native resource");
		goto cleanup;
	}

	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	return_code = (int32_t)ctx;
	goto end;

cleanup:
	EVP_CIPHER_CTX_free(ctx);
end:
	return return_code;
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_wrap(int32_t transformation_id, int32_t native_id, int32_t key_id, uint8_t *output,
                                        int32_t output_offset, int32_t output_length, uint8_t *algorithm) {
	LLCRYPTO_AES_KEY_WRAP_DEBUG_PRINTF("%s\n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	LLCRYPTO_UNUSED_PARAM(output_length);
	LLCRYPTO_UNUSED_PARAM(algorithm);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)native_id;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key_to_wrap = (const struct llcrypto_key *)key_id;

	int32_t return_code = SNI_ERROR;
	const uint8_t *plaintext = NULL;
	int32_t plaintext_len = 0;

	if (key_to_wrap->type != LLCRYPTO_KEY_TYPE_SECRET_KEY) {
		(void)SNI_throwNativeException(SNI_ERROR, "AES Key Wrap only supports secret keys");
		goto end;
	}

	plaintext = key_to_wrap->secret_key.buffer;
	plaintext_len = (int32_t)key_to_wrap->secret_key.length;

	int outl = 0;
	if (EVP_EncryptUpdate(ctx, &output[output_offset], &outl, plaintext, plaintext_len) != 1) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto end;
	}

	int finl = 0;
	if (EVP_EncryptFinal_ex(ctx, &output[output_offset + outl], &finl) != 1) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto end;
	}

	return_code = (int32_t)(outl + finl);

end:
	return return_code;
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_unwrap(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                          int32_t buffer_offset, int32_t buffer_length, uint8_t *algorithm) {
	LLCRYPTO_AES_KEY_WRAP_DEBUG_PRINTF("%s\n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)native_id;
	int32_t return_code = SNI_ERROR;

	/* Allocate temporary buffer for unwrapped key material */
	uint8_t *unwrapped = LLCRYPTO_calloc(1, (size_t)buffer_length);
	if (NULL == unwrapped) {
		(void)SNI_throwNativeException(SNI_ERROR, "Out of memory");
		goto end;
	}

	int outl = 0;
	if (EVP_DecryptUpdate(ctx, unwrapped, &outl, &buffer[buffer_offset], buffer_length) != 1) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto cleanup;
	}

	int finl = 0;
	if (EVP_DecryptFinal_ex(ctx, &unwrapped[outl], &finl) != 1) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto cleanup;
	}

	{
		int32_t key_len = outl + finl;
		struct llcrypto_key *key = llcrypto_key_from_secret_key(unwrapped, (size_t)key_len, algorithm);
		if (NULL == key) {
			(void)SNI_throwNativeException(SNI_ERROR, "Can't create unwrapped secret key");
		} else {
			// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
			return_code = (int32_t)key;
		}
	}

cleanup:
	LLCRYPTO_free(unwrapped);
end:
	return return_code;
}

void LLCRYPTO_AES_KEY_WRAP_IMPL_close(int32_t transformation_id, int32_t native_id) {
	LLCRYPTO_AES_KEY_WRAP_DEBUG_PRINTF("%s\n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	LLCRYPTO_AES_KEY_WRAP_openssl_close((void *)native_id);
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	if (SNI_unregisterResource((void *)native_id, (SNI_closeFunction)LLCRYPTO_AES_KEY_WRAP_openssl_close) != SNI_OK) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource");
	}
}

int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_get_close_id(int32_t transformation_id) {
	LLCRYPTO_AES_KEY_WRAP_DEBUG_PRINTF("%s\n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)LLCRYPTO_AES_KEY_WRAP_openssl_close;
}
