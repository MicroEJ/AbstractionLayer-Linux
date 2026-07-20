/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"
#include <LLCRYPTO_CIPHER_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>
#include <sni.h>
#include <stdint.h>

#define MICROEJ_LLCRYPTO_CIPHER_SUCCESS 1
#define MICROEJ_LLCRYPTO_CIPHER_ERROR   0

#define AES_CBC_BLOCK_BITS    (128u)
#define AES_CBC_BLOCK_BYTES   (AES_CBC_BLOCK_BITS / 8u)

#define AES_ECB_BLOCK_BITS    (128u)
#define AES_ECB_BLOCK_BYTES   (AES_ECB_BLOCK_BITS / 8u)

#define AES_CTR_BLOCK_BITS    (128u)
#define AES_CTR_BLOCK_BYTES   (AES_CTR_BLOCK_BITS / 8u)
#define AES_CTR_UNIT_BYTES    (1u) // CTR is a stream cipher mode, byte-granular

#define DES_CBC_BLOCK_BITS    (64u)
#define DES_CBC_BLOCK_BYTES   (DES_CBC_BLOCK_BITS / 8u)

#define AES_GCM_BLOCK_BITS    (128u)
#define AES_GCM_BLOCK_BYTES   (AES_GCM_BLOCK_BITS / 8u)
#define AES_GCM_UNIT_BYTES    (1u) // GCM/CCM is byte-granular

#define AES_GCM_DEFAULT_TAG_BYTES (16u)

// #define LLCRYPTO_CIPHER_DEBUG_TRACE

#ifdef LLCRYPTO_CIPHER_DEBUG_TRACE
#define LLCRYPTO_CIPHER_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_CIPHER_DEBUG_PRINTF(...) ((void)0)
#endif

/**
 * Unified cipher context used by all transformations.
 * For non-AEAD modes tag_length is 0. buffered_length tracks the number of
 * input bytes given to update calls but not yet returned (OpenSSL keeps
 * partial blocks internally until enough data is supplied).
 */
typedef struct {
	EVP_CIPHER_CTX *ctx;
	int32_t tag_length;
	int32_t buffered_length;
	uint8_t is_decrypting;
} LLCRYPTO_CIPHER_ctx;

/**
 * Cipher init function type
 */
typedef int (*LLCRYPTO_CIPHER_init)(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                    const uint8_t *iv, int32_t iv_length);

typedef int (*LLCRYPTO_CIPHER_decrypt)(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer, int32_t buffer_length,
                                       uint8_t *output, int32_t *output_length, uint8_t do_final);
typedef int (*LLCRYPTO_CIPHER_encrypt)(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer, int32_t buffer_length,
                                       uint8_t *output, int32_t *output_length, uint8_t do_final);
typedef void (*LLCRYPTO_CIPHER_close)(void *native_id);

typedef struct {
	char *name; // the name of the transformation
	LLCRYPTO_CIPHER_init init;
	LLCRYPTO_CIPHER_decrypt decrypt;
	LLCRYPTO_CIPHER_encrypt encrypt;
	LLCRYPTO_CIPHER_close close;
	LLCRYPTO_CIPHER_transformation_desc description;
} LLCRYPTO_CIPHER_transformation;

static int LLCRYPTO_CIPHER_aescbc_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                       const uint8_t *iv, int32_t iv_length);
static int LLCRYPTO_CIPHER_aesecb_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                       const uint8_t *iv, int32_t iv_length);
static int LLCRYPTO_CIPHER_aesctr_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                       const uint8_t *iv, int32_t iv_length);
static int LLCRYPTO_CIPHER_des3cbc_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                        const uint8_t *iv, int32_t iv_length);
static int LLCRYPTO_CIPHER_aesgcm_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                       const uint8_t *iv, int32_t iv_length);
static int openssl_cipher_decrypt(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer, int32_t buffer_length,
                                  uint8_t *output, int32_t *output_length, uint8_t do_final);
static int openssl_cipher_encrypt(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer, int32_t buffer_length,
                                  uint8_t *output, int32_t *output_length, uint8_t do_final);
static void openssl_cipher_close(void *native_id);

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file.
static LLCRYPTO_CIPHER_transformation available_transformations[5] =
{
	{
		.name = "AES/CBC/NoPadding",
		.init = LLCRYPTO_CIPHER_aescbc_init,
		.decrypt = openssl_cipher_decrypt,
		.encrypt = openssl_cipher_encrypt,
		.close = openssl_cipher_close,
		{
			.block_size = AES_CBC_BLOCK_BYTES,
			.unit_bytes = AES_CBC_BLOCK_BYTES,
			.cipher_mode = CBC_MODE,
		}
	},
	{
		.name = "AES/ECB/NoPadding",
		.init = LLCRYPTO_CIPHER_aesecb_init,
		.decrypt = openssl_cipher_decrypt,
		.encrypt = openssl_cipher_encrypt,
		.close = openssl_cipher_close,
		{
			.block_size = AES_ECB_BLOCK_BYTES,
			.unit_bytes = AES_ECB_BLOCK_BYTES,
			.cipher_mode = ECB_MODE,
		}
	},
	{
		.name = "AES/CTR/NoPadding",
		.init = LLCRYPTO_CIPHER_aesctr_init,
		.decrypt = openssl_cipher_decrypt,
		.encrypt = openssl_cipher_encrypt,
		.close = openssl_cipher_close,
		{
			.block_size = AES_CTR_BLOCK_BYTES,
			.unit_bytes = AES_CTR_UNIT_BYTES,
			.cipher_mode = CTR_MODE,
		}
	},
	{
		.name = "DESede/CBC/NoPadding",
		.init = LLCRYPTO_CIPHER_des3cbc_init,
		.decrypt = openssl_cipher_decrypt,
		.encrypt = openssl_cipher_encrypt,
		.close = openssl_cipher_close,
		{
			.block_size = DES_CBC_BLOCK_BYTES,
			.unit_bytes = DES_CBC_BLOCK_BYTES,
			.cipher_mode = CBC_MODE,
		}
	},
	{
		.name = "AES/GCM/NoPadding",
		.init = LLCRYPTO_CIPHER_aesgcm_init,
		.decrypt = openssl_cipher_decrypt,
		.encrypt = openssl_cipher_encrypt,
		.close = openssl_cipher_close,
		{
			.block_size = AES_GCM_BLOCK_BYTES,
			.unit_bytes = AES_GCM_UNIT_BYTES,
			.cipher_mode = GCM_MODE,
		}
	}
};

/**
 * Allocate a LLCRYPTO_CIPHER_ctx wrapping a new EVP_CIPHER_CTX.
 * On success *out is set and MICROEJ_LLCRYPTO_CIPHER_SUCCESS is returned.
 */
static int llcrypto_cipher_ctx_new(LLCRYPTO_CIPHER_ctx **out, uint8_t is_decrypting, int32_t tag_length) {
	int return_code = MICROEJ_LLCRYPTO_CIPHER_ERROR;
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)LLCRYPTO_calloc(1, sizeof(LLCRYPTO_CIPHER_ctx));

	if (NULL != cipher_ctx) {
		cipher_ctx->ctx = EVP_CIPHER_CTX_new();
		if (NULL == cipher_ctx->ctx) {
			LLCRYPTO_free(cipher_ctx);
		} else {
			cipher_ctx->is_decrypting = is_decrypting;
			cipher_ctx->tag_length = tag_length;
			*out = cipher_ctx;
			return_code = MICROEJ_LLCRYPTO_CIPHER_SUCCESS;
		}
	}

	return return_code;
}

static int LLCRYPTO_CIPHER_aescbc_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                       const uint8_t *iv, int32_t iv_length) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(iv_length);
	LLCRYPTO_CIPHER_ctx *cipher_ctx = NULL;
	int return_code = llcrypto_cipher_ctx_new(&cipher_ctx, is_decrypting, 0);

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		const EVP_CIPHER *cipher_type;
		// Key can only be 128, 192, 256
		switch (key->secret_key.length * 8u) {
		case 128u:
			cipher_type = EVP_aes_128_cbc();
			break;
		case 192u:
			cipher_type = EVP_aes_192_cbc();
			break;
		case 256u:
			cipher_type = EVP_aes_256_cbc();
			break;
		default:
			return_code = MICROEJ_LLCRYPTO_CIPHER_ERROR;
			break;
		}

		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
			if ((uint8_t)1 == is_decrypting) {
				return_code = EVP_DecryptInit_ex(cipher_ctx->ctx, cipher_type, NULL, key->secret_key.buffer, iv);
			} else {
				return_code = EVP_EncryptInit_ex(cipher_ctx->ctx, cipher_type, NULL, key->secret_key.buffer, iv);
			}
		}

		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
			//EVP_CIPHER_CTX_set_padding always returns 1
			(void)EVP_CIPHER_CTX_set_padding(cipher_ctx->ctx, 0);
		}
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		*native_id = (void *)cipher_ctx;
	} else if (cipher_ctx != NULL) {
		EVP_CIPHER_CTX_free(cipher_ctx->ctx);
		LLCRYPTO_free(cipher_ctx);
	}

	return return_code;
}

static int LLCRYPTO_CIPHER_aesecb_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                       const uint8_t *iv, int32_t iv_length) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(iv);
	LLCRYPTO_UNUSED_PARAM(iv_length);
	LLCRYPTO_CIPHER_ctx *cipher_ctx = NULL;
	int return_code = llcrypto_cipher_ctx_new(&cipher_ctx, is_decrypting, 0);

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		const EVP_CIPHER *cipher_type;
		// Key can only be 128, 192, 256
		switch (key->secret_key.length * 8u) {
		case 128u:
			cipher_type = EVP_aes_128_ecb();
			break;
		case 192u:
			cipher_type = EVP_aes_192_ecb();
			break;
		case 256u:
			cipher_type = EVP_aes_256_ecb();
			break;
		default:
			return_code = MICROEJ_LLCRYPTO_CIPHER_ERROR;
			break;
		}

		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
			if ((uint8_t)1 == is_decrypting) {
				return_code = EVP_DecryptInit_ex(cipher_ctx->ctx, cipher_type, NULL, key->secret_key.buffer, NULL);
			} else {
				return_code = EVP_EncryptInit_ex(cipher_ctx->ctx, cipher_type, NULL, key->secret_key.buffer, NULL);
			}
		}

		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
			//EVP_CIPHER_CTX_set_padding always returns 1
			(void)EVP_CIPHER_CTX_set_padding(cipher_ctx->ctx, 0);
		}
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		*native_id = (void *)cipher_ctx;
	} else if (cipher_ctx != NULL) {
		EVP_CIPHER_CTX_free(cipher_ctx->ctx);
		LLCRYPTO_free(cipher_ctx);
	}

	return return_code;
}

static int LLCRYPTO_CIPHER_aesctr_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                       const uint8_t *iv, int32_t iv_length) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(iv_length);
	LLCRYPTO_CIPHER_ctx *cipher_ctx = NULL;
	int return_code = llcrypto_cipher_ctx_new(&cipher_ctx, is_decrypting, 0);

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		const EVP_CIPHER *cipher_type;
		switch (key->secret_key.length * 8u) {
		case 128u:
			cipher_type = EVP_aes_128_ctr();
			break;
		case 192u:
			cipher_type = EVP_aes_192_ctr();
			break;
		case 256u:
			cipher_type = EVP_aes_256_ctr();
			break;
		default:
			return_code = MICROEJ_LLCRYPTO_CIPHER_ERROR;
			break;
		}

		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
			if ((uint8_t)1 == is_decrypting) {
				return_code = EVP_DecryptInit_ex(cipher_ctx->ctx, cipher_type, NULL, key->secret_key.buffer, iv);
			} else {
				return_code = EVP_EncryptInit_ex(cipher_ctx->ctx, cipher_type, NULL, key->secret_key.buffer, iv);
			}
		}

		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
			(void)EVP_CIPHER_CTX_set_padding(cipher_ctx->ctx, 0);
		}
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		*native_id = (void *)cipher_ctx;
	} else if (cipher_ctx != NULL) {
		EVP_CIPHER_CTX_free(cipher_ctx->ctx);
		LLCRYPTO_free(cipher_ctx);
	}

	return return_code;
}

static int LLCRYPTO_CIPHER_des3cbc_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                        const uint8_t *iv, int32_t iv_length) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(iv_length);
	LLCRYPTO_CIPHER_ctx *cipher_ctx = NULL;
	int return_code = llcrypto_cipher_ctx_new(&cipher_ctx, is_decrypting, 0);

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		if ((uint8_t)1 == is_decrypting) {
			return_code = EVP_DecryptInit_ex(cipher_ctx->ctx, EVP_des_ede3_cbc(), NULL, key->secret_key.buffer, iv);
		} else {
			return_code = EVP_EncryptInit_ex(cipher_ctx->ctx, EVP_des_ede3_cbc(), NULL, key->secret_key.buffer, iv);
		}
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		//EVP_CIPHER_CTX_set_padding always returns 1
		(void)EVP_CIPHER_CTX_set_padding(cipher_ctx->ctx, 0);
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		*native_id = (void *)cipher_ctx;
	} else if (cipher_ctx != NULL) {
		EVP_CIPHER_CTX_free(cipher_ctx->ctx);
		LLCRYPTO_free(cipher_ctx);
	}

	return return_code;
}

static int LLCRYPTO_CIPHER_aesgcm_init(void **native_id, uint8_t is_decrypting, const struct llcrypto_key *key,
                                       const uint8_t *iv, int32_t iv_length) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_CIPHER_ctx *cipher_ctx = NULL;
	int return_code = llcrypto_cipher_ctx_new(&cipher_ctx, is_decrypting, AES_GCM_DEFAULT_TAG_BYTES);

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		const EVP_CIPHER *cipher_type;
		switch (key->secret_key.length * 8u) {
		case 128u:
			cipher_type = EVP_aes_128_gcm();
			break;
		case 192u:
			cipher_type = EVP_aes_192_gcm();
			break;
		case 256u:
			cipher_type = EVP_aes_256_gcm();
			break;
		default:
			return_code = MICROEJ_LLCRYPTO_CIPHER_ERROR;
			break;
		}

		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
			/* Initialize cipher without key/IV first */
			if ((uint8_t)1 == is_decrypting) {
				return_code = EVP_DecryptInit_ex(cipher_ctx->ctx, cipher_type, NULL, NULL, NULL);
			} else {
				return_code = EVP_EncryptInit_ex(cipher_ctx->ctx, cipher_type, NULL, NULL, NULL);
			}
		}

		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
			/* Set IV length if non-default */
			return_code = EVP_CIPHER_CTX_ctrl(cipher_ctx->ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length, NULL);
		}

		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
			/* Now set key and IV */
			if ((uint8_t)1 == is_decrypting) {
				return_code = EVP_DecryptInit_ex(cipher_ctx->ctx, NULL, NULL, key->secret_key.buffer, iv);
			} else {
				return_code = EVP_EncryptInit_ex(cipher_ctx->ctx, NULL, NULL, key->secret_key.buffer, iv);
			}
		}
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		*native_id = (void *)cipher_ctx;
	} else if (cipher_ctx != NULL) {
		EVP_CIPHER_CTX_free(cipher_ctx->ctx);
		LLCRYPTO_free(cipher_ctx);
	}

	return return_code;
}

static int openssl_cipher_encrypt(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer, int32_t buffer_length,
                                  uint8_t *output, int32_t *output_length, uint8_t do_final) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	EVP_CIPHER_CTX *ctx = cipher_ctx->ctx;
	int len = 0;
	int total = 0;

	int return_code = EVP_EncryptUpdate(ctx, output, &len, buffer, buffer_length);
	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
		return return_code;
	}
	total = len;
	cipher_ctx->buffered_length += buffer_length - len;

	if ((uint8_t)1 == do_final) {
		int final_len = 0;
		return_code = EVP_EncryptFinal_ex(ctx, &output[total], &final_len);
		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
			return return_code;
		}
		total += final_len;
		cipher_ctx->buffered_length = 0;

		if (cipher_ctx->tag_length > 0) {
			/* Append the GCM authentication tag after the ciphertext */
			return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, cipher_ctx->tag_length, &output[total]);
			if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
				return return_code;
			}
			total += cipher_ctx->tag_length;
		}
	}

	*output_length = total;
	return return_code;
}

static int openssl_cipher_decrypt(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer, int32_t buffer_length,
                                  uint8_t *output, int32_t *output_length, uint8_t do_final) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	EVP_CIPHER_CTX *ctx = cipher_ctx->ctx;
	int return_code = MICROEJ_LLCRYPTO_CIPHER_SUCCESS;
	int total = 0;
	int32_t ciphertext_length = buffer_length;

	/* For GCM decrypt, the trailing tag_length bytes of the final input are the
	 * authentication tag. Update calls (do_final == 0) treat the entire buffer
	 * as ciphertext. */
	if (((uint8_t)1 == do_final) && (cipher_ctx->tag_length > 0)) {
		ciphertext_length = buffer_length - cipher_ctx->tag_length;
		// cppcheck-suppress misra-c2012-11.8 // EVP_CIPHER_CTX_ctrl takes void* not const void*
		return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, cipher_ctx->tag_length,
		                                  (void *)&buffer[ciphertext_length]);
		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
			return return_code;
		}
	}

	int len = 0;
	return_code = EVP_DecryptUpdate(ctx, output, &len, buffer, ciphertext_length);
	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
		return return_code;
	}
	total = len;
	cipher_ctx->buffered_length += ciphertext_length - len;

	if ((uint8_t)1 == do_final) {
		int final_len = 0;
		return_code = EVP_DecryptFinal_ex(ctx, &output[total], &final_len);
		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
			return return_code;
		}
		total += final_len;
		cipher_ctx->buffered_length = 0;
	}

	*output_length = total;
	return return_code;
}

static void openssl_cipher_close(void *native_id) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
	EVP_CIPHER_CTX_free(cipher_ctx->ctx);
	LLCRYPTO_free(cipher_ctx);
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_CIPHER_IMPL_get_transformation_description(uint8_t *transformation_name,
                                                            LLCRYPTO_CIPHER_transformation_desc *transformation_desc) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_transformations = sizeof(available_transformations) / sizeof(LLCRYPTO_CIPHER_transformation);
	LLCRYPTO_CIPHER_transformation *transformation = &available_transformations[0];

	while (--nb_transformations >= 0) {
		if (0 == strcmp((char *)transformation_name, transformation->name)) {
			(void)memcpy(transformation_desc, &(transformation->description),
			             sizeof(LLCRYPTO_CIPHER_transformation_desc));
			break;
		}
		transformation++;
	}

	if (nb_transformations >= 0) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t)transformation;
	}
	return return_code;
}

int32_t LLCRYPTO_CIPHER_IMPL_get_buffered_length(int32_t nativeTransformationId, int32_t nativeId) {
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLCRYPTO_CIPHER_ctx *cipher_ctx = (const LLCRYPTO_CIPHER_ctx *)nativeId;
	LLCRYPTO_UNUSED_PARAM(nativeTransformationId);
	int32_t return_code = cipher_ctx->buffered_length;
	/* For GCM encryption, the tag is appended to the output at doFinal */
	if ((cipher_ctx->tag_length > 0) && ((uint8_t)0 == cipher_ctx->is_decrypting)) {
		return_code += cipher_ctx->tag_length;
	}
	return return_code;
}

/**
 *  Warning: iv must not be used outside of the VM task or saved
 */
void LLCRYPTO_CIPHER_IMPL_get_IV(int32_t transformation_id, int32_t native_id, uint8_t *iv, int32_t iv_length) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLCRYPTO_CIPHER_ctx *cipher_ctx = (const LLCRYPTO_CIPHER_ctx *)native_id;
	EVP_CIPHER_CTX *ctx = cipher_ctx->ctx;
	(void)EVP_CIPHER_CTX_get_updated_iv(ctx, iv, iv_length);
}

// cppcheck-suppress constParameterPointer // SNI type conflict
void LLCRYPTO_CIPHER_IMPL_set_IV(int32_t transformation_id, int32_t native_id, uint8_t *iv, int32_t iv_length) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	LLCRYPTO_UNUSED_PARAM(iv_length);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLCRYPTO_CIPHER_ctx *cipher_ctx = (const LLCRYPTO_CIPHER_ctx *)native_id;
	(void)EVP_EncryptInit_ex(cipher_ctx->ctx, NULL, NULL, NULL, iv);
}

int32_t LLCRYPTO_CIPHER_IMPL_get_IV_length(int32_t transformation_id, int32_t native_id) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLCRYPTO_CIPHER_ctx *cipher_ctx = (const LLCRYPTO_CIPHER_ctx *)native_id;
	int32_t return_code = EVP_CIPHER_CTX_iv_length(cipher_ctx->ctx);
	if (0 == return_code) {
		return_code = SNI_ERROR;
	}
	return return_code;
}

int32_t LLCRYPTO_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, int32_t secret_key_id,
                                  uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);

	void *native_id = NULL;
	int32_t return_code = MICROEJ_LLCRYPTO_CIPHER_SUCCESS;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *key = (const struct llcrypto_key *)secret_key_id;

	return_code = transformation->init((void **)&native_id, is_decrypting, key, iv, iv_length);
	if (MICROEJ_LLCRYPTO_CIPHER_ERROR == return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}

	/* For GCM mode, override the tag length if the caller specified one */
	if ((MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) && (tag_length > 0)) {
		// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
		LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
		cipher_ctx->tag_length = tag_length;
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		if (SNI_registerResource(native_id, transformation->close, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			transformation->close((void *)native_id);
			return_code = MICROEJ_LLCRYPTO_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		return_code = (int32_t)(native_id);
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

void LLCRYPTO_CIPHER_IMPL_update_AAD(int32_t transformation_id, int32_t native_id, uint8_t *aad_buffer,
                                     int32_t aad_buffer_offset, int32_t aad_buffer_length) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	if (cipher_ctx->tag_length > 0) {
		int len = 0;
		int rc;
		if ((uint8_t)1 == cipher_ctx->is_decrypting) {
			rc = EVP_DecryptUpdate(cipher_ctx->ctx, NULL, &len, &aad_buffer[aad_buffer_offset], aad_buffer_length);
		} else {
			rc = EVP_EncryptUpdate(cipher_ctx->ctx, NULL, &len, &aad_buffer[aad_buffer_offset], aad_buffer_length);
		}
		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != rc) {
			int err = ERR_get_error();
			(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		}
	} else {
		LLCRYPTO_UNUSED_PARAM(aad_buffer);
		LLCRYPTO_UNUSED_PARAM(aad_buffer_offset);
		LLCRYPTO_UNUSED_PARAM(aad_buffer_length);
		(void)SNI_throwNativeException(LLCRYPTO_ERROR, "AAD not supported for this cipher mode");
	}
}

int32_t LLCRYPTO_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                     int32_t buffer_offset,
                                     int32_t buffer_length, uint8_t *output, int32_t output_offset, uint8_t do_final) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	int32_t output_length = 0;
	int32_t return_code;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	return_code = transformation->decrypt(cipher_ctx, &buffer[buffer_offset], buffer_length,
	                                      &output[output_offset], &output_length, do_final);
	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
		if (((uint8_t)1 == do_final) && (cipher_ctx->tag_length > 0)) {
			/* GCM authentication tag verification failed */
			return_code = LLCRYPTO_ERROR_AEAD_AUTH;
		} else {
			int err = ERR_get_error();
			(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
			return_code = SNI_ERROR;
		}
	} else {
		return_code = output_length;
	}
	return return_code;
}

int32_t LLCRYPTO_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                     int32_t buffer_offset,
                                     int32_t buffer_length, uint8_t *output, int32_t output_offset, uint8_t do_final) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	int32_t output_length = 0;
	int32_t return_code;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	return_code = transformation->encrypt(cipher_ctx, &buffer[buffer_offset], buffer_length,
	                                      &output[output_offset], &output_length, do_final);
	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return_code = SNI_ERROR;
	} else {
		return_code = output_length;
	}
	return return_code;
}

void LLCRYPTO_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	transformation->close((void *)native_id);
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	if (SNI_unregisterResource((void *)native_id, (SNI_closeFunction)transformation->close) != SNI_OK) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource\n");
	}
}

int32_t LLCRYPTO_CIPHER_IMPL_get_close_id(int32_t transformation_id) {
	LLCRYPTO_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)transformation->close;
}
