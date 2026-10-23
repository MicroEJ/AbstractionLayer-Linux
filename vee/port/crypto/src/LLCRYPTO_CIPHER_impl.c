/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdint.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <LLCRYPTO_CIPHER_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"
#include "LLCRYPTO_utils.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

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

#define AES_GCM_MAX_TAG_BYTES     (16u)
#define AES_GCM_DEFAULT_TAG_BYTES (AES_GCM_MAX_TAG_BYTES)

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
typedef int (*LLCRYPTO_CIPHER_init)(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                    const struct llcrypto_key *key,
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

static int llcrypto_openssl_cipher_aes_cbc_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                const struct llcrypto_key *key,
                                                const uint8_t *iv, int32_t iv_length);
static int llcrypto_openssl_cipher_aes_ecb_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                const struct llcrypto_key *key,
                                                const uint8_t *iv, int32_t iv_length);
static int llcrypto_openssl_cipher_aes_ctr_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                const struct llcrypto_key *key,
                                                const uint8_t *iv, int32_t iv_length);
static int llcrypto_openssl_cipher_des3_cbc_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                 const struct llcrypto_key *key,
                                                 const uint8_t *iv, int32_t iv_length);
static int llcrypto_openssl_cipher_aes_gcm_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                const struct llcrypto_key *key,
                                                const uint8_t *iv, int32_t iv_length);
static int llcrypto_openssl_cipher_decrypt(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer,
                                           int32_t buffer_length,
                                           uint8_t *output, int32_t *output_length, uint8_t do_final);
static int llcrypto_openssl_cipher_encrypt(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer,
                                           int32_t buffer_length,
                                           uint8_t *output, int32_t *output_length, uint8_t do_final);
static void llcrypto_openssl_cipher_close(void *native_id);

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

static int llcrypto_openssl_cipher_aes_cbc_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                const struct llcrypto_key *key,
                                                const uint8_t *iv, int32_t iv_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(iv_length);
	LLCRYPTO_CIPHER_ctx *cipher_ctx = NULL;
	int return_code = llcrypto_cipher_ctx_new(&cipher_ctx, is_decrypting, 0);

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		const EVP_CIPHER *cipher_type = NULL;
		switch (key->secret_key.length * 8u) {
		case LLCRYPTO_AES_128_KEY_BITS:
			cipher_type = EVP_aes_128_cbc();
			break;
		case LLCRYPTO_AES_192_KEY_BITS:
			cipher_type = EVP_aes_192_cbc();
			break;
		case LLCRYPTO_AES_256_KEY_BITS:
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
		*native_id = cipher_ctx;
	} else {
		if (NULL != cipher_ctx) {
			EVP_CIPHER_CTX_free(cipher_ctx->ctx);
			LLCRYPTO_free(cipher_ctx);
		}
	}

	return return_code;
}

static int llcrypto_openssl_cipher_aes_ecb_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                const struct llcrypto_key *key,
                                                const uint8_t *iv, int32_t iv_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(iv);
	LLCRYPTO_UNUSED_PARAM(iv_length);
	LLCRYPTO_CIPHER_ctx *cipher_ctx = NULL;
	int return_code = llcrypto_cipher_ctx_new(&cipher_ctx, is_decrypting, 0);

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		const EVP_CIPHER *cipher_type = NULL;
		switch (key->secret_key.length * 8u) {
		case LLCRYPTO_AES_128_KEY_BITS:
			cipher_type = EVP_aes_128_ecb();
			break;
		case LLCRYPTO_AES_192_KEY_BITS:
			cipher_type = EVP_aes_192_ecb();
			break;
		case LLCRYPTO_AES_256_KEY_BITS:
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
		*native_id = cipher_ctx;
	} else {
		if (NULL != cipher_ctx) {
			EVP_CIPHER_CTX_free(cipher_ctx->ctx);
			LLCRYPTO_free(cipher_ctx);
		}
	}

	return return_code;
}

static int llcrypto_openssl_cipher_aes_ctr_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                const struct llcrypto_key *key,
                                                const uint8_t *iv, int32_t iv_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(iv_length);
	LLCRYPTO_CIPHER_ctx *cipher_ctx = NULL;
	int return_code = llcrypto_cipher_ctx_new(&cipher_ctx, is_decrypting, 0);

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		const EVP_CIPHER *cipher_type = NULL;
		switch (key->secret_key.length * 8u) {
		case LLCRYPTO_AES_128_KEY_BITS:
			cipher_type = EVP_aes_128_ctr();
			break;
		case LLCRYPTO_AES_192_KEY_BITS:
			cipher_type = EVP_aes_192_ctr();
			break;
		case LLCRYPTO_AES_256_KEY_BITS:
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
		*native_id = cipher_ctx;
	} else {
		if (NULL != cipher_ctx) {
			EVP_CIPHER_CTX_free(cipher_ctx->ctx);
			LLCRYPTO_free(cipher_ctx);
		}
	}

	return return_code;
}

static int llcrypto_openssl_cipher_des3_cbc_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                 const struct llcrypto_key *key,
                                                 const uint8_t *iv, int32_t iv_length) {
	VEEPORT_LOGGER_LOG_DBG("");
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
		*native_id = cipher_ctx;
	} else {
		if (NULL != cipher_ctx) {
			EVP_CIPHER_CTX_free(cipher_ctx->ctx);
			LLCRYPTO_free(cipher_ctx);
		}
	}

	return return_code;
}

static int llcrypto_openssl_cipher_aes_gcm_init(LLCRYPTO_CIPHER_ctx **native_id, uint8_t is_decrypting,
                                                const struct llcrypto_key *key,
                                                const uint8_t *iv, int32_t iv_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_CIPHER_ctx *cipher_ctx = NULL;
	int return_code = llcrypto_cipher_ctx_new(&cipher_ctx, is_decrypting, AES_GCM_DEFAULT_TAG_BYTES);

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		const EVP_CIPHER *cipher_type = NULL;
		switch (key->secret_key.length * 8u) {
		case LLCRYPTO_AES_128_KEY_BITS:
			cipher_type = EVP_aes_128_gcm();
			break;
		case LLCRYPTO_AES_192_KEY_BITS:
			cipher_type = EVP_aes_192_gcm();
			break;
		case LLCRYPTO_AES_256_KEY_BITS:
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
		*native_id = cipher_ctx;
	} else {
		if (NULL != cipher_ctx) {
			EVP_CIPHER_CTX_free(cipher_ctx->ctx);
			LLCRYPTO_free(cipher_ctx);
		}
	}

	return return_code;
}

static int llcrypto_openssl_cipher_encrypt(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer,
                                           int32_t buffer_length,
                                           uint8_t *output, int32_t *output_length, uint8_t do_final) {
	VEEPORT_LOGGER_LOG_DBG("");
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

static int llcrypto_openssl_cipher_decrypt(LLCRYPTO_CIPHER_ctx *cipher_ctx, const uint8_t *buffer,
                                           int32_t buffer_length,
                                           uint8_t *output, int32_t *output_length, uint8_t do_final) {
	VEEPORT_LOGGER_LOG_DBG("");
	EVP_CIPHER_CTX *ctx = cipher_ctx->ctx;
	int return_code = MICROEJ_LLCRYPTO_CIPHER_SUCCESS;
	int total = 0;
	int32_t ciphertext_length = buffer_length;

	/* For GCM decrypt, the trailing tag_length bytes of the final input are the
	 * authentication tag. Update calls (do_final == 0) treat the entire buffer
	 * as ciphertext. */
	if (((uint8_t)1 == do_final) && (cipher_ctx->tag_length > 0)) {
		if (buffer_length < cipher_ctx->tag_length) {
			/* Not enough input to hold a tag: subtracting would index before buffer. */
			return MICROEJ_LLCRYPTO_CIPHER_ERROR;
		}
		ciphertext_length = buffer_length - cipher_ctx->tag_length;
		return_code = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, cipher_ctx->tag_length,
		                                  /* cppcheck-suppress misra-c2012-11.8 ; EVP_CIPHER_CTX_ctrl takes a non-const
		                                   * void*, but
		                                   * EVP_CTRL_GCM_SET_TAG only reads the tag it is given. */
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

static void llcrypto_openssl_cipher_close(void *native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
	EVP_CIPHER_CTX_free(cipher_ctx->ctx);
	LLCRYPTO_free(cipher_ctx);
}

int32_t LLCRYPTO_CIPHER_IMPL_get_transformation_description(uint8_t *transformation_name,
                                                            LLCRYPTO_CIPHER_transformation_desc *transformation_desc) {
	static const LLCRYPTO_CIPHER_transformation available_transformations[5] =
	{
		{
			.name = "AES/CBC/NoPadding",
			.init = llcrypto_openssl_cipher_aes_cbc_init,
			.decrypt = llcrypto_openssl_cipher_decrypt,
			.encrypt = llcrypto_openssl_cipher_encrypt,
			.close = llcrypto_openssl_cipher_close,
			.description = {
				.block_size = AES_CBC_BLOCK_BYTES,
				.unit_bytes = AES_CBC_BLOCK_BYTES,
				.cipher_mode = CBC_MODE,
			}
		},
		{
			.name = "AES/ECB/NoPadding",
			.init = llcrypto_openssl_cipher_aes_ecb_init,
			.decrypt = llcrypto_openssl_cipher_decrypt,
			.encrypt = llcrypto_openssl_cipher_encrypt,
			.close = llcrypto_openssl_cipher_close,
			.description = {
				.block_size = AES_ECB_BLOCK_BYTES,
				.unit_bytes = AES_ECB_BLOCK_BYTES,
				.cipher_mode = ECB_MODE,
			}
		},
		{
			.name = "AES/CTR/NoPadding",
			.init = llcrypto_openssl_cipher_aes_ctr_init,
			.decrypt = llcrypto_openssl_cipher_decrypt,
			.encrypt = llcrypto_openssl_cipher_encrypt,
			.close = llcrypto_openssl_cipher_close,
			.description = {
				.block_size = AES_CTR_BLOCK_BYTES,
				.unit_bytes = AES_CTR_UNIT_BYTES,
				.cipher_mode = CTR_MODE,
			}
		},
		{
			.name = "DESede/CBC/NoPadding",
			.init = llcrypto_openssl_cipher_des3_cbc_init,
			.decrypt = llcrypto_openssl_cipher_decrypt,
			.encrypt = llcrypto_openssl_cipher_encrypt,
			.close = llcrypto_openssl_cipher_close,
			.description = {
				.block_size = DES_CBC_BLOCK_BYTES,
				.unit_bytes = DES_CBC_BLOCK_BYTES,
				.cipher_mode = CBC_MODE,
			}
		},
		{
			.name = "AES/GCM/NoPadding",
			.init = llcrypto_openssl_cipher_aes_gcm_init,
			.decrypt = llcrypto_openssl_cipher_decrypt,
			.encrypt = llcrypto_openssl_cipher_encrypt,
			.close = llcrypto_openssl_cipher_close,
			.description = {
				.block_size = AES_GCM_BLOCK_BYTES,
				.unit_bytes = AES_GCM_UNIT_BYTES,
				.cipher_mode = GCM_MODE,
			}
		}
	};

	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = SNI_ERROR;
	size_t nb_transformations = sizeof(available_transformations) / sizeof(available_transformations[0]);
	const LLCRYPTO_CIPHER_transformation *transformation = &available_transformations[0];

	/* The description struct is mapped on a Java byte array whose length the caller chooses, so
	 * it is checked against the struct it must hold before the copy below. */
	if (!sni_array_contains_range(transformation_desc, 0, (int32_t)sizeof(LLCRYPTO_CIPHER_transformation_desc))) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		for (size_t i = 0; i < nb_transformations; i++) {
			if (0 == strcmp((char *)transformation_name, transformation->name)) {
				(void)memcpy(transformation_desc, &(transformation->description),
				             sizeof(LLCRYPTO_CIPHER_transformation_desc));
				return_code = (int32_t)transformation;
				break;
			}
			transformation++;
		}
	}
	return return_code;
}

int32_t LLCRYPTO_CIPHER_IMPL_get_buffered_length(int32_t nativeTransformationId, int32_t nativeId) {
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
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	const LLCRYPTO_CIPHER_ctx *cipher_ctx = (const LLCRYPTO_CIPHER_ctx *)native_id;

	/* EVP_CIPHER_CTX_get_updated_iv writes the length it is given. */
	if (!sni_array_contains_range(iv, 0, iv_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		EVP_CIPHER_CTX *ctx = cipher_ctx->ctx;
		if (1 != EVP_CIPHER_CTX_get_updated_iv(ctx, iv, iv_length)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Cannot read the initialization vector");
		}
	}
}

void LLCRYPTO_CIPHER_IMPL_set_IV(int32_t transformation_id, int32_t native_id, uint8_t *iv, int32_t iv_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	const LLCRYPTO_CIPHER_ctx *cipher_ctx = (const LLCRYPTO_CIPHER_ctx *)native_id;
	int32_t expected_iv_length = EVP_CIPHER_CTX_iv_length(cipher_ctx->ctx);

	/* EVP_EncryptInit_ex reads expected_iv_length bytes from iv and never looks at iv_length, so a
	 * caller declaring a different size is handing over the wrong IV: the bytes past iv_length
	 * would be used as IV material. iv_length is only a claim, so the array is checked too. */
	if (expected_iv_length <= 0) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cipher has no IV");
	} else if (iv_length != expected_iv_length) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "IV length does not match the cipher");
	} else if (!sni_array_contains_range(iv, 0, expected_iv_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		if (1 != EVP_EncryptInit_ex(cipher_ctx->ctx, NULL, NULL, NULL, iv)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Cannot set the initialization vector");
		}
	}
}

int32_t LLCRYPTO_CIPHER_IMPL_get_IV_length(int32_t transformation_id, int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	const LLCRYPTO_CIPHER_ctx *cipher_ctx = (const LLCRYPTO_CIPHER_ctx *)native_id;
	int32_t return_code = EVP_CIPHER_CTX_iv_length(cipher_ctx->ctx);
	if (0 == return_code) {
		return_code = SNI_ERROR;
	}
	return return_code;
}

int32_t LLCRYPTO_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, int32_t secret_key_id,
                                  uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	LLCRYPTO_CIPHER_ctx *native_id = NULL;
	int32_t return_code = MICROEJ_LLCRYPTO_CIPHER_SUCCESS;
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	const struct llcrypto_key *key = (const struct llcrypto_key *)secret_key_id;

	/* ECB is initialized with no IV, so a zero length is legal here; only the claimed length
	 * exceeding the array is not. */
	if (!sni_array_contains_range(iv, 0, iv_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		return_code = MICROEJ_LLCRYPTO_CIPHER_ERROR;
	} else {
		return_code = transformation->init(&native_id, is_decrypting, key, iv, iv_length);
		if (MICROEJ_LLCRYPTO_CIPHER_ERROR == return_code) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		}
	}

	/* For GCM mode, override the tag length if the caller specified one */
	if ((MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) && (tag_length > 0)) {
		if (tag_length > (int32_t)AES_GCM_MAX_TAG_BYTES) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_CIPHER_INVALID_TAG_LENGTH,
			                                               "invalid authentication tag length");
			transformation->close(native_id);
			return_code = MICROEJ_LLCRYPTO_CIPHER_ERROR;
		} else {
			LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
			cipher_ctx->tag_length = tag_length;
		}
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		if (SNI_OK != SNI_registerResource(native_id, transformation->close, NULL)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Can't register SNI native resource");
			transformation->close(native_id);
			return_code = MICROEJ_LLCRYPTO_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS == return_code) {
		return_code = (int32_t)native_id;
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

void LLCRYPTO_CIPHER_IMPL_update_AAD(int32_t transformation_id, int32_t native_id, uint8_t *aad_buffer,
                                     int32_t aad_buffer_offset, int32_t aad_buffer_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	if (!sni_array_contains_range(aad_buffer, aad_buffer_offset, aad_buffer_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else if (cipher_ctx->tag_length > 0) {
		int len = 0;
		int rc = 0;
		if ((uint8_t)1 == cipher_ctx->is_decrypting) {
			rc = EVP_DecryptUpdate(cipher_ctx->ctx, NULL, &len, &aad_buffer[aad_buffer_offset], aad_buffer_length);
		} else {
			rc = EVP_EncryptUpdate(cipher_ctx->ctx, NULL, &len, &aad_buffer[aad_buffer_offset], aad_buffer_length);
		}
		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != rc) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		}
	} else {
		LLCRYPTO_UNUSED_PARAM(aad_buffer);
		LLCRYPTO_UNUSED_PARAM(aad_buffer_offset);
		LLCRYPTO_UNUSED_PARAM(aad_buffer_length);
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "AAD not supported for this cipher mode");
	}
}

/**
 * Number of bytes the decrypt path can write for a chunk of buffer_length bytes: a block cipher
 * emits the bytes buffered by earlier update calls together with this chunk, so the write can
 * exceed buffer_length. The final GCM chunk carries the tag in its input instead, so it writes
 * tag_length fewer bytes than it reads; a chunk too short to hold a tag is left to the AEAD path
 * to reject.
 *
 * Call only once buffer_length is known to fit its array. buffered_length is under one cipher
 * block and tag_length is capped at AES_GCM_MAX_TAG_BYTES, so the sum overflows only for a
 * buffer_length within ~32 of INT32_MAX — a ~2 GiB Java array.
 */
static int32_t decrypt_output_max_len(const LLCRYPTO_CIPHER_ctx *cipher_ctx, int32_t buffer_length,
                                      uint8_t do_final) {
	int32_t output_max_len = buffer_length + cipher_ctx->buffered_length;

	if (((uint8_t)1 == do_final) && (cipher_ctx->tag_length > 0)) {
		output_max_len = (output_max_len > cipher_ctx->tag_length) ?
		                 (output_max_len - cipher_ctx->tag_length) : 0;
	}
	return output_max_len;
}

/**
 * Number of bytes the encrypt path can write for a chunk of buffer_length bytes: the chunk, plus
 * whatever earlier update calls left buffered, plus the GCM tag appended on the final chunk.
 *
 * Same precondition as decrypt_output_max_len: buffer_length must already be bounded by its array.
 */
static int32_t encrypt_output_max_len(const LLCRYPTO_CIPHER_ctx *cipher_ctx, int32_t buffer_length,
                                      uint8_t do_final) {
	int32_t output_max_len = buffer_length + cipher_ctx->buffered_length;

	if (((uint8_t)1 == do_final) && (cipher_ctx->tag_length > 0)) {
		output_max_len += cipher_ctx->tag_length;
	}
	return output_max_len;
}

int32_t LLCRYPTO_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                     int32_t buffer_offset,
                                     int32_t buffer_length, uint8_t *output, int32_t output_offset, uint8_t do_final) {
	VEEPORT_LOGGER_LOG_DBG("");
	int32_t output_length = 0;
	int32_t return_code = LLCRYPTO_ERROR;
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	/* buffer first: decrypt_output_max_len needs buffer_length bounded before it adds to it. */
	if (!sni_array_contains_range(buffer, buffer_offset, buffer_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		return_code = SNI_ERROR;
	} else if (!sni_array_contains_range(output, output_offset,
	                                     decrypt_output_max_len(cipher_ctx, buffer_length, do_final))) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		return_code = SNI_ERROR;
	} else {
		return_code = transformation->decrypt(cipher_ctx, &buffer[buffer_offset], buffer_length,
		                                      &output[output_offset], &output_length, do_final);
		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
			if (((uint8_t)1 == do_final) && (cipher_ctx->tag_length > 0)) {
				/* GCM authentication tag verification failed */
				/* A rejected tag is an expected outcome, not a failure: drop the entry the
				 * decryption queued so it cannot surface from a later, unrelated call. */
				ERR_clear_error();
				return_code = LLCRYPTO_ERROR_AEAD_AUTH;
			} else {
				int err = ERR_get_error();
				VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
				                                               ERR_error_string(err, NULL));
				return_code = SNI_ERROR;
			}
		} else {
			return_code = output_length;
		}
	}
	return return_code;
}

int32_t LLCRYPTO_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                     int32_t buffer_offset,
                                     int32_t buffer_length, uint8_t *output, int32_t output_offset, uint8_t do_final) {
	VEEPORT_LOGGER_LOG_DBG("");
	int32_t output_length = 0;
	int32_t return_code = LLCRYPTO_ERROR;
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	/* buffer first: encrypt_output_max_len needs buffer_length bounded before it adds to it. */
	if (!sni_array_contains_range(buffer, buffer_offset, buffer_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		return_code = SNI_ERROR;
	} else if (!sni_array_contains_range(output, output_offset,
	                                     encrypt_output_max_len(cipher_ctx, buffer_length, do_final))) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		return_code = SNI_ERROR;
	} else {
		return_code = transformation->encrypt(cipher_ctx, &buffer[buffer_offset], buffer_length,
		                                      &output[output_offset], &output_length, do_final);
		if (MICROEJ_LLCRYPTO_CIPHER_SUCCESS != return_code) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
			return_code = SNI_ERROR;
		} else {
			return_code = output_length;
		}
	}
	return return_code;
}

void LLCRYPTO_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	llcrypto_unregister_and_close((LLCRYPTO_CIPHER_ctx *)native_id, transformation->close);
}

int32_t LLCRYPTO_CIPHER_IMPL_get_close_id(int32_t transformation_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	const LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	return sni_close_id(transformation->close);
}
