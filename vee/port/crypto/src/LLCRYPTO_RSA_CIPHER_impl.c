/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdint.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <LLCRYPTO_CIPHER_impl.h>
#include <LLCRYPTO_RSA_CIPHER_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"
#include "LLCRYPTO_utils.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

#define MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS 1
#define MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR   0

/**
 * Cipher init function type
 */
typedef int (*LLCRYPTO_RSA_CIPHER_init)(EVP_PKEY_CTX **native_id, uint8_t is_decrypting, int32_t key_id,
                                        int32_t padding_type,
                                        int32_t oaep_hash_algorithm);
typedef int (*LLCRYPTO_RSA_CIPHER_decrypt)(EVP_PKEY_CTX *ctx, const uint8_t *buffer, int32_t buffer_length,
                                           uint8_t *output, int32_t output_capacity,
                                           int32_t *output_length);
typedef int (*LLCRYPTO_RSA_CIPHER_encrypt)(EVP_PKEY_CTX *ctx, const uint8_t *buffer, int32_t buffer_length,
                                           uint8_t *output, int32_t output_capacity,
                                           int32_t *output_length);
typedef void (*LLCRYPTO_RSA_CIPHER_close)(void *native_id);

typedef struct {
	char *name; // the name of the transformation
	LLCRYPTO_RSA_CIPHER_init init;
	LLCRYPTO_RSA_CIPHER_decrypt decrypt;
	LLCRYPTO_RSA_CIPHER_encrypt encrypt;
	LLCRYPTO_RSA_CIPHER_close close;
	LLCRYPTO_RSA_CIPHER_transformation_desc description;
} LLCRYPTO_RSA_CIPHER_transformation;

static int llcrypto_openssl_rsa_cipher_init(EVP_PKEY_CTX **native_id, uint8_t is_decrypting, int32_t key_id,
                                            int32_t padding_type,
                                            int32_t oaep_hash_algorithm);
static int llcrypto_openssl_rsa_cipher_decrypt(EVP_PKEY_CTX *ctx, const uint8_t *buffer, int32_t buffer_length,
                                               uint8_t *output,
                                               int32_t output_capacity, int32_t *output_length);
static int llcrypto_openssl_rsa_cipher_encrypt(EVP_PKEY_CTX *ctx, const uint8_t *buffer, int32_t buffer_length,
                                               uint8_t *output,
                                               int32_t output_capacity, int32_t *output_length);
static void llcrypto_openssl_rsa_cipher_close(void *native_id);

static int llcrypto_openssl_rsa_cipher_init(EVP_PKEY_CTX **native_id, uint8_t is_decrypting, int32_t key_id,
                                            int32_t padding_type,
                                            int32_t oaep_hash_algorithm) {
	VEEPORT_LOGGER_LOG_DBG("key_id %d is_decrypting %d padding_type %d oaep_hash_algorithm %d", key_id, is_decrypting,
	                       padding_type, oaep_hash_algorithm);
	EVP_PKEY_CTX *ctx = NULL;
	int32_t return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS;

	// OpenSSL has the public and private key in the same object
	const struct llcrypto_key *key = (const struct llcrypto_key *)key_id;
	ctx = EVP_PKEY_CTX_new(key->evp_key, NULL);

	if (!ctx) {
		// Handle error
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_new failed: %s", ERR_error_string(ERR_get_error(), NULL));
		return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		if ((uint8_t)1 == is_decrypting) {
			if (EVP_PKEY_decrypt_init(ctx) <= 0) {
				VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_decrypt_init failed: %s", ERR_error_string(ERR_get_error(), NULL));
				return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
			}
		} else {
			if (EVP_PKEY_encrypt_init(ctx) <= 0) {
				VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_encrypt_init failed: %s", ERR_error_string(ERR_get_error(), NULL));
				return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
			}
		}
	}

	int32_t padding = (padding_type == (int32_t)PAD_PKCS1_TYPE) ? RSA_PKCS1_PADDING : RSA_PKCS1_OAEP_PADDING;
	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
			VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_set_rsa_padding failed: %s", ERR_error_string(ERR_get_error(), NULL));
			return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		if (padding_type == (int32_t)PAD_OAEP_MGF1_TYPE) {
			const EVP_MD *md = (oaep_hash_algorithm == (int32_t)OAEP_HASH_SHA_1_ALGORITHM) ? EVP_sha1() : EVP_sha256();
			if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
				VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_set_rsa_oaep_md failed: %s",
				                       ERR_error_string(ERR_get_error(), NULL));
				return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
			}
			if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
				VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_set_rsa_mgf1_md failed: %s",
				                       ERR_error_string(ERR_get_error(), NULL));
				return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
			}
		}
	}

	*native_id = ctx;

	return return_code;
}

static int llcrypto_openssl_rsa_cipher_decrypt(EVP_PKEY_CTX *ctx, const uint8_t *buffer, int32_t buffer_length,
                                               uint8_t *output,
                                               int32_t output_capacity, int32_t *output_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	size_t len = 0;

	int return_code = EVP_PKEY_decrypt(ctx, NULL, &len, buffer, buffer_length);
	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS != return_code) {
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_decrypt failed: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		/* EVP_PKEY_decrypt refuses to write past the size passed in, so the array bounds the operation. */
		len = (size_t)output_capacity;
		return_code = EVP_PKEY_decrypt(ctx, output, &len, buffer, buffer_length);
		if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS != return_code) {
			VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_decrypt failed: %s", ERR_error_string(ERR_get_error(), NULL));
		}
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		// actual number of bytes is written to len
		*output_length = len;
	}
	return return_code;
}

static int llcrypto_openssl_rsa_cipher_encrypt(EVP_PKEY_CTX *ctx, const uint8_t *buffer, int32_t buffer_length,
                                               uint8_t *output,
                                               int32_t output_capacity, int32_t *output_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	size_t len = 0;

	int return_code = EVP_PKEY_encrypt(ctx, NULL, &len, buffer, buffer_length);
	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS != return_code) {
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_encrypt failed: %s", ERR_error_string(ERR_get_error(), NULL));
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		/* EVP_PKEY_encrypt refuses to write past the size passed in, so the array bounds the operation. */
		len = (size_t)output_capacity;
		return_code = EVP_PKEY_encrypt(ctx, output, &len, buffer, buffer_length);
		if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS != return_code) {
			VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_encrypt failed: %s", ERR_error_string(ERR_get_error(), NULL));
		}
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		// actual number of bytes is written to len
		*output_length = len;
	}
	return return_code;
}

static void llcrypto_openssl_rsa_cipher_close(void *native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX *)native_id;

	/* Clean up */
	EVP_PKEY_CTX_free(ctx);
}

int32_t LLCRYPTO_RSA_CIPHER_IMPL_get_transformation_description(uint8_t *transformation_name,
                                                                LLCRYPTO_RSA_CIPHER_transformation_desc *
                                                                transformation_desc) {
	static const LLCRYPTO_RSA_CIPHER_transformation available_transformations[3] =
	{
		{
			.name = "RSA/ECB/PKCS1Padding",
			.init = llcrypto_openssl_rsa_cipher_init,
			.decrypt = llcrypto_openssl_rsa_cipher_decrypt,
			.encrypt = llcrypto_openssl_rsa_cipher_encrypt,
			.close = llcrypto_openssl_rsa_cipher_close,
			.description = {
				.padding_type = PAD_PKCS1_TYPE,
				.oaep_hash_algorithm = OAEP_HASH_SHA_1_ALGORITHM,
			}
		},
		{
			.name = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
			.init = llcrypto_openssl_rsa_cipher_init,
			.decrypt = llcrypto_openssl_rsa_cipher_decrypt,
			.encrypt = llcrypto_openssl_rsa_cipher_encrypt,
			.close = llcrypto_openssl_rsa_cipher_close,
			.description = {
				.padding_type = PAD_OAEP_MGF1_TYPE,
				.oaep_hash_algorithm = OAEP_HASH_SHA_1_ALGORITHM,
			}
		},
		{
			.name = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
			.init = llcrypto_openssl_rsa_cipher_init,
			.decrypt = llcrypto_openssl_rsa_cipher_decrypt,
			.encrypt = llcrypto_openssl_rsa_cipher_encrypt,
			.close = llcrypto_openssl_rsa_cipher_close,
			.description = {
				.padding_type = PAD_OAEP_MGF1_TYPE,
				.oaep_hash_algorithm = OAEP_HASH_SHA_256_ALGORITHM,
			}
		}
	};

	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = SNI_ERROR;
	size_t nb_transformations = sizeof(available_transformations) / sizeof(available_transformations[0]);
	const LLCRYPTO_RSA_CIPHER_transformation *transformation = &available_transformations[0];

	/* The description struct is mapped on a Java byte array whose length the caller chooses, so
	 * it is checked against the struct it must hold before the copy below. */
	if (!sni_array_contains_range(transformation_desc, 0, (int32_t)sizeof(LLCRYPTO_RSA_CIPHER_transformation_desc))) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		for (size_t i = 0; i < nb_transformations; i++) {
			if (0 == strcmp((char *)transformation_name, transformation->name)) {
				(void)memcpy(transformation_desc, &(transformation->description),
				             sizeof(LLCRYPTO_RSA_CIPHER_transformation_desc));
				return_code = (int32_t)transformation;
				break;
			}
			transformation++;
		}
	}
	return return_code;
}

/**
 * @brief Initializes a RSA Cipher resource.
 *
 * @param[in] tranformation_id            The transformation ID.
 * @param[in] is_decrypting                '1' for decrypting, '0' for encryting.
 * @param[in] key_id                    The key id (either a {@link NativePublicKey} or a {@link NativePrivateKey}).
 * @param[in] padding_type                The RSA padding type.
 * @param[in] oaep_hash_algorithm        The hash algorithm for OAEP RSA padding type.
 *
 * @return The nativeId of the newly initialized resource.
 *
 * @note Throws NativeException on error.
 */
int32_t LLCRYPTO_RSA_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, int32_t key_id,
                                      int32_t padding_type, int32_t oaep_hash_algorithm) {
	int32_t return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS;
	VEEPORT_LOGGER_LOG_DBG("");
	EVP_PKEY_CTX *native_id = NULL;
	LLCRYPTO_RSA_CIPHER_transformation *transformation = (LLCRYPTO_RSA_CIPHER_transformation *)transformation_id;

	if (0 == key_id) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "LLCRYPTO_RSA_CIPHER_IMPL_init invalid key_id");
		return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		if ((padding_type != (int32_t)PAD_PKCS1_TYPE) && (padding_type != (int32_t)PAD_OAEP_MGF1_TYPE)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "LLCRYPTO_RSA_CIPHER_IMPL_init invalid padding_type");
			return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		if ((padding_type == (int32_t)PAD_OAEP_MGF1_TYPE) &&
		    ((oaep_hash_algorithm != (int32_t)OAEP_HASH_SHA_1_ALGORITHM) &&
		     (oaep_hash_algorithm != (int32_t)OAEP_HASH_SHA_256_ALGORITHM))) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "LLCRYPTO_RSA_CIPHER_IMPL_init invalid oaep_hash_algorithm");
			return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		return_code = transformation->init(&native_id, is_decrypting, key_id, padding_type,
		                                   oaep_hash_algorithm);

		if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS != return_code) {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
			return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_OK != SNI_registerResource(native_id, transformation->close, NULL)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Can't register SNI native resource");
			transformation->close(native_id);
			return_code = MICROEJ_LLCRYPTO_RSA_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
		return_code = (int32_t)native_id;
	}

	return return_code;
}

/**
 * @brief Decrypts the message contained in <code>buffer</code>.
 *
 * @param[in] transformation_id            The transformation ID.
 * @param[in] native_id                    The resource's native ID.
 * @param[in] buffer                    The buffer containing the message to decrypt.
 * @param[in] buffer_offset                The buffer offset.
 * @param[in] buffer_length                The buffer length.
 * @param[out] output                    The output buffer containing the plaintext message.
 * @param[out] output_offset            The output offset.
 *
 * @return The length of the buffer.
 *
 * @note Throws NativeException on error.
 *
 * @warning <code>buffer</code> must not be used outside of the VM task or saved.
 * @warning <code>output</code> must not be used outside of the VM task or saved.
 */
int32_t LLCRYPTO_RSA_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                         int32_t buffer_offset, int32_t buffer_length, uint8_t *output,
                                         int32_t output_offset) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_RSA_CIPHER_transformation *transformation = (LLCRYPTO_RSA_CIPHER_transformation *)transformation_id;
	int32_t output_len = 0;
	int32_t return_code = LLCRYPTO_ERROR;
	/* The transformation writes as much as the array can hold from output_offset, so it is given
	 * that remaining length rather than a caller-declared one. */
	int32_t output_capacity = sni_array_get_avail(output, output_offset);
	if (!sni_array_contains_range(buffer, buffer_offset, buffer_length) || (output_capacity < 0)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		return_code = SNI_ERROR;
	} else {
		return_code = transformation->decrypt((EVP_PKEY_CTX *)native_id, &buffer[buffer_offset], buffer_length,
		                                      &output[output_offset], output_capacity, &output_len);
		if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
			return_code = output_len;
		} else {
			/* Constant message: a distinguishable PKCS#1 v1.5 failure reason is a
			 * decryption oracle. */
			VEEPORT_LOGGER_LOG_ERR("failed: %s", ERR_error_string(ERR_get_error(), NULL));
			ERR_clear_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_RSA_CIPHER_DECRYPTION_FAILED, "decryption failed");
			return_code = SNI_ERROR;
		}
	}
	return return_code;
}

/**
 * @brief Encrypts the message contained in <code>buffer</code>.
 *
 * @param[in]  transformation_id           The transformation ID.
 * @param[in]  native_id                   The resource's native ID.
 * @param[in]  buffer                      The buffer containing the plaintext message to encrypt.
 * @param[in]  buffer_offset               The buffer offset.
 * @param[in]  buffer_length               The buffer length.
 * @param[out] output                      The output buffer containing the encrypted message.
 * @param[in]  output_offset               The output offset.
 *
 * @return The length of the buffer.
 *
 * @note Throws NativeException on error.
 *
 * @warning <code>buffer</code> must not be used outside of the VM task or saved.
 * @warning <code>output</code> must not be used outside of the VM task or saved.
 */
int32_t LLCRYPTO_RSA_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                         int32_t buffer_offset, int32_t buffer_length, uint8_t *output,
                                         int32_t output_offset) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_RSA_CIPHER_transformation *transformation = (LLCRYPTO_RSA_CIPHER_transformation *)transformation_id;
	int32_t output_len = 0;
	int32_t return_code = LLCRYPTO_ERROR;
	/* The transformation writes as much as the array can hold from output_offset, so it is given
	 * that remaining length rather than a caller-declared one. */
	int32_t output_capacity = sni_array_get_avail(output, output_offset);
	if (!sni_array_contains_range(buffer, buffer_offset, buffer_length) || (output_capacity < 0)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		return_code = SNI_ERROR;
	} else {
		return_code = transformation->encrypt((EVP_PKEY_CTX *)native_id, &buffer[buffer_offset], buffer_length,
		                                      &output[output_offset], output_capacity, &output_len);
		if (MICROEJ_LLCRYPTO_RSA_CIPHER_SUCCESS == return_code) {
			return_code = output_len;
		} else {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
			return_code = SNI_ERROR;
		}
	}
	return return_code;
}

/**
 * @brief Closes the resource related to the native ID.
 *
 * @param[in] transformation_id            The transformation ID.
 * @param[in] native_id                    The resource's native ID.
 *
 * @note Throws NativeException on error.
 */
void LLCRYPTO_RSA_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_RSA_CIPHER_transformation *transformation = (LLCRYPTO_RSA_CIPHER_transformation *)transformation_id;
	llcrypto_unregister_and_close((EVP_PKEY_CTX *)native_id, transformation->close);
}

/**
 * @brief Gets the id of the native close function.
 * @param[in] transformation_id            The transformation ID.
 *
 * @return the id of the static native close function.
 *
 * @note Throws NativeException on error.
 */
int32_t LLCRYPTO_RSA_CIPHER_IMPL_get_close_id(int32_t transformation_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	const LLCRYPTO_RSA_CIPHER_transformation *transformation = (LLCRYPTO_RSA_CIPHER_transformation *)transformation_id;
	return sni_close_id(transformation->close);
}
