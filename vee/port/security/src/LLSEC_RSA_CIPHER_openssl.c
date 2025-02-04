/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

/**
 * @file
 * @brief MicroEJ Security low level API implementation for OpenSSL Library
 * @author MicroEJ Developer Team
 * @version 3.0.0
 * @date 20 August 2024
 */


#include <LLSEC_CIPHER_impl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rsa.h>

#include <stdint.h>
#include <string.h>

#include "sni.h"
#include "LLSEC_RSA_CIPHER_impl.h"
#include "LLSEC_openssl.h"

#define MICROEJ_LLSECU_CIPHER_SUCCESS 1
#define MICROEJ_LLSECU_CIPHER_ERROR   0

// #define LLSEC_RSA_CIPHER_DEBUG_TRACE

#ifdef LLSEC_RSA_CIPHER_DEBUG_TRACE
#define LLSEC_RSA_CIPHER_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLSEC_RSA_CIPHER_DEBUG_PRINTF(...) ((void)0)
#endif

/**
 * Cipher init function type
 */
typedef int (*LLSEC_RSA_CIPHER_init)(void** native_id, uint8_t is_decrypting, int32_t key_id, int32_t padding_type, int32_t oaep_hash_algorithm);
typedef int (*LLSEC_RSA_CIPHER_decrypt)(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output, int32_t* output_length);
typedef int (*LLSEC_RSA_CIPHER_encrypt)(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output, int32_t* output_length);
typedef void (*LLSEC_RSA_CIPHER_close)(void* native_id);

typedef struct {
	char* name; // the name of the transformation
	LLSEC_RSA_CIPHER_init init;
	LLSEC_RSA_CIPHER_decrypt decrypt;
	LLSEC_RSA_CIPHER_encrypt encrypt;
	LLSEC_RSA_CIPHER_close close;
	LLSEC_RSA_CIPHER_transformation_desc description;
} LLSEC_RSA_CIPHER_transformation;

static int LLSEC_CIPHER_rsa_init(void** native_id, uint8_t is_decrypting, int32_t key_id, int32_t padding_type, int32_t oaep_hash_algorithm);
static int openssl_rsa_cipher_decrypt(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output, int32_t* output_length);
static int openssl_rsa_cipher_encrypt(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output, int32_t* output_length);
static void openssl_rsa_cipher_close(void* native_id);

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file
static LLSEC_RSA_CIPHER_transformation available_transformations[3] =
{
	{
		.name = "RSA/ECB/PKCS1Padding",
		.init = LLSEC_CIPHER_rsa_init,
		.decrypt = openssl_rsa_cipher_decrypt,
		.encrypt = openssl_rsa_cipher_encrypt,
		.close = openssl_rsa_cipher_close,
		{
			.padding_type = PAD_PKCS1_TYPE,
			.oaep_hash_algorithm = OAEP_HASH_SHA_1_ALGORITHM,
		}
	},
	{
		.name = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
		.init = LLSEC_CIPHER_rsa_init,
		.decrypt = openssl_rsa_cipher_decrypt,
		.encrypt = openssl_rsa_cipher_encrypt,
		.close = openssl_rsa_cipher_close,
		{
			.padding_type = PAD_OAEP_MGF1_TYPE,
			.oaep_hash_algorithm = OAEP_HASH_SHA_1_ALGORITHM,
		}
	},
	{
		.name = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
		.init = LLSEC_CIPHER_rsa_init,
		.decrypt = openssl_rsa_cipher_decrypt,
		.encrypt = openssl_rsa_cipher_encrypt,
		.close = openssl_rsa_cipher_close,
		{
			.padding_type = PAD_OAEP_MGF1_TYPE,
			.oaep_hash_algorithm = OAEP_HASH_SHA_256_ALGORITHM,
		}
	}
};

static int LLSEC_CIPHER_rsa_init(void** native_id, uint8_t is_decrypting, int32_t key_id, int32_t padding_type, int32_t oaep_hash_algorithm) {
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s : key_id %d is_decrypting %d padding_type %d oaep_hash_algorithm %d\n", __func__, key_id, is_decrypting, padding_type, oaep_hash_algorithm);
	EVP_PKEY_CTX *ctx = NULL;
	uint32_t err;
	int32_t return_code = MICROEJ_LLSECU_CIPHER_SUCCESS;

	// OpenSSL has the public and private key in the same object
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_priv_key* key = (LLSEC_priv_key*)key_id;
	ctx = EVP_PKEY_CTX_new(key->key, NULL);

	if (!ctx) {
		// Handle error
		err = ERR_get_error();
		LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_CTX_new failed: %s\n", __func__, ERR_error_string(err, NULL));
		return_code = MICROEJ_LLSECU_CIPHER_ERROR;
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		if ((uint8_t) 1 == is_decrypting) {
			if (EVP_PKEY_decrypt_init(ctx) <= 0) {
				err = ERR_get_error();
				LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_decrypt_init failed: %s\n", __func__, ERR_error_string(err, NULL));
				return_code = MICROEJ_LLSECU_CIPHER_ERROR;
			}
		} else {
			if (EVP_PKEY_encrypt_init(ctx) <= 0) {
				err = ERR_get_error();
				LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_encrypt_init failed: %s\n", __func__, ERR_error_string(err, NULL));
				return_code = MICROEJ_LLSECU_CIPHER_ERROR;
			}
		}
	}

	int32_t padding = (padding_type == (int32_t)PAD_PKCS1_TYPE) ? RSA_PKCS1_PADDING : RSA_PKCS1_OAEP_PADDING;
	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <=0) {
			err = ERR_get_error();
			LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_CTX_set_rsa_padding failed: %s\n", __func__, ERR_error_string(err, NULL));
			return_code = MICROEJ_LLSECU_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		if (padding_type == (int32_t)PAD_OAEP_MGF1_TYPE) {
			const EVP_MD *md = (oaep_hash_algorithm == (int32_t)OAEP_HASH_SHA_1_ALGORITHM) ? EVP_sha1() : EVP_sha256();
			if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
				err = ERR_get_error();
				LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_CTX_set_rsa_oaep_md failed: %s\n", __func__, ERR_error_string(err, NULL));
				return_code = MICROEJ_LLSECU_CIPHER_ERROR;
			}
			if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
				err = ERR_get_error();
				LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_CTX_set_rsa_mgf1_md failed: %s\n", __func__, ERR_error_string(err, NULL));
				return_code = MICROEJ_LLSECU_CIPHER_ERROR;
			}
		}
	}

	*native_id = (void*)ctx;

	return return_code;
}

static int openssl_rsa_cipher_decrypt(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output, int32_t* output_length) {
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX*)native_id;
	size_t len = 0;

	int return_code = EVP_PKEY_decrypt(ctx, NULL, &len, buffer, buffer_length);
	if (MICROEJ_LLSECU_CIPHER_SUCCESS != return_code) {
		int32_t err = ERR_get_error();
		LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_decrypt failed: %s\n", __func__, ERR_error_string(err, NULL));
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		return_code = EVP_PKEY_decrypt(ctx, output, &len, buffer, buffer_length);
		if (MICROEJ_LLSECU_CIPHER_SUCCESS != return_code) {
			int32_t err = ERR_get_error();
			LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_decrypt failed: %s\n", __func__, ERR_error_string(err, NULL));
		}
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		// actual number of bytes is written to len
		*output_length = len;
	}
	return return_code;
}

static int openssl_rsa_cipher_encrypt(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output, int32_t* output_length) {
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX*)native_id;
	size_t len = 0;

	int return_code = EVP_PKEY_encrypt(ctx, NULL, &len, buffer, buffer_length);
	if (MICROEJ_LLSECU_CIPHER_SUCCESS != return_code) {
		int32_t err = ERR_get_error();
		LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_encrypt failed: %s\n", __func__, ERR_error_string(err, NULL));
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		return_code = EVP_PKEY_encrypt(ctx, output, &len, buffer, buffer_length);
		if (MICROEJ_LLSECU_CIPHER_SUCCESS != return_code) {
			int32_t err = ERR_get_error();
			LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s EVP_PKEY_decrypt failed: %s\n", __func__, ERR_error_string(err, NULL));
		}
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		// actual number of bytes is written to len
		*output_length = len;
	}
	return return_code;
}

static void openssl_rsa_cipher_close(void* native_id) {
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX*)native_id;

	/* Clean up */
	EVP_PKEY_CTX_free(ctx);
}

// cppcheck-suppress constParameterPointer // SNI type conflic
int32_t LLSEC_RSA_CIPHER_IMPL_get_transformation_description(uint8_t *transformation_name,
															 LLSEC_RSA_CIPHER_transformation_desc *transformation_desc)
{
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s\n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_transformations = sizeof(available_transformations) / sizeof(LLSEC_RSA_CIPHER_transformation);
	LLSEC_RSA_CIPHER_transformation* transformation = &available_transformations[0];

	while (--nb_transformations >= 0)
	{
		if (0 == strcmp(transformation_name, transformation->name)) {
			(void)memcpy(transformation_desc, &(transformation->description), sizeof(LLSEC_RSA_CIPHER_transformation_desc));
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
int32_t LLSEC_RSA_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, int32_t key_id,
								   int32_t padding_type, int32_t oaep_hash_algorithm) {
	int32_t return_code = MICROEJ_LLSECU_CIPHER_SUCCESS;
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s\n", __func__);
	void* native_id = NULL;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_transformation* transformation = (LLSEC_RSA_CIPHER_transformation*)transformation_id;

	if (0 == key_id) {
		(void)SNI_throwNativeException(key_id, "LLSEC_RSA_CIPHER_IMPL_init invalid key_id");
		return_code = MICROEJ_LLSECU_CIPHER_ERROR;
	}

	if ((padding_type != (int32_t)PAD_PKCS1_TYPE) && (padding_type != (int32_t)PAD_OAEP_MGF1_TYPE)) {
		(void)SNI_throwNativeException(padding_type, "LLSEC_RSA_CIPHER_IMPL_init invalid padding_type");
		return_code = MICROEJ_LLSECU_CIPHER_ERROR;
	}

	if ((padding_type == (int32_t)PAD_OAEP_MGF1_TYPE) && ((oaep_hash_algorithm != (int32_t)OAEP_HASH_SHA_1_ALGORITHM) && (oaep_hash_algorithm != (int32_t)OAEP_HASH_SHA_256_ALGORITHM))) {
		(void)SNI_throwNativeException(oaep_hash_algorithm, "LLSEC_RSA_CIPHER_IMPL_init invalid oaep_hash_algorithm");
		return_code = MICROEJ_LLSECU_CIPHER_ERROR;
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		return_code = transformation->init((void**)&native_id, is_decrypting, key_id, padding_type, oaep_hash_algorithm);

		if (MICROEJ_LLSECU_CIPHER_SUCCESS != return_code) {
			int err = ERR_get_error();
			(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
			return_code = MICROEJ_LLSECU_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_OK != SNI_registerResource(native_id, transformation->close, NULL)) {
			(void)SNI_throwNativeException(SNI_ERROR, "Can't register SNI native resource");
			transformation->close((void*)native_id);
			return_code = MICROEJ_LLSECU_CIPHER_ERROR;
		} 
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code){
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		return_code = (int32_t)(native_id);
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
int32_t LLSEC_RSA_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
									  int32_t buffer_offset, int32_t buffer_length, uint8_t *output,
									  int32_t output_offset) {
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s\n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_transformation* transformation = (LLSEC_RSA_CIPHER_transformation*)transformation_id;
	size_t output_len = 0;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int32_t return_code = transformation->decrypt((void*)native_id, &buffer[buffer_offset], buffer_length, &output[output_offset], &output_len);
	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		return_code = output_len;
	} else {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return_code = SNI_ERROR;
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
int32_t LLSEC_RSA_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
									  int32_t buffer_offset, int32_t buffer_length, uint8_t *output,
									  int32_t output_offset) {
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s\n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_transformation* transformation = (LLSEC_RSA_CIPHER_transformation*)transformation_id;
	size_t output_len = 0;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	int32_t return_code = transformation->encrypt((void*)native_id, &buffer[buffer_offset], buffer_length, &output[output_offset], &output_len);
	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		return_code = output_len;
	} else {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return_code = SNI_ERROR;
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
void LLSEC_RSA_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id) {
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s\n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_transformation* transformation = (LLSEC_RSA_CIPHER_transformation*)transformation_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	transformation->close((void*)native_id);
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	if (SNI_OK != SNI_unregisterResource((void*)native_id, (SNI_closeFunction)transformation->close)) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource");
	}
}

/**
 * @brief Gets the id of the native close function.
 * @param[in] transformation_id            The transformation ID.
 *
 * @return the id of the static native close function.
 *
 * @note Throws NativeException on error.
 */
int32_t LLSEC_RSA_CIPHER_IMPL_get_close_id(int32_t transformation_id) {
	LLSEC_RSA_CIPHER_DEBUG_PRINTF("%s\n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_RSA_CIPHER_transformation* transformation = (LLSEC_RSA_CIPHER_transformation*)transformation_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)transformation->close;
}
