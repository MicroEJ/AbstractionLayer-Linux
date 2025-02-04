/*
 * C
 *
 * Copyright 2019-2024 MicroEJ Corp. All rights reserved.
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

#include <string.h>
#include <sni.h>
#include <stdint.h>

#define MICROEJ_LLSECU_CIPHER_SUCCESS 1
#define MICROEJ_LLSECU_CIPHER_ERROR   0

#define AES_CBC_BLOCK_BITS    (128u)
#define AES_CBC_BLOCK_BYTES   (AES_CBC_BLOCK_BITS / 8u)

#define DES_CBC_BLOCK_BITS    (64u)
#define DES_CBC_BLOCK_BYTES   (DES_CBC_BLOCK_BITS / 8u)

// #define LLSEC_CIPHER_DEBUG_TRACE

#ifdef LLSEC_CIPHER_DEBUG_TRACE
#define LLSEC_CIPHER_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLSEC_CIPHER_DEBUG_PRINTF(...) ((void)0)
#endif

/**
 * Cipher init function type
 */
typedef int (*LLSEC_CIPHER_init)(void** native_id, uint8_t is_decrypting, const uint8_t* key, int32_t key_length, const uint8_t* iv, int32_t iv_length);
typedef int (*LLSEC_CIPHER_decrypt)(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output);
typedef int (*LLSEC_CIPHER_encrypt)(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output);
typedef void (*LLSEC_CIPHER_close)(void* native_id);

typedef struct {
	char* name; // the name of the transformation
	LLSEC_CIPHER_init init;
	LLSEC_CIPHER_decrypt decrypt;
	LLSEC_CIPHER_encrypt encrypt;
	LLSEC_CIPHER_close close;
	LLSEC_CIPHER_transformation_desc description;
} LLSEC_CIPHER_transformation;

static int LLSEC_CIPHER_aescbc_init(void** native_id, uint8_t is_decrypting, const uint8_t* key, int32_t key_length, const uint8_t* iv, int32_t iv_length);
static int LLSEC_CIPHER_des3cbc_init(void** native_id, uint8_t is_decrypting, const uint8_t* key, int32_t key_length, const uint8_t* iv, int32_t iv_length);
static int openssl_cipher_decrypt(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output);
static int openssl_cipher_encrypt(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output);
static void openssl_cipher_close(void* native_id);

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file.
static LLSEC_CIPHER_transformation available_transformations[2] =
{
	{
		.name = "AES/CBC/NoPadding",
		.init = LLSEC_CIPHER_aescbc_init,
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
		.name = "DESede/CBC/NoPadding",
		.init = LLSEC_CIPHER_des3cbc_init,
		.decrypt = openssl_cipher_decrypt,
		.encrypt = openssl_cipher_encrypt,
		.close = openssl_cipher_close,
		{
			.block_size = DES_CBC_BLOCK_BYTES,
			.unit_bytes = DES_CBC_BLOCK_BYTES,
			.cipher_mode = CBC_MODE,
		}
	}
};

static int LLSEC_CIPHER_aescbc_init(void** native_id, uint8_t is_decrypting, const uint8_t* key, int32_t key_length, const uint8_t* iv, int32_t iv_length)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	(void)iv_length;
	int return_code = MICROEJ_LLSECU_CIPHER_SUCCESS;
	const EVP_CIPHER *cipher_type;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (NULL == ctx) {
		return_code = MICROEJ_LLSECU_CIPHER_ERROR;
	}


	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		// Key can only be 128, 192, 256
		switch (key_length * 8) {
		case 128:
			cipher_type = EVP_aes_128_cbc();
			break;
		case 192:
			cipher_type = EVP_aes_192_cbc();
			break;
		case 256:
			cipher_type = EVP_aes_256_cbc();
			break;
		default:
			EVP_CIPHER_CTX_free(ctx);
			return_code = MICROEJ_LLSECU_CIPHER_ERROR;
			break;
		}
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		if ((uint8_t) 1 == is_decrypting) {
			return_code = EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, iv);
		} else {
			return_code = EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, iv);
		}
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		//EVP_CIPHER_CTX_set_padding always returns 1
		(void)EVP_CIPHER_CTX_set_padding(ctx, 0);
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		// Store ctx address in native_id
		*native_id = (void*)ctx;
	} else {
		EVP_CIPHER_CTX_free(ctx);
	}

	return return_code;
}

static int LLSEC_CIPHER_des3cbc_init(void** native_id, uint8_t is_decrypting, const uint8_t* key, int32_t key_length, const uint8_t* iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	(void)key_length;
	(void)iv_length;
	int return_code = MICROEJ_LLSECU_CIPHER_SUCCESS;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (NULL == ctx) {
		return_code = MICROEJ_LLSECU_CIPHER_ERROR;
	}


	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		if ((uint8_t) 1 == is_decrypting) {
			return_code = EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
		} else {
			return_code = EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
		}
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		//EVP_CIPHER_CTX_set_padding always returns 1
		(void)EVP_CIPHER_CTX_set_padding(ctx, 0);
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		// Store ctx address in native_id
		*native_id = (void*)ctx;
	} else {
		EVP_CIPHER_CTX_free(ctx);
	}

	return return_code;
}


static int openssl_cipher_decrypt(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;
	int len = 0;

	int return_code = EVP_DecryptUpdate(ctx, output, &len, buffer, buffer_length);
	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		return_code =  EVP_DecryptFinal_ex(ctx, &output[len], &len);
	}
	return return_code;
}

static int openssl_cipher_encrypt(void* native_id, const uint8_t* buffer, int32_t buffer_length, uint8_t* output)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;
	int len = 0;

	int return_code = EVP_EncryptUpdate(ctx, output, &len, buffer, buffer_length);
	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		return_code =  EVP_EncryptFinal_ex(ctx, &output[len], &len);
	}
	return return_code;
}

static void openssl_cipher_close(void* native_id)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLSEC_CIPHER_IMPL_get_transformation_description(uint8_t* transformation_name, LLSEC_CIPHER_transformation_desc* transformation_desc)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_transformations = sizeof(available_transformations) / sizeof(LLSEC_CIPHER_transformation);
	LLSEC_CIPHER_transformation* transformation = &available_transformations[0];

	while (--nb_transformations >= 0)
	{
		if (0 == strcmp(transformation_name, transformation->name))
		{
			(void)memcpy(transformation_desc, &(transformation->description), sizeof(LLSEC_CIPHER_transformation_desc));
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


int32_t LLSEC_CIPHER_IMPL_get_buffered_length(int32_t nativeTransformationId, int32_t nativeId)
{
	(void)nativeTransformationId;
	(void)nativeId;
	return 0;
}

/**
 *  Warning: iv must not be used outside of the VM task or saved
 */
void LLSEC_CIPHER_IMPL_get_IV(int32_t transformation_id, int32_t native_id, uint8_t* iv, int32_t iv_length)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	(void)transformation_id;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	(void)memcpy(iv, ctx->iv, iv_length);
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
	(void)memcpy(iv, EVP_CIPHER_CTX_iv(ctx), iv_length);
#else
	(void)EVP_CIPHER_CTX_get_updated_iv(ctx, iv, iv_length);
#endif
}

// cppcheck-suppress constParameterPointer // SNI type conflict
void LLSEC_CIPHER_IMPL_set_IV(int32_t transformation_id, int32_t native_id, uint8_t* iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	(void)transformation_id;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	(void)memcpy(ctx->iv, iv, iv_length);
#else
	(void)iv_length;
	(void)EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
#endif
}

int32_t LLSEC_CIPHER_IMPL_get_IV_length(int32_t transformation_id, int32_t native_id)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	(void)transformation_id;
	int32_t return_code = 0;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;
	int iv_len = EVP_CIPHER_CTX_iv_length(ctx);
	if (0 == iv_len) {
		return_code = SNI_ERROR;
	} else {
		return_code = iv_len;
	}
	return return_code;
}

int32_t LLSEC_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, uint8_t* key, int32_t key_length, uint8_t* iv, int32_t iv_length)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	void *native_id = NULL;
	int32_t return_code = MICROEJ_LLSECU_CIPHER_SUCCESS;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)transformation_id;

	return_code = transformation->init((void**)&native_id, is_decrypting, key, key_length, iv, iv_length);
	if (MICROEJ_LLSECU_CIPHER_ERROR == return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_registerResource(native_id, transformation->close, NULL) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
			transformation->close((void*)native_id);
			return_code = MICROEJ_LLSECU_CIPHER_ERROR;
		}
	}

	if (MICROEJ_LLSECU_CIPHER_SUCCESS == return_code) {
		// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
		return_code = (int32_t)(native_id);
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

int32_t LLSEC_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t* buffer, int32_t buffer_offset, int32_t buffer_length, uint8_t* output, int32_t output_offset)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = MICROEJ_LLSECU_CIPHER_SUCCESS;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)transformation_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	return_code = transformation->decrypt((void*)native_id, &buffer[buffer_offset], buffer_length, &output[output_offset]);
	if (MICROEJ_LLSECU_CIPHER_SUCCESS != return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return_code = SNI_ERROR;
	} else {
		return_code = buffer_length;
	}
	return return_code;
}


int32_t LLSEC_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t* buffer, int32_t buffer_offset, int32_t buffer_length, uint8_t* output, int32_t output_offset)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = MICROEJ_LLSECU_CIPHER_SUCCESS;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)transformation_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	return_code = transformation->encrypt((void*) native_id, &buffer[buffer_offset], buffer_length, &output[output_offset]);
	if (MICROEJ_LLSECU_CIPHER_SUCCESS != return_code) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return_code = SNI_ERROR;
	} else {
		return_code = buffer_length;
	}
	return return_code;
}

void LLSEC_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id)
{
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)transformation_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	transformation->close((void*)native_id);
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	if(SNI_unregisterResource((void*)native_id, (SNI_closeFunction) transformation->close) != SNI_OK){
		(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource\n");
	}
}

int32_t LLSEC_CIPHER_IMPL_get_close_id(int32_t transformation_id) {
	LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)transformation_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t) transformation->close;
}
