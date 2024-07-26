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
 * @version 1.3.0
 * @date 15 June 2021
 */


#include <LLSEC_CIPHER_impl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <sni.h>
#include <stdint.h>

#define MICROEJ_LLSECU_CIPHER_SUCCESS 1
#define MICROEJ_LLSECU_CIPHER_ERROR   0
#define AES_CBC_BLOCK_BITS 128u
#define AES_CBC_BLOCK_BYTES AES_CBC_BLOCK_BITS / 8u

// #define LLSEC_CIPHER_DEBUG_TRACE

#ifdef LLSEC_CIPHER_DEBUG_TRACE
#define LLSEC_CIPHER_DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define LLSEC_CIPHER_DEBUG_PRINTF(...) ((void)0)
#endif


/**
 * Cipher init function type
 */
typedef int (*LLSEC_CIPHER_init)(void** native_id, uint8_t is_decrypting, uint8_t* key, int32_t key_length, uint8_t* iv, int32_t iv_length);
typedef int (*LLSEC_CIPHER_decrypt)(void* native_id, uint8_t* buffer, int32_t buffer_length, uint8_t* output);
typedef int (*LLSEC_CIPHER_encrypt)(void* native_id, uint8_t* buffer, int32_t buffer_length, uint8_t* output);
typedef int (*LLSEC_CIPHER_close)(void* native_id);

typedef struct {
    char* name; // the name of the transformation
    LLSEC_CIPHER_init init;
    LLSEC_CIPHER_decrypt decrypt;
    LLSEC_CIPHER_encrypt encrypt;
    LLSEC_CIPHER_close close;
    LLSEC_CIPHER_transformation_desc description;
} LLSEC_CIPHER_transformation;

static int LLSEC_CIPHER_aescbc_init(void** native_id, uint8_t is_decrypting, uint8_t* key, int32_t key_length, uint8_t* iv, int32_t iv_length);
static int openssl_cipher_decrypt(void* native_id, uint8_t* buffer, int32_t buffer_length, uint8_t* output);
static int openssl_cipher_encrypt(void* native_id, uint8_t* buffer, int32_t buffer_length, uint8_t* output);
static int openssl_cipher_close(void* native_id);

static LLSEC_CIPHER_transformation available_transformations[] =
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
    }
};

static int LLSEC_CIPHER_aescbc_init(void** native_id, uint8_t is_decrypting, uint8_t* key, int32_t key_length, uint8_t* iv, int32_t iv_length)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    EVP_CIPHER_CTX *ctx = NULL;
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        // Handle error
        return MICROEJ_LLSECU_CIPHER_ERROR;
    }

    int rc = MICROEJ_LLSECU_CIPHER_ERROR;

    // Key can only be 128, 192,256
    const EVP_CIPHER *cipher_type;
    switch (key_length * 8)
    {
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
        return rc;
    }

    if (is_decrypting)
    {
        rc = EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, iv);
    }
    else
    {
        rc = EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, iv);
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (rc == MICROEJ_LLSECU_CIPHER_SUCCESS)
    {
        // Store ctx address in native_id
        *native_id = (void*)ctx;
    } else
    {
        EVP_CIPHER_CTX_free(ctx);
    }

    return rc;
}

static int openssl_cipher_decrypt(void* native_id, uint8_t* buffer, int32_t buffer_length, uint8_t* output)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;

    int len = 0;
    int rc = EVP_DecryptUpdate(ctx, output, &len, buffer, buffer_length);
    if (MICROEJ_LLSECU_CIPHER_SUCCESS != rc)
    {
        // Handle error
        return rc;
    }

    rc =  EVP_DecryptFinal_ex(ctx, output + len, &len);

    return rc;
}

static int openssl_cipher_encrypt(void* native_id, uint8_t* buffer, int32_t buffer_length, uint8_t* output)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;

    int len = 0;
    int rc =  EVP_EncryptUpdate(ctx, output, &len, buffer, buffer_length);


    if (MICROEJ_LLSECU_CIPHER_SUCCESS != rc)
    {
        // Handle error
        return rc;
    }

    rc =  EVP_EncryptFinal_ex(ctx, output + len, &len);

    return rc;
}

static int openssl_cipher_close(void* native_id)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return MICROEJ_LLSECU_CIPHER_SUCCESS;
}

/**
 * Gets for the given transformation the cipher description.
 *
 * Warning: algorithm_name must not be used outside of the VM task or saved
 *
 * @param transformation Null terminated string that describes the transformation (Warning: must not be used outside of the VM task or saved)
 * @return transformation ID on success or -1 on error.
 */
int32_t LLSEC_CIPHER_IMPL_get_transformation_description(uint8_t* transformation_name, LLSEC_CIPHER_transformation_desc* transformation_desc)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    int32_t nb_transformations = sizeof(available_transformations) / sizeof(LLSEC_CIPHER_transformation);
    LLSEC_CIPHER_transformation* transformation = &available_transformations[0];

    while (--nb_transformations >= 0)
    {
        if (strcmp(transformation_name, transformation->name) == 0)
        {
            memcpy(transformation_desc, &(transformation->description), sizeof(LLSEC_CIPHER_transformation_desc));
            return (int32_t)transformation;
        }
        transformation++;
    }

    // Transformation not found.
    return -1;
}

/**
 * @brief Returns the number of bytes that are buffered internally inside the given cipher.
 *
 * @param[in] nativeTransformationId	The transformation ID.
 * @param[in] nativeId					The resource's native ID.
 *
 * @return The length of the buffer.
 */
int32_t LLSEC_CIPHER_IMPL_get_buffered_length(int32_t nativeTransformationId, int32_t nativeId)
{
	LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)nativeTransformationId;
    return 0;
}

/**
 *  Warning: iv must not be used outside of the VM task or saved
 */
void LLSEC_CIPHER_IMPL_get_IV(int32_t transformation_id, int32_t native_id, uint8_t* iv, int32_t iv_length)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    memcpy(iv, ctx->iv, iv_length);
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
    memcpy(iv, EVP_CIPHER_CTX_iv(ctx), iv_length);
#else
    EVP_CIPHER_CTX_get_updated_iv(ctx, iv, iv_length);
#endif

}

/**
 * Return -1 if no IV, otherwise returns the length of the IV.
 */
int32_t LLSEC_CIPHER_IMPL_get_IV_length(int32_t transformation_id, int32_t native_id)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)native_id;
    int iv_len = EVP_CIPHER_CTX_iv_length(ctx);
    if (iv_len == 0)
    {
        return -1;
    }
    else
    {
        return iv_len;
    }
}

/**
 * Returns a nativeId.
 *
 *  Warning: key must not be used outside of the VM task or saved
 *  Warning: iv must not be used outside of the VM task or saved
 */
int32_t LLSEC_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, uint8_t* key, int32_t key_length, uint8_t* iv, int32_t iv_length)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    void *native_id = NULL;
    LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)transformation_id;

    int returnCode = transformation->init((void**)&native_id, is_decrypting, key, key_length, iv, iv_length);

    if (returnCode != MICROEJ_LLSECU_CIPHER_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
        return -1;
    }

    return (int32_t)(native_id);
}

/**
 *  Warning: buffer must not be used outside of the VM task or saved
 *  Warning: output must not be used outside of the VM task or saved
 */
int32_t LLSEC_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t* buffer, int32_t buffer_offset, int32_t buffer_length, uint8_t* output, int32_t output_offset)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)transformation_id;
    int returnCode = transformation->decrypt((void*)native_id, buffer + buffer_offset, buffer_length, output + output_offset);
    if (returnCode != MICROEJ_LLSECU_CIPHER_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
        return -1;
    }
    return buffer_length;
}


/**
 *  Warning: buffer must not be used outside of the VM task or saved
 *  Warning: output must not be used outside of the VM task or saved
 */
int32_t LLSEC_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t* buffer, int32_t buffer_offset, int32_t buffer_length, uint8_t* output, int32_t output_offset)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)transformation_id;
    int returnCode = transformation->encrypt((void*) native_id, buffer + buffer_offset, buffer_length, output + output_offset);
    if (returnCode != MICROEJ_LLSECU_CIPHER_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
        return -1;
    }
    return buffer_length;
}

void LLSEC_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id)
{
    LLSEC_CIPHER_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_CIPHER_transformation* transformation = (LLSEC_CIPHER_transformation*)transformation_id;
    int returnCode = transformation->close((void*)native_id);
    if (returnCode != MICROEJ_LLSECU_CIPHER_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
    }
}
