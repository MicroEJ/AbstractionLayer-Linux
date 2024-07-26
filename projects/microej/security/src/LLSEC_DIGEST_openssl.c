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


#include <LLSEC_DIGEST_impl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <string.h>
#include <sni.h>
#include <stdint.h>

#define MICROEJ_LLSECU_DIGEST_SUCCESS 1
#define MICROEJ_LLSECU_DIGEST_ERROR   0

// #define LLSEC_DIGEST_DEBUG_TRACE

#ifdef LLSEC_DIGEST_DEBUG_TRACE
#define LLSEC_DIGEST_DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define LLSEC_DIGEST_DEBUG_PRINTF(...) ((void)0)
#endif


typedef int (*LLSEC_DIGEST_init)(void** native_id);
typedef int (*LLSEC_DIGEST_update)(void* native_id, uint8_t* buffer, int32_t buffer_length);
typedef int (*LLSEC_DIGEST_digest)(void* native_id, uint8_t* out, int32_t* out_length);
typedef int (*LLSEC_DIGEST_close)(void* native_id);

/*
 * LL-API related functions & struct
 */
typedef struct {
    char* name;
    LLSEC_DIGEST_init init;
    LLSEC_DIGEST_update update;
    LLSEC_DIGEST_digest digest;
    LLSEC_DIGEST_close close;
    LLSEC_DIGEST_algorithm_desc description;
} LLSEC_DIGEST_algorithm;

static int openssl_digest_update(void* native_id, uint8_t* buffer, int32_t buffer_length);
static int openssl_digest_digest(void* native_id, uint8_t* out, int32_t* out_length);
static int openssl_digest_close(void* native_id);
static int LLSEC_DIGEST_SHA256_init(void** native_id);
static int LLSEC_DIGEST_SHA512_init(void** native_id);

static LLSEC_DIGEST_algorithm available_algorithms[] = {
    {
        .name   = "SHA-256",
        .init   = LLSEC_DIGEST_SHA256_init,
        .update = openssl_digest_update,
        .digest = openssl_digest_digest,
        .close  = openssl_digest_close,
        {
            .digest_length = SHA256_DIGEST_LENGTH
        }
    },
    {
        .name   = "SHA-512",
        .init   = LLSEC_DIGEST_SHA512_init,
        .update = openssl_digest_update,
        .digest = openssl_digest_digest,
        .close  = openssl_digest_close,
        {
            .digest_length = SHA512_DIGEST_LENGTH
        }
    }
};

/*
 * Generic openssl function
 */
static int openssl_digest_update(void* native_id, uint8_t* buffer, int32_t buffer_length)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);

    EVP_MD_CTX* md_ctx  = (EVP_MD_CTX*)native_id;
    int rc = EVP_DigestUpdate(md_ctx, buffer, buffer_length);

    return rc;
}

static int openssl_digest_digest(void* native_id, uint8_t* out, int32_t* out_length)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);

    EVP_MD_CTX* md_ctx  = (EVP_MD_CTX*)native_id;
    int rc = EVP_DigestFinal_ex(md_ctx, out, out_length);

    return rc;
}

static int openssl_digest_close(void* native_id)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);

    EVP_MD_CTX* md_ctx  = (EVP_MD_CTX*)native_id;
    // Memory deallocation
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EVP_MD_CTX_destroy(md_ctx); //EVP_MD_CTX_destroy() cleans the ctx before releasing it
#else
    EVP_MD_CTX_free(md_ctx);
#endif

    return 1;
}

/*
 * Specific sha-256 function
 */
static int LLSEC_DIGEST_SHA256_init(void** native_id)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);

    // Memory allocation
    EVP_MD_CTX* md_ctx  = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        return MICROEJ_LLSECU_DIGEST_ERROR;
    }

    int rc = EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);

    if (rc == MICROEJ_LLSECU_DIGEST_SUCCESS)
    {
        *native_id = md_ctx;
    }
    else
    {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    	EVP_MD_CTX_destroy(md_ctx);
#else
    	EVP_MD_CTX_free(md_ctx);
#endif

    }

    return rc;
}

/*
 * Specific sha-512 function
 */
static int LLSEC_DIGEST_SHA512_init(void** native_id)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);

    // Memory allocation
    EVP_MD_CTX* md_ctx  = EVP_MD_CTX_create();
    if (md_ctx == NULL)
    {
        return MICROEJ_LLSECU_DIGEST_ERROR;
    }

    int rc = EVP_DigestInit_ex(md_ctx, EVP_sha512(), NULL);

    if (rc == MICROEJ_LLSECU_DIGEST_SUCCESS)
    {
        *native_id = md_ctx;
    }
    else
    {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	EVP_MD_CTX_destroy(md_ctx);
#else
    EVP_MD_CTX_free(md_ctx);
#endif
    }

    return rc;
}

/**
 * Gets for the given algorithm the message digest description.
 * <p>
 *
 * Warning: algorithm_name must not be used outside of the VM task or saved
 *
 * @return algorithm ID on success or -1 on error.
 */
int32_t LLSEC_DIGEST_IMPL_get_algorithm_description(uint8_t* algorithm_name, LLSEC_DIGEST_algorithm_desc* algorithm_desc)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);
    int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLSEC_DIGEST_algorithm);
    LLSEC_DIGEST_algorithm* algorithm = &available_algorithms[0];

    while (--nb_algorithms >= 0)
    {
        if (strcmp(algorithm_name, algorithm->name) == 0)
        {
            memcpy(algorithm_desc, &(algorithm->description), sizeof(LLSEC_DIGEST_algorithm_desc));
            return (int32_t)algorithm;
        }
        algorithm++;
    }

    // Algorithm not found.
    return -1;
}

/**
 * Returns a nativeId.
 *
 *  Warning: key must not be used outside of the VM task or saved
 *  Warning: iv must not be used outside of the VM task or saved
 */
int32_t LLSEC_DIGEST_IMPL_init(int32_t algorithm_id)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);
    void* native_id = NULL;
    LLSEC_DIGEST_algorithm* algorithm = (LLSEC_DIGEST_algorithm*)algorithm_id;

    int returnCode = algorithm->init((void**)&native_id);

    if (returnCode != MICROEJ_LLSECU_DIGEST_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
        return -1;
    }
    return (int32_t)native_id;
}

/**
 *
 * Throw NativeException on error.
 */
void LLSEC_DIGEST_IMPL_close(int32_t algorithm_id, int32_t native_id)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_DIGEST_algorithm* algorithm = (LLSEC_DIGEST_algorithm*)algorithm_id;
    int returnCode = algorithm->close((void*)native_id);

    if (returnCode != MICROEJ_LLSECU_DIGEST_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
    }
}


/**
 *  Throw NativeException on error.
 *
 *  Warning: out must not be used outside of the VM task or saved
 */
void LLSEC_DIGEST_IMPL_digest(int32_t algorithm_id, int32_t native_id, uint8_t* out, int32_t out_offset, int32_t out_length)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_DIGEST_algorithm* algorithm = (LLSEC_DIGEST_algorithm*)algorithm_id;
    int len;
    int returnCode = algorithm->digest((void*)native_id, out + out_offset, &len);

    if (returnCode != MICROEJ_LLSECU_DIGEST_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
    }
}

/**
 *  Throw NativeException on error.
 *
 *  Warning: buffer must not be used outside of the VM task or saved
 */
void LLSEC_DIGEST_IMPL_update(int32_t algorithm_id, int32_t native_id, uint8_t* buffer, int32_t buffer_offset, int32_t buffer_length)
{
    LLSEC_DIGEST_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_DIGEST_algorithm* algorithm = (LLSEC_DIGEST_algorithm*)algorithm_id;
    int returnCode = algorithm->update((void*)native_id, buffer + buffer_offset, buffer_length);

    if (returnCode != MICROEJ_LLSECU_DIGEST_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
    }
}

