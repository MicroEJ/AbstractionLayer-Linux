/*
 * C
 *
 * Copyright 2019-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include "LLSEC_MAC_impl.h"

#define MICROEJ_LLSECU_MAC_SUCCESS 1
#define MICROEJ_LLSECU_MAC_ERROR   0

/**
 * @file
 * @brief MicroEJ Security low level API implementation for OpenSSL Library
 * @author MicroEJ Developer Team
 * @version 1.3.0
 * @date 15 June 2021
 */

typedef int (*LLSEC_MAC_init)(void** native_id, uint8_t* key, int32_t key_length);
typedef int (*LLSEC_MAC_update)(void* native_id, uint8_t* buffer, int32_t buffer_length);
typedef int (*LLSEC_MAC_do_final)(void* native_id, uint8_t* out, int32_t out_length);
typedef int (*LLSEC_MAC_reset)(void* native_id);
typedef int (*LLSEC_MAC_close)(void* native_id);

typedef struct {
    char* name;
    LLSEC_MAC_init init;
    LLSEC_MAC_update update;
    LLSEC_MAC_do_final do_final;
    LLSEC_MAC_reset reset;
    LLSEC_MAC_close close;
    LLSEC_MAC_algorithm_desc description;
} LLSEC_MAC_algorithm;

static int LLSEC_MAC_openssl_HmacSha256_init(void** native_id, uint8_t* key, int32_t key_length);
static int LLSEC_MAC_openssl_update(void* native_id, uint8_t* buffer, int32_t buffer_length);
static int LLSEC_MAC_openssl_do_final(void* native_id, uint8_t* out, int32_t out_length);
static int LLSEC_MAC_openssl_reset(void* native_id);
static int LLSEC_MAC_openssl_close(void* native_id);

static LLSEC_MAC_algorithm available_algorithms[] = {

    {
        .name = "HmacSHA256",
        .init = LLSEC_MAC_openssl_HmacSha256_init,
        .update = LLSEC_MAC_openssl_update,
        .do_final = LLSEC_MAC_openssl_do_final,
        .reset = LLSEC_MAC_openssl_reset,
        .close = LLSEC_MAC_openssl_close,
        {
            .mac_length = 32
        }
    }
};

static int LLSEC_MAC_openssl_HmacSha256_init(void** native_id, uint8_t* key, int32_t key_length)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX* ctx = (HMAC_CTX*)OPENSSL_malloc(sizeof(HMAC_CTX));
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
    HMAC_CTX* ctx = HMAC_CTX_new();
#else
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL)
    {
        return MICROEJ_LLSECU_MAC_ERROR;
    }
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
#endif

    if (ctx == NULL)
    {
        //out of memory
        return MICROEJ_LLSECU_MAC_ERROR;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX_init(ctx);
#endif

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    int returnCode = HMAC_Init_ex(ctx, key, key_length, EVP_sha256(), NULL);
#else
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    int returnCode = EVP_MAC_init(ctx, key, key_length, params);
#endif

    if (returnCode != MICROEJ_LLSECU_MAC_SUCCESS)
    {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        HMAC_CTX_cleanup(ctx);
        OPENSSL_free((void*)ctx);
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
        HMAC_CTX_free(ctx);
#else
        EVP_MAC_CTX_free(ctx);
#endif
    }
    else
    {
        //set the context as native id
        (*native_id) = (void*)ctx;
    }

    return returnCode;
}

static int LLSEC_MAC_openssl_update(void* native_id, uint8_t* buffer, int32_t buffer_length)
{
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    HMAC_CTX* ctx = (HMAC_CTX*)(native_id);
    int rc = HMAC_Update(ctx, buffer, buffer_length);
#else
    EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)(native_id);
    int rc = EVP_MAC_update(ctx, buffer, buffer_length);
#endif
    return rc;
}

static int LLSEC_MAC_openssl_do_final(void* native_id, uint8_t* out, int32_t out_length)
{
    unsigned int len;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    HMAC_CTX* ctx = (HMAC_CTX*)(native_id);
    int rc = HMAC_Final(ctx, out, &len);
#else
    EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)(native_id);
    int rc = EVP_MAC_final(ctx, out, &len, out_length);
#endif
    out_length = len;
    return rc;
}

static int LLSEC_MAC_openssl_reset(void* native_id)
{
    HMAC_CTX* ctx = (HMAC_CTX*)(native_id);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX_cleanup(ctx); //HMAC_CTX_cleanup() cleans the ctx and set its memory to 0
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
    HMAC_CTX_reset(ctx);
#else
    // not implemented
#endif
    return MICROEJ_LLSECU_MAC_SUCCESS;
}

static int LLSEC_MAC_openssl_close(void* native_id)
{
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    HMAC_CTX* ctx = (HMAC_CTX*)(native_id);
#else
    EVP_MAC_CTX* ctx = (EVP_MAC_CTX*)(native_id);
#endif
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
#elif (OPENSSL_VERSION_NUMBER < 0x30000000L)
    HMAC_CTX_free(ctx);
#else
    EVP_MAC_CTX_free(ctx);
#endif
    return MICROEJ_LLSECU_MAC_SUCCESS;
}


/**
 * Gets for the given algorithm the message digest description.
 * <p>
 * <code>description</code> must be filled-in with:
 * <ul>
 *  <li>[0-3]: macLength: length of the message digest in bytes</li>
 * </ul>
 *
 * Warning: algorithm_name must not be used outside of the VM task or saved
 *
 * @param algorithm_name Null terminated string that describes the algorithm
 * @return algorithm ID on success or -1 on error.
 */
int32_t LLSEC_MAC_IMPL_get_algorithm_description(uint8_t* algorithm_name, LLSEC_MAC_algorithm_desc* algorithm_desc)
{
    int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLSEC_MAC_algorithm);
    LLSEC_MAC_algorithm* algorithm = &available_algorithms[0];

    while (--nb_algorithms >= 0)
    {
        if (strcmp(algorithm_name, algorithm->name) == 0)
        {
            memcpy(algorithm_desc, &(algorithm->description), sizeof(LLSEC_MAC_algorithm_desc));
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
 * Throw NativeException on error.
 *
 *  Warning: key must not be used outside of the VM task or saved
 */
int32_t LLSEC_MAC_IMPL_init(int32_t algorithm_id, uint8_t* key, int32_t key_length) {
    void* native_id = NULL;
    LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

    int returnCode = algorithm->init(&native_id, key, key_length);

    if (returnCode != MICROEJ_LLSECU_MAC_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
        return -1;
    }
    return (int32_t)native_id;
}

/**
 *  Throw NativeException on error.
 *
 *  Warning: buffer must not be used outside of the VM task or saved
 */
void LLSEC_MAC_IMPL_update(int32_t algorithm_id, int32_t native_id, uint8_t* buffer, int32_t buffer_offset, int32_t buffer_length)
{
    LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

    int returnCode = algorithm->update((void*)native_id, buffer + buffer_offset, buffer_length);

    if (returnCode != MICROEJ_LLSECU_MAC_SUCCESS)
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
void LLSEC_MAC_IMPL_do_final(int32_t algorithm_id, int32_t native_id, uint8_t* out, int32_t out_offset, int32_t out_length)
{
    LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

    int returnCode = algorithm->do_final((void*)native_id, out + out_offset, out_length);

    if (returnCode != MICROEJ_LLSECU_MAC_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
    }
}

void LLSEC_MAC_IMPL_reset(int32_t algorithm_id, int32_t native_id)
{
    LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

    int returnCode = algorithm->reset((void*)native_id);

    if (returnCode != MICROEJ_LLSECU_MAC_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
    }
}

void LLSEC_MAC_IMPL_close(int32_t algorithm_id, int32_t native_id)
{
    LLSEC_MAC_algorithm* algorithm = (LLSEC_MAC_algorithm*)algorithm_id;

    int returnCode = algorithm->close((void*)native_id);

    if (returnCode != MICROEJ_LLSECU_MAC_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
    }
}

