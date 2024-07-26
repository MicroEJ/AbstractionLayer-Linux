/*
 * C
 *
 * Copyright 2017-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include <LLSEC_SIG_impl.h>
#include <LLSEC_openssl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sni.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define MICROEJ_LLSECU_SIGNATURE_INVALID 2
#define MICROEJ_LLSECU_SIG_SUCCESS 1
#define MICROEJ_LLSECU_SIG_ERROR   0

/**
 * @file
 * @brief MicroEJ Security low level API implementation for CycurLIB library
 * @author MicroEJ Developer Team
 * @version 1.3.0
 * @date 15 June 2021
 */

// #define LLSEC_SIG_DEBUG_TRACE

#ifdef LLSEC_SIG_DEBUG_TRACE
#define LLSEC_SIG_DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define LLSEC_SIG_DEBUG_PRINTF(...) ((void)0)
#endif


typedef struct LLSEC_SIG_algorithm LLSEC_SIG_algorithm;
typedef int (*LLSEC_SIG_verify)(LLSEC_SIG_algorithm* algorithm, uint8_t* signature, int32_t signature_length, LLSEC_pub_key* pub_key, int32_t key_length, uint8_t* digest, int32_t digest_length);
typedef int (*LLSEC_SIG_sign)(LLSEC_SIG_algorithm* algorithm, uint8_t* signature, int32_t* signature_length, LLSEC_priv_key* priv_key, int32_t key_length, uint8_t* digest, int32_t digest_length);

struct LLSEC_SIG_algorithm {
    char* name;
    char* digest_name;
    char* digest_native_name;
    LLSEC_SIG_verify verify;
    LLSEC_SIG_sign sign;
};

static int LLSEC_SIG_openssl_verify(LLSEC_SIG_algorithm* algorithm, uint8_t* signature, int32_t signature_length, LLSEC_pub_key* pub_key, int32_t key_length, uint8_t* digest, int32_t digest_length);
static int LLSEC_SIG_openssl_sign(LLSEC_SIG_algorithm* algorithm, uint8_t* signature, int32_t* signature_length, LLSEC_priv_key* priv_key, int32_t key_length, uint8_t* digest, int32_t digest_length);

static LLSEC_SIG_algorithm available_algorithms[] = {
    {
        .name = "SHA256withRSA",
        .digest_name = "SHA-256",
        .digest_native_name = "SHA256",
        .verify = LLSEC_SIG_openssl_verify,
        .sign = LLSEC_SIG_openssl_sign
    },
    {
        .name = "SHA256withECDSA",
        .digest_name = "SHA-256",
        .digest_native_name = "SHA256",
        .verify = LLSEC_SIG_openssl_verify,
        .sign = LLSEC_SIG_openssl_sign
    }
};


static int LLSEC_SIG_openssl_verify(LLSEC_SIG_algorithm* algorithm, uint8_t* signature, int32_t signature_length, LLSEC_pub_key* pub_key, int32_t key_length, uint8_t* digest, int32_t digest_length)
{
    LLSEC_SIG_DEBUG_PRINTF("%s \n", __func__);
    EVP_PKEY_CTX* ctx = NULL;
    int result = MICROEJ_LLSECU_SIG_ERROR;
    do {
        ctx = EVP_PKEY_CTX_new(pub_key->key, NULL);
        if (ctx == NULL)
        {
            // Context init failed
            LLSEC_SIG_DEBUG_PRINTF("EVP_PKEY_CTX_new failed");
            break;
        }

        int rc = EVP_PKEY_verify_init(ctx);
        if (rc != 1)
        {
            // Verify init failed
            LLSEC_SIG_DEBUG_PRINTF("EVP_PKEY_verify_init failed");
            break;
        }

        rc = EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(algorithm->digest_native_name));
        if (rc != 1)
        {
            // Set signature method failed
            LLSEC_SIG_DEBUG_PRINTF("EVP_PKEY_CTX_set_signature_md failed");
            break;
        }

        rc  = EVP_PKEY_verify(ctx, signature, signature_length, digest, digest_length);
        if (rc == 0)
        {
            result == MICROEJ_LLSECU_SIGNATURE_INVALID;
            break;
        }
        else if (rc != 1)
        {
            // Verify signature  failed
            break;
        }

        result = MICROEJ_LLSECU_SIG_SUCCESS;
    } while (0);

    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    // Memory of pub->key is allocated in KEY_FACTORY and stored in a Java object but never freed
    // Calling EVP_PKEY_free here solve the memory leak problem BUT makes the Java object Key not reusable which is not acceptable
    // EVP_PKEY_free(pub_key->key);

    return result;
}

static int LLSEC_SIG_openssl_sign(LLSEC_SIG_algorithm* algorithm, uint8_t* signature, int32_t* signature_length, LLSEC_priv_key* priv_key, int32_t key_length, uint8_t* digest, int32_t digest_length)
{
    LLSEC_SIG_DEBUG_PRINTF("%s \n", __func__);
    EVP_PKEY_CTX *ctx;
    int result = MICROEJ_LLSECU_SIG_ERROR;

    do {
        ctx = EVP_PKEY_CTX_new(priv_key->key, NULL);
        if (ctx == NULL)
        {
            // Init context failed
            LLSEC_SIG_DEBUG_PRINTF("EVP_PKEY_CTX_new failed");
            break; /* failed */
        }

        int rc = EVP_PKEY_sign_init(ctx);
        if (rc != 1)
        {
            // Sign init failed
            LLSEC_SIG_DEBUG_PRINTF("EVP_PKEY_verify_init failed");
            break;
        }

        rc = EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(algorithm->digest_native_name));
        if (rc != 1)
        {
            LLSEC_SIG_DEBUG_PRINTF("EVP_PKEY_CTX_set_signature_md failed");
            break;
        }

        // First sign gives size of signature
        rc  = EVP_PKEY_sign(ctx, NULL, signature_length, digest, digest_length);
        if (rc != 1)
        {
            LLSEC_SIG_DEBUG_PRINTF("First EVP_PKEY_sign failed");
            break;
        }

        // Second sign actually signs the data
        rc  = EVP_PKEY_sign(ctx, signature, signature_length, digest, digest_length);
        if (rc != 1)
        {
            LLSEC_SIG_DEBUG_PRINTF("Second EVP_PKEY_sign failed");
            break;
        }

        result = MICROEJ_LLSECU_SIG_SUCCESS;
    } while (0);

    // Clean memory
    if (ctx)
    {
        EVP_PKEY_CTX_free(ctx);
    }
    // Memory of pub->key is allocated in KEY_FACTORY and stored in a Java object but never freed
    // Calling EVP_PKEY_free here solve the memory leak problem BUT makes the Java object Key not reusable which is not acceptable
    // EVP_PKEY_free(priv_key->key);

    return result;
}

/**
 * Gets for the given algorithm the message digest description.
 * <p>
 * <code>description</code> must be filled-in with:
 * <ul>
 *  <li>TODO: remove?</li>
 * </ul>
 *
 * Warning: algorithm_name must not be used outside of the VM task or saved
 *
 * @param algorithm_name Null terminated string that describes the algorithm
 * @return algorithm ID on success or -1 on error.
 */
int32_t LLSEC_SIG_IMPL_get_algorithm_description(uint8_t* algorithm_name, uint8_t* digest_algorithm_name, int32_t digest_algorithm_name_length) {
    LLSEC_SIG_DEBUG_PRINTF("%s \n", __func__);
    int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLSEC_SIG_algorithm);
    LLSEC_SIG_algorithm* algorithm = &available_algorithms[0];

    while (--nb_algorithms >= 0)
    {
        if (strcmp(algorithm_name, algorithm->name) == 0)
        {
            strncpy(digest_algorithm_name, algorithm->digest_name, digest_algorithm_name_length);
            // strncpy result may not be null-terminated.
            digest_algorithm_name[digest_algorithm_name_length - 1] = '\0';
            return (int32_t)algorithm;
        }
        algorithm++;
    }

// Algorithm not found.
    return -1;
}

/**
 * Warning: signature must not be used outside of the VM task or saved
 * Warning: key must not be used outside of the VM task or saved
 * Warning: digest must not be used outside of the VM task or saved
 *
 */
uint8_t LLSEC_SIG_IMPL_verify(int32_t algorithm_id, uint8_t* signature, int32_t signature_length, uint8_t* key, int32_t key_length, uint8_t* digest, int32_t digest_length)
{
    LLSEC_SIG_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_SIG_algorithm* algorithm = (LLSEC_SIG_algorithm*)algorithm_id;

    int returnCode = algorithm->verify(algorithm, signature, signature_length, (LLSEC_pub_key*) key, key_length, digest, digest_length);

    if (returnCode == MICROEJ_LLSECU_SIG_SUCCESS)
    {
        return JTRUE;
    }
    else if (returnCode == MICROEJ_LLSECU_SIGNATURE_INVALID)
    {
        return JFALSE;
    }

    int err = ERR_get_error();
    SNI_throwNativeException(err, ERR_error_string(err, NULL));
    return -1;
}

int32_t LLSEC_SIG_IMPL_sign(int32_t algorithm_id, uint8_t* signature, int32_t signature_length, uint8_t* key, int32_t key_length, uint8_t* digest, int32_t digest_length)
{
    LLSEC_SIG_DEBUG_PRINTF("%s \n", __func__);
    LLSEC_SIG_algorithm* algorithm = (LLSEC_SIG_algorithm*)algorithm_id;

    int returnCode = algorithm->sign(algorithm, signature, &signature_length, (LLSEC_priv_key*)key, key_length, digest, digest_length);

    if (returnCode != MICROEJ_LLSECU_SIG_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
        return JFALSE;
    }

    return signature_length;
}
