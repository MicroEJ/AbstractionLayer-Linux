/*
 * C
 *
 * Copyright 2017-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include <LLSEC_KEY_FACTORY_impl.h>
#include <sni.h>
#include <string.h>
#include "LLSEC_openssl.h"
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <stdio.h>

#define MICROEJ_LLSECU_KEY_FACTORY_SUCCESS 1
#define MICROEJ_LLSECU_KEY_FACTORY_ERROR   0

// #define LLSEC_KEY_FACTORY_DEBUG_TRACE

#ifdef LLSEC_KEY_FACTORY_DEBUG_TRACE
#define LLSEC_KEY_FACTORY_PRINTF(...) printf(__VA_ARGS__)
#else
#define LLSEC_KEY_FACTORY_PRINTF(...) ((void)0)
#endif


static const char* pkcs8_format = "PKCS#8";

typedef int(*LLSEC_KEY_FACTORY_get_private_key_data)(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length);

typedef struct {
    char* name;
    LLSEC_KEY_FACTORY_get_private_key_data get_private_key_data;
} LLSEC_KEY_FACTORY_algorithm;

static int LLSEC_KEY_FACTORY_RSA_openssl_get_private_key_data(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length);
static int LLSEC_KEY_FACTORY_EC_openssl_get_private_key_data(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length);


static LLSEC_KEY_FACTORY_algorithm available_algorithms[] =
{
    {
        .name = "RSA",
        .get_private_key_data = LLSEC_KEY_FACTORY_RSA_openssl_get_private_key_data
    },
    {
        .name = "EC",
        .get_private_key_data = LLSEC_KEY_FACTORY_EC_openssl_get_private_key_data
    }
};

static int LLSEC_KEY_FACTORY_RSA_openssl_get_private_key_data(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length)
{
    LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);

    priv_key->type = TYPE_RSA;
    // with no call to EVP_PKEY_free this will leak memory
    // A mean to free native memory upon gargbage collection of the associated Java object is required
    priv_key->key = d2i_PrivateKey(EVP_PKEY_RSA, (NULL) , (const unsigned char **)&encoded_key, encoded_key_length);
    if (priv_key->key == NULL)
    {
        // Error
        return MICROEJ_LLSECU_KEY_FACTORY_ERROR;
    }

    return MICROEJ_LLSECU_KEY_FACTORY_SUCCESS;
}

static int LLSEC_KEY_FACTORY_EC_openssl_get_private_key_data(LLSEC_priv_key* priv_key, uint8_t* encoded_key, int32_t encoded_key_length)
{
    LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);

    priv_key->type = TYPE_ECDSA;
    // with no call to EVP_PKEY_free this will leak memory
    // A mean to free native memory upon gargbage collection of the associated Java object is required
    priv_key->key  = d2i_PrivateKey(EVP_PKEY_EC, (NULL) , (const unsigned char **)&encoded_key, encoded_key_length);
    if (priv_key->key == NULL)
    {
        // Error
        return MICROEJ_LLSECU_KEY_FACTORY_ERROR;
    }

    return MICROEJ_LLSECU_KEY_FACTORY_SUCCESS;
}


void LLSEC_KEY_FACTORY_IMPL_get_private_key_data(int32_t algorithm_id, uint8_t* format_name, uint8_t* key_data, int32_t key_data_length, uint8_t* encoded_key, int32_t encoded_key_length)
{
    LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);

    LLSEC_priv_key* private_key = (LLSEC_priv_key*) key_data;
    LLSEC_KEY_FACTORY_algorithm* algorithm = (LLSEC_KEY_FACTORY_algorithm*)algorithm_id;

    if (strcmp(format_name, pkcs8_format) != 0) {
        SNI_throwNativeException(-1, NULL);
    }

    if (key_data_length < sizeof(*private_key)) {
        SNI_throwNativeException(-1, "Invalid buffer length");
        return;
    }

    int returnCode = algorithm->get_private_key_data(private_key, encoded_key, encoded_key_length);

    if (returnCode != MICROEJ_LLSECU_KEY_FACTORY_SUCCESS)
    {
        int err = ERR_get_error();
        SNI_throwNativeException(err, ERR_error_string(err, NULL));
    }
}

int32_t LLSEC_KEY_FACTORY_IMPL_get_algorithm_description(uint8_t* algorithm_name)
{
    LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);
    int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLSEC_KEY_FACTORY_algorithm);
    LLSEC_KEY_FACTORY_algorithm* algorithm = &available_algorithms[0];

    while (--nb_algorithms >= 0)
    {
        if (strcmp(algorithm_name, algorithm->name) == 0)
        {
            return (int32_t)algorithm;
        }
        algorithm++;
    }

    // Algorithm not found.
    return -1;
}

int32_t LLSEC_KEY_FACTORY_IMPL_get_private_key_length(int32_t algorithm_id, uint8_t* format_name, uint8_t* encoded_key, int32_t encoded_key_length) {
    LLSEC_KEY_FACTORY_PRINTF("%s \n", __func__);

    return sizeof(LLSEC_priv_key);
}

