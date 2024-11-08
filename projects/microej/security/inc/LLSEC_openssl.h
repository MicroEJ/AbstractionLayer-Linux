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

#ifndef LLSEC_OPENSSL_H
#define LLSEC_OPENSSL_H

#include "openssl/evp.h"

#ifdef __cplusplus
	extern "C" {
#endif

typedef enum {
    TYPE_RSA = EVP_PKEY_RSA,
    TYPE_ECDSA = EVP_PKEY_EC,
} LLSEC_pub_key_type;

typedef struct {
    LLSEC_pub_key_type type;
    EVP_PKEY *key;
} LLSEC_priv_key;

typedef struct {
    LLSEC_pub_key_type type;
    EVP_PKEY *key;
} LLSEC_pub_key;

typedef struct {
    unsigned char* key;
    int32_t        key_length;
} LLSEC_secret_key;

typedef enum {
    LLSEC_MD_SHA1,
    LLSEC_MD_SHA224,
    LLSEC_MD_SHA256,
    LLSEC_MD_SHA384,
    LLSEC_MD_SHA512
} LLSEC_md_type;

//keep backward compatibility
#define openssl_security_global_initialize OPENSSL_SECURITY_global_initialize

// Initialize openssl algorithm and error string
// Must be called before using any openssl algorithm
void OPENSSL_SECURITY_global_initialize(void);

// clean up openssl algorithm and error string
void OPENSSL_SECURITY_global_clean_up(void);

#ifdef __cplusplus
	}
#endif

#endif /* LLSEC_OPENSLL_H */
