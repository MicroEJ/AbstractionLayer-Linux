/*
 * C
 *
 * Copyright 2019-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

#ifndef __LLSEC_OPENSSL___
#define __LLSEC_OPENSSL__

#include "openssl/evp.h"

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

// Initialize openssl algorithm and error string
// Must be called before using any openssl algorithm
void OPENSSL_SECURITY_global_initialize();

// clean up openssl algorithm and error string
void OPENSSL_SECURITY_global_clean_up();

#endif /* __LLSEC_OPENSLL__ */
