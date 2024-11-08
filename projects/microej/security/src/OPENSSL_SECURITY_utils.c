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

#include "LLSEC_openssl.h"
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

// Initialize openssl algorithm and error string
// Must be called before using any openssl algorithm
void OPENSSL_SECURITY_global_initialize()
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

//#else: The needed resources (algorithms, error strings etc.) are automatically initialized. Explicit initialization is not required.

#endif
}

// clean up openssl algorithm and error string
void OPENSSL_SECURITY_global_clean_up()
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	EVP_cleanup();
	ERR_free_strings();

//#else algorithms and error strings are automatically de-initialized

#endif
}
