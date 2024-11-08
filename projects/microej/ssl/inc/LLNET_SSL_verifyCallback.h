/*
 * C
 *
 * Copyright 2017-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLNET_SSL_VERIFY_CALLBACK
#define LLNET_SSL_VERIFY_CALLBACK
#include <sni.h>
#include <openssl/ssl.h>

/**
 * @file
 * @brief Common LLNET_SSL over OpenSSL header.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 25 July 2024
 */

#ifdef __cplusplus
	extern "C" {
#endif


/*
 * Certificate verification callback
*/
int32_t LLNET_SSL_VERIFY_verifyCallback(int32_t ok, X509_STORE_CTX *ctx);


#ifdef __cplusplus
	}
#endif

#endif
