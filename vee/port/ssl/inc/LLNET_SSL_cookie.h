/*
 * C
 *
 * Copyright 2018-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLNET_SSL_COOKIE_CALLBACK
#define LLNET_SSL_COOKIE_CALLBACK
#include <sni.h>
#include <openssl/ssl.h>

/**
 * @file
 * @brief LLNET SSL cookie OpenSSL header.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 25 July 2024
 */

#ifdef __cplusplus
	extern "C" {
#endif

int LLNET_SSL_Generate_Cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);

/* Verify cookie. Returns 1 on success, 0 otherwise */
int LLNET_SSL_Verify_Cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);

#ifdef __cplusplus
	}
#endif

#endif
