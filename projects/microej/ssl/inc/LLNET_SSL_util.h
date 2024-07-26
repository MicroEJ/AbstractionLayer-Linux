/*
 * C
 *
 * Copyright 2016-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLNET_SSL_UTIL
#define LLNET_SSL_UTIL

#include <openssl/ssl.h>
#include <stdint.h>
#include <LLNET_SSL_CONSTANTS.h>

 /**
 * @file
 * @brief LLNET_SSL_X509_CERT implementation over OpenSSL header.
 * @author MicroEJ Developer Team
 * @version 1.0.1
 * @date 27 November 2020
 */

#ifdef __cplusplus
	extern "C" {
#endif

/**
 * Creates an X509 certificate from the given certificate data pointed by cert.
 * Stores in format the format of the certificate (CERT_PEM_FORMAT or CERT_DER_FORMAT).
 *
 * format may be null.
 *
 * Returns the created X509 or null on error.
 */
X509* LLNET_SSL_X509_CERT_create(uint8_t *cert, int32_t off, int32_t len, int32_t* format);

#ifdef LLNET_SSL_DEBUG

/** Print OpenSSL's error stack. */
#define LLNET_SSL_DEBUG_PRINT_ERR 	LLNET_SSL_print_errors
void LLNET_SSL_print_errors();

#else

#define LLNET_SSL_DEBUG_PRINT_ERR(...) ((void) 0)

#endif


#ifdef __cplusplus
	}
#endif

#endif
