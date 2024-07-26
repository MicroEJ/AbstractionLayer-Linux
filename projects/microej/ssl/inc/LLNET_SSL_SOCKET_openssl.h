/*
 * C
 *
 * Copyright 2016-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLNET_SSL_SOCKET_OPENSSL
#define LLNET_SSL_SOCKET_OPENSSL
#include <sni.h>

/**
 * @file
 * @brief Common LLNET_SSL over OpenSSL header.
 * @author MicroEJ Developer Team
 * @version 1.0.1
 * @date 27 November 2020
 */

#ifdef __cplusplus
	extern "C" {
#endif

/**
 * Manages asynchronous I/O operations
 */
int32_t LLNET_SSL_SOCKET_asyncOperation(int32_t fd, int32_t operation, uint8_t retry);

#ifdef __cplusplus
	}
#endif

#endif
