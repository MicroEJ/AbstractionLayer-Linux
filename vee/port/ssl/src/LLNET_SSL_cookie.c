/*
 * C
 *
 * Copyright 2018-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#include <LLNET_SSL_cookie.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <LLNET_SSL_CONSTANTS.h>
#include "LLNET_SSL_util.h"


/**
 * @file
 * @brief LLNET SSL cookie implementation over OpenSSL.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 25 July 2024
 */

#ifdef __cplusplus
	extern "C" {
#endif

#define COOKIE_SECRET_LENGTH 16

static int32_t cookie_initialized = 0;

int LLNET_SSL_Generate_Cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
	int ret = 1;
	uint8_t *buffer;
	uint32_t length = 0;
	int32_t error = 0;
	uint8_t cookie_secret[COOKIE_SECRET_LENGTH];

	uint16_t port;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* Initialize a random secret */
	if(!cookie_initialized) {
		error = RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH);
		if(error <= 0) {
			(void)SNI_throwNativeException(LLNET_SSL_TranslateReturnCode(ssl, error), "Error setting random cookie secret");
			ret = 0;
		} else {
			cookie_initialized = 1;
		}
	}

	if (ret != 0) {
		(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
		length = 0;
		switch(peer.ss.ss_family) {
			case AF_INET:
				length += sizeof(struct in_addr);
				break;
			case AF_INET6:
				length += sizeof(struct in6_addr);
				break;
			default:
				(void)SNI_throwNativeException(LLNET_SSL_TranslateReturnCode(ssl, error), "Unknown ss family");
				ret = 0;
				break;
		}

		if (ret != 0) {
			length += sizeof(in_port_t);
			buffer = (unsigned char*) OPENSSL_malloc(length);

			if(buffer == NULL) {
				(void)SNI_throwNativeException(LLNET_SSL_TranslateReturnCode(ssl, error), "Out of memory");
				ret = 0;
			} else {

				switch(peer.ss.ss_family) {
					case AF_INET:
						(void)memcpy(buffer, (void *)&peer.s4.sin_port, sizeof(in_port_t));
						(void)memcpy(buffer + sizeof(peer.s4.sin_port), (void *)&peer.s4.sin_addr, sizeof(struct in_addr));
						break;
					case AF_INET6:
						(void)memcpy(buffer, (void *)&peer.s6.sin6_port, sizeof(in_port_t));
						(void)memcpy(buffer + sizeof(in_port_t), (void *)&peer.s6.sin6_addr, sizeof(struct in6_addr));
						break;
					default:
						(void)SNI_throwNativeException(LLNET_SSL_TranslateReturnCode(ssl, error), "Unknown ss family");
						OPENSSL_free(buffer);
						ret = 0;
						break;
				}

				if (ret != 0) {
					/* Calculate HMAC of buffer using the secret */
					(void)HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
						(const unsigned char*) buffer, length, cookie, cookie_len);
					OPENSSL_free(buffer);
				}
			}
		}
	}

	return ret;
}

/* Verify cookie. Returns 1 on success, 0 otherwise */
int LLNET_SSL_Verify_Cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
	int ret = 0;
	uint8_t result[EVP_MAX_MD_SIZE];
	uint32_t resultlength;

	if(cookie_initialized
		&& (LLNET_SSL_Generate_Cookie(ssl, result, &resultlength))
		&& (cookie_len == resultlength)
		&& (memcmp(result, cookie, resultlength) == 0)) {
		ret = 1;
	}

	return ret;
}

#ifdef __cplusplus
	}
#endif
