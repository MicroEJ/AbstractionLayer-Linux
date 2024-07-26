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


/**
 * @file
 * @brief LLNET SSL cookie implementation over OpenSSL.
 * @author MicroEJ Developer Team
 * @version 1.0.1
 * @date 27 November 2020
 */

#ifdef __cplusplus
	extern "C" {
#endif

#define COOKIE_SECRET_LENGTH 16

static uint8_t cookie_secret[COOKIE_SECRET_LENGTH];
static int32_t cookie_initialized = 0;

int LLNET_SSL_Generate_Cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    uint8_t *buffer;
    uint32_t length = 0;

    uint16_t port;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

    /* Initialize a random secret */
    if(!cookie_initialized) {
		if(RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH) <= 0) {
			LLNET_SSL_DEBUG_TRACE("error setting random cookie secret\n");
			return 0;
		}
        cookie_initialized = 1;
    }

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
			LLNET_SSL_DEBUG_TRACE("Unknown ss family\n");
			return 0;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if(buffer == NULL) {
		LLNET_SSL_DEBUG_TRACE("out of memory\n");
		return 0;
	}

	switch(peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr, sizeof(struct in6_addr));
			break;
		default:
			LLNET_SSL_DEBUG_TRACE("Unknown ss family\n");
			OPENSSL_free(buffer);
			return 0;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, cookie, cookie_len);
	OPENSSL_free(buffer);
	return 1;
}

/* Verify cookie. Returns 1 on success, 0 otherwise */
int LLNET_SSL_Verify_Cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
	uint8_t result[EVP_MAX_MD_SIZE];
    uint32_t resultlength;

    if(cookie_initialized
        && LLNET_SSL_Generate_Cookie(ssl, result, &resultlength)
        && cookie_len == resultlength
        && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}

#ifdef __cplusplus
	}
#endif
