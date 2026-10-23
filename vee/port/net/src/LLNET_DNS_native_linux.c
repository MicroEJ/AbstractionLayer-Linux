/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLNET_DNS 2.1.0 implementation over Linux.
 * @author MicroEJ Developer Team
 * @version 3.0.0
 * @date 23 July 2024
 */

#include <LLNET_DNS_impl.h>

#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "LLNET_ERRORS.h"
#include "LLNET_Common.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLNET_LOG_MODULE_NAME, LLNET_LOG_LEVEL)

#ifdef __cplusplus
extern "C" {
#endif

int32_t LLNET_DNS_IMPL_getHostByAddr(int8_t *address, int32_t address_length, uint8_t *hostname,
                                     int32_t hostname_length) {
	int32_t result = J_EHOSTUNKNOWN;
	const struct hostent *host = NULL;
	if (address_length == 4) {
		/* Resolve the address */
		host = gethostbyaddr(address, address_length, AF_INET);
		if (host != NULL) {
			(void)memcpy(hostname, host->h_name, hostname_length);
			result = hostname_length;
		}
	}
	VEEPORT_LOGGER_LOG_DBG("(address_length=%d), host=%s, result=%d", address_length,
	                       (NULL != host) ? host->h_name : "<unresolved>", result);
	return result;
}

int32_t LLNET_DNS_IMPL_getHostByNameAt(int32_t index, uint8_t *hostname, int32_t hostname_length, int8_t *address,
                                       int32_t address_length) {
	(void)hostname_length;
	VEEPORT_LOGGER_LOG_DBG("host ->%s<- index = %d", (unsigned char *)hostname, index);

	int r;
	struct addrinfo hints = { 0 };
	struct addrinfo *addrinfos;
	const void *ptr = NULL;
	int32_t addrLength = 0;
	int32_t indexCounter = 0;
	int32_t res = J_EHOSTUNKNOWN;

	// Set the hints address structure with the type of IP address we need

#if LLNET_AF == LLNET_AF_IPV4 // only IPv4
	hints.ai_family = AF_INET;
#endif

#if LLNET_AF == LLNET_AF_IPV6 //only IPv6
	hints.ai_family = AF_INET6;
#endif

	// IPv4+IPv6 configuration: request addresses for any address family
#if LLNET_AF == LLNET_AF_DUAL
	//either IPv4 or IPv6
	hints.ai_family = AF_UNSPEC;
	// allow to map on IPv4 if no IPv6 available
	hints.ai_flags = AI_V4MAPPED;
#endif

	r = getaddrinfo((char *)hostname, NULL, &hints, &addrinfos);
	if (r != 0) {
		VEEPORT_LOGGER_LOG_DBG("getaddrinfo() returned %d: %s", r, gai_strerror(r));
		VEEPORT_ERRORS_throw_caught_exception(J_EHOSTUNKNOWN);
		res = SNI_IGNORED_RETURNED_VALUE;
	}

	// Find the right address
	const struct addrinfo *current_addrinfo = addrinfos;
	while ((NULL != current_addrinfo) && (indexCounter != index)) {
		indexCounter++;
		current_addrinfo = current_addrinfo->ai_next;
	}

	if (NULL != current_addrinfo) {
#if LLNET_AF & LLNET_AF_IPV4
		if (current_addrinfo->ai_family == AF_INET) {
			ptr = &((struct sockaddr_in *)current_addrinfo->ai_addr)->sin_addr;
			addrLength = sizeof(in_addr_t);
		}
#endif
#if LLNET_AF & LLNET_AF_IPV6
		if (current_addrinfo->ai_family == AF_INET6) {
			ptr = &((struct sockaddr_in6 *)current_addrinfo->ai_addr)->sin6_addr;
			addrLength = sizeof(struct in6_addr);
		}
#endif
		if (ptr != NULL) {
			size_t copy_size = 0;
			// Check maximum length that can be copied in destination buffer.
			if (addrLength <= address_length) {
				copy_size = addrLength;
			} else {
				copy_size = address_length;
			}
			(void)memcpy(address, ptr, copy_size);
			res = copy_size;
		}
	}
	freeaddrinfo(addrinfos);
	if (0 >= res) {
		VEEPORT_LOGGER_LOG_DBG("getaddrinfo(): no usable address");
		VEEPORT_ERRORS_throw_caught_exception(J_EHOSTUNKNOWN);
		res = SNI_IGNORED_RETURNED_VALUE;
	}
	return res;
}

int32_t LLNET_DNS_IMPL_getHostByNameCount(uint8_t *hostname, int32_t hostname_length) {
	(void)hostname_length;
	VEEPORT_LOGGER_LOG_DBG("host ->%s<-", (unsigned char *)hostname);

	int r;
	struct addrinfo hints = { 0 };
	struct addrinfo *addrinfos;
	unsigned int counter = 0;

	// Set the hints address structure with the type of IP address we need

#if LLNET_AF == LLNET_AF_IPV4 // only IPv4
	hints.ai_family = AF_INET;
#endif

#if LLNET_AF == LLNET_AF_IPV6 //only IPv6
	hints.ai_family = AF_INET6;
#endif

	// IPv4+IPv6 configuration: request addresses for any address family
#if LLNET_AF == LLNET_AF_DUAL
	//either IPv4 or IPv6
	hints.ai_family = AF_UNSPEC;
	// allow to map on IPv4 if no IPv6 available
	hints.ai_flags = AI_V4MAPPED;
#endif

	r = getaddrinfo((char *)hostname, NULL, &hints, &addrinfos);
	if (r != 0) {
		VEEPORT_LOGGER_LOG_DBG("getaddrinfo(hostname) returned %d: %s", r, gai_strerror(r));
		VEEPORT_ERRORS_throw_caught_exception(J_EHOSTUNKNOWN);
		counter = SNI_IGNORED_RETURNED_VALUE;
		addrinfos = NULL;
	}

	// Count the number of entries
	struct addrinfo *current_addrinfo = addrinfos;
	while (NULL != current_addrinfo) {
		++counter;
		current_addrinfo = current_addrinfo->ai_next;
	}

	VEEPORT_LOGGER_LOG_DBG("host count = %d", counter);

	freeaddrinfo(addrinfos);

	return counter;
}

#ifdef __cplusplus
}
#endif
