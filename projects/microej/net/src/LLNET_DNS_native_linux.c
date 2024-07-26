/*
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLNET_DNS 2.1.0 implementation over Linux.
 * @author MicroEJ Developer Team
 * @version 2.0.3
 * @date 27 November 2020
 */

#include <LLNET_DNS_impl.h>

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "LLNET_CONSTANTS.h"
#include "LLNET_ERRORS.h"
#include "LLNET_Common.h"

#ifdef __cplusplus
	extern "C" {
#endif

int32_t LLNET_DNS_IMPL_getHostByAddr(int8_t* inOut, int32_t offset, int32_t length, uint8_t retry)
{
	LLNET_DEBUG_TRACE("%s\n", __func__);
	struct hostent * host;
	if(length == 4) {
		/* Resolve the address */
		host = gethostbyaddr(inOut, length, AF_INET);
		if(host != NULL){
			memcpy(inOut+offset, host->h_name, host->h_length);
			return host->h_length;
		}
	}
	return J_EHOSTUNKNOWN;
}

int32_t LLNET_DNS_IMPL_getHostByNameAt(int32_t index, int8_t* inOut, int32_t offset, int32_t length, uint8_t retry)
{
	LLNET_DEBUG_TRACE("%s host ->%s<- index = %d\n", __func__,(unsigned char *)inOut+offset, index);
	struct hostent *hret;

	int r;
	struct addrinfo hints =  {0};
	struct addrinfo* addrinfos;
	void *ptr = NULL;
	int32_t addrLength = 0;
	unsigned int indexCounter = 0;

	// Set the hints address structure with the type of IP address we need

// If IPv6 or IPv4+IPv6 configuration, then use IPv6. Otherwise (only IPv4 configuration) use IPv4.
#if LLNET_AF & LLNET_AF_IPV6
	hints.ai_family = AF_INET6;

#if LLNET_AF == LLNET_AF_DUAL
	// allow to map on IPv4 if no IPv6 available
	hints.ai_flags = AI_V4MAPPED;
#endif

#else // only IPv4
	hints.ai_family = AF_INET;
#endif

	r = getaddrinfo(inOut+offset, NULL, &hints, &addrinfos);
	LLNET_DEBUG_TRACE("%s getaddrinfo(inOut) returned %d\n", __func__, r);
	if(r != 0){
		return J_EHOSTUNKNOWN;
	}

	// Find the right address
	struct addrinfo* current_addrinfo = addrinfos;
	while (current_addrinfo && indexCounter != index) {
		indexCounter++;
		current_addrinfo = current_addrinfo->ai_next;
	}

	int res = J_EHOSTUNKNOWN;
	if(current_addrinfo){
#if LLNET_AF & LLNET_AF_IPV4
		if(current_addrinfo->ai_family == AF_INET) {
			ptr = &((struct sockaddr_in *) current_addrinfo->ai_addr)->sin_addr;
			addrLength = sizeof(in_addr_t);
		}
#endif
#if LLNET_AF & LLNET_AF_IPV6
		if(current_addrinfo->ai_family == AF_INET6) {
			ptr = &((struct sockaddr_in6 *) current_addrinfo->ai_addr)->sin6_addr;
			addrLength = sizeof(struct in6_addr);
		}
#endif
		if (ptr != NULL) {
			int bufferLength = SNI_getArrayLength(inOut) - offset;
			if(addrLength <= bufferLength){
				memcpy(inOut + offset, ptr, addrLength);
				res = addrLength;
			}
		}
	}
	freeaddrinfo(addrinfos);
	return res;
}

int32_t LLNET_DNS_IMPL_getHostByNameCount(int8_t* hostname, int32_t offset, int32_t length, uint8_t retry)
{
	LLNET_DEBUG_TRACE("%s host ->%s<- \n", __func__,(unsigned char *)hostname+offset);
	struct hostent *hret;

	int r;
	struct addrinfo hints =  {0};
	struct addrinfo* addrinfos;
	unsigned int counter = 0;

	// Set the hints address structure with the type of IP address we need

// If IPv6 or IPv4+IPv6 configuration, then use IPv6. Otherwise (only IPv4 configuration) use IPv4.
#if LLNET_AF & LLNET_AF_IPV6
	hints.ai_family = AF_INET6;

#if LLNET_AF == LLNET_AF_DUAL
	// allow to map on IPv4 if no IPv6 available
	hints.ai_flags = AI_V4MAPPED;
#endif

#else // only IPv4
	hints.ai_family = AF_INET;
#endif

	r = getaddrinfo(hostname+offset, NULL, &hints, &addrinfos);
	LLNET_DEBUG_TRACE("%s getaddrinfo(hostname) returned %d\n", __func__, r);
	if(r != 0){
		return J_EHOSTUNKNOWN;
	}

	// Count the number of entries
	struct addrinfo* current_addrinfo = addrinfos;
	while (current_addrinfo) {
		++counter;
		current_addrinfo = current_addrinfo->ai_next;
	}

	LLNET_DEBUG_TRACE("%s host count = %d\n", __func__,counter);

	freeaddrinfo(addrinfos);

	return counter;
}

#ifdef __cplusplus
	}
#endif

