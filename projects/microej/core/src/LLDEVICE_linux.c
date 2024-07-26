/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLDEVICE API port for Linux.
 * @author MicroEJ Developer Team
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include "LLDEVICE_linux_configuration.h"
#include "LLDEVICE_impl.h"

#ifdef __cplusplus
	extern "C" {
#endif

#define MAC_ADDRESS_SIZE	6

// Buffer used to cache the ID so we don't need to request it from the system everytime.
static uint8_t	LLDEVICE_IMPL_id_cache[MAC_ADDRESS_SIZE];
// -1 if ID has not been cached, positive value otherwise
static int32_t	LLDEVICE_IMPL_id_cache_length = -1;

static int32_t LLDEVICE_IMPL_getId_linux(uint8_t* buffer, int32_t buffer_size);

uint8_t LLDEVICE_IMPL_getArchitecture(uint8_t* buffer, int32_t length) {
	if (length >= sizeof(LLDEVICE_ARCHITECTURE)) {
		strncpy(buffer, LLDEVICE_ARCHITECTURE, sizeof(LLDEVICE_ARCHITECTURE));
		return 1;
	}
	else {
		return 0;
	}
}

uint32_t LLDEVICE_IMPL_getId(uint8_t* buffer, int32_t length) {

	if(LLDEVICE_IMPL_id_cache_length == -1){
		// First time we are asking for the id: put it in the cache buffer
		int id_length = LLDEVICE_IMPL_getId_linux(LLDEVICE_IMPL_id_cache, sizeof(LLDEVICE_IMPL_id_cache));

		if(id_length < 0){
			// An error occurred: just return an empty buffer
			id_length = 0;
		}
		LLDEVICE_IMPL_id_cache_length = id_length;
	}

	int id_length = LLDEVICE_IMPL_id_cache_length;
 	if(id_length > length){
 		id_length = length;
 	}
	memcpy(buffer, LLDEVICE_IMPL_id_cache, id_length);

	return id_length;
}

/**
 * Fills-in the given buffer with the ID of the device.
 *
 * The ID of the device is the first network interface MAC address found (except loopback).
 *
 * Returns the number of bytes filled on success, a negative value on failure.
 */
static int32_t LLDEVICE_IMPL_getId_linux(uint8_t* buffer, int32_t buffer_size) {
	struct ifreq ifr = {0};
	struct ifconf ifc = {0};
	char buf[1024] = {0};
	int found = 0;

	assert(buffer_size == MAC_ADDRESS_SIZE);

	// verify that socket is working on the target
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
		return -1; // an error occurred
	};

	// get network interfaces
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
		return -2; // an error occurred
	}

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	// iterate on network interfaces and stopped when a MAC address is found
	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't take loopback interface into account
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					found = 1;
					break;
				}
			}
		}
		else {
			return -3; // an error occurred
		}
	}

	if(!found) {
		return -4;
	}

	// fill
	memcpy(buffer, ifr.ifr_hwaddr.sa_data, buffer_size);
	return buffer_size;
}

#ifdef __cplusplus
	}
#endif
