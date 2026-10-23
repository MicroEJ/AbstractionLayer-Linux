/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
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
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <openssl/crypto.h>
#include "veeport_errors.h"
#include "LLDEVICE_linux_configuration.h"
#include "LLDEVICE_id_util.h"
#include "LLDEVICE_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAC_ADDRESS_SIZE                (6)

// Number of bytes kept from the identifier derived from the machine ID.
#define DERIVED_ID_SIZE                 (6)
#define MACHINE_ID_SIZE                 (16)
#define MACHINE_ID_HEX_SIZE             (32)

// Largest ID this port reports. A device tree serial number longer than this is truncated.
#define DEVICE_ID_MAX_SIZE              (64)

// Returned by a source that holds no ID, so the next source is tried.
#define SOURCE_NO_ANSWER                (-1)

// Length held by the cache while the sources have not been read yet.
#define ID_CACHE_NOT_READ               (-1)

// The ID is read once and cached, so every call reports the same value for the life of the process.
static uint8_t LLDEVICE_IMPL_id_cache[DEVICE_ID_MAX_SIZE];
static int32_t LLDEVICE_IMPL_id_cache_length = ID_CACHE_NOT_READ;

static int32_t get_device_id(uint8_t *buffer, int32_t buffer_size);
static int32_t get_id_from_device_tree(uint8_t *buffer, int32_t buffer_size);
static int32_t get_id_from_mac_address(uint8_t *buffer, int32_t buffer_size);
static int32_t get_id_from_machine_id(uint8_t *buffer, int32_t buffer_size);

uint8_t LLDEVICE_IMPL_getArchitecture(uint8_t *buffer, int32_t length) {
	const size_t architecture_size = sizeof(LLDEVICE_ARCHITECTURE);
	if ((size_t)length >= architecture_size) {
		strncpy((char *)buffer, LLDEVICE_ARCHITECTURE, architecture_size);
		return 1;
	} else {
		return 0;
	}
}

uint32_t LLDEVICE_IMPL_getId(uint8_t *buffer, int32_t length) {
	if (ID_CACHE_NOT_READ == LLDEVICE_IMPL_id_cache_length) {
		int32_t cached_length = get_device_id(LLDEVICE_IMPL_id_cache, (int32_t)sizeof(LLDEVICE_IMPL_id_cache));

		if (0 > cached_length) {
			// Cache the failure too, so the sources are never read a second time
			cached_length = 0;
		}
		LLDEVICE_IMPL_id_cache_length = cached_length;
	}

	int32_t id_length = LLDEVICE_IMPL_id_cache_length;
	if (id_length > length) {
		id_length = length;
	}
	if (0 > id_length) {
		id_length = 0;
	}
	(void)memcpy(buffer, LLDEVICE_IMPL_id_cache, (size_t)id_length);

	return (uint32_t)id_length;
}

/**
 * @brief Fills the given buffer with the ID of the device.
 *
 * Tries the device tree serial number, then the MAC address of the first non-loopback
 * network interface, then a derivation of the machine ID of the host. Hardware identity
 * comes first: a machine ID is unique per installation, so an image shipping a populated
 * /etc/machine-id gives one ID to a whole fleet.
 *
 * @param buffer the buffer to fill with the ID.
 * @param buffer_size the size of @p buffer in bytes.
 * @return the number of bytes filled, a negative value when no source holds an ID.
 */
static int32_t get_device_id(uint8_t *buffer, int32_t buffer_size) {
	int32_t id_length = get_id_from_device_tree(buffer, buffer_size);

	if (0 >= id_length) {
		id_length = get_id_from_mac_address(buffer, buffer_size);
	}
	if (0 >= id_length) {
		id_length = get_id_from_machine_id(buffer, buffer_size);
	}

	return id_length;
}

/**
 * @brief Fills the given buffer with the serial number of the board, read from the device tree.
 *
 * @param buffer the buffer to fill with the serial number.
 * @param buffer_size the size of @p buffer in bytes. A longer serial number is truncated.
 * @return the number of bytes filled, a negative value when the device tree holds no serial number.
 */
static int32_t get_id_from_device_tree(uint8_t *buffer, int32_t buffer_size) {
	int32_t id_length = lldevice_id_util_read_file(LLDEVICE_SERIAL_NUMBER_FILE, buffer, buffer_size);

	if (0 < id_length) {
		id_length = lldevice_id_util_trim(buffer, id_length);
	}
	if (0 >= id_length) {
		id_length = SOURCE_NO_ANSWER;
	}

	return id_length;
}

/**
 * @brief Fills the given buffer with the MAC address of the first non-loopback network interface.
 *
 * Enumerates with getifaddrs() rather than the SIOCGIFCONF ioctl, which reports only the
 * interfaces that carry an IPv4 address and therefore hides the MAC address of an interface
 * that is up without IPv4, and of every IPv6-only interface.
 *
 * Skips an interface whose hardware address holds only zero bytes, which identifies nothing.
 *
 * @param buffer the buffer to fill with the MAC address.
 * @param buffer_size the size of @p buffer in bytes.
 * @return the number of bytes filled, a negative value when no interface holds a MAC address.
 */
static int32_t get_id_from_mac_address(uint8_t *buffer, int32_t buffer_size) {
	struct ifaddrs *interfaces = NULL;
	int32_t id_length = SOURCE_NO_ANSWER;

	if (MAC_ADDRESS_SIZE > buffer_size) {
		goto end;
	}

	if (0 != getifaddrs(&interfaces)) {
		goto end;
	}

	for (const struct ifaddrs *interface = interfaces; NULL != interface; interface = interface->ifa_next) {
		if (NULL == interface->ifa_addr) {
			continue;
		}
		if (AF_PACKET != interface->ifa_addr->sa_family) {
			continue;
		}
		if (0 != (interface->ifa_flags & (unsigned int)IFF_LOOPBACK)) {
			continue;
		}

		const struct sockaddr_ll *link_address = (const struct sockaddr_ll *)(const void *)interface->ifa_addr;
		if (MAC_ADDRESS_SIZE != link_address->sll_halen) {
			continue;
		}
		if (lldevice_id_util_is_all_zero(link_address->sll_addr, MAC_ADDRESS_SIZE)) {
			continue;
		}

		(void)memcpy(buffer, link_address->sll_addr, MAC_ADDRESS_SIZE);
		id_length = MAC_ADDRESS_SIZE;
		break;
	}

	freeifaddrs(interfaces);

end:
	return id_length;
}

/**
 * @brief Fills the given buffer with an identifier derived from the machine ID of the host.
 *
 * @param buffer the buffer to fill with the derived identifier.
 * @param buffer_size the size of @p buffer in bytes.
 * @return the number of bytes filled, a negative value when the host holds no usable machine ID.
 */
static int32_t get_id_from_machine_id(uint8_t *buffer, int32_t buffer_size) {
	// One byte more than the hexadecimal machine ID, so a longer file is told apart from a valid one.
	uint8_t machine_id_hex[MACHINE_ID_HEX_SIZE + 1] = { 0 };
	uint8_t machine_id[MACHINE_ID_SIZE] = { 0 };
	int32_t id_length = SOURCE_NO_ANSWER;
	int32_t hex_length = 0;

	if (DERIVED_ID_SIZE > buffer_size) {
		goto end;
	}

	hex_length = lldevice_id_util_read_file(LLDEVICE_MACHINE_ID_FILE, machine_id_hex, (int32_t)sizeof(machine_id_hex));
	if (0 >= hex_length) {
		goto end;
	}

	hex_length = lldevice_id_util_trim(machine_id_hex, hex_length);
	if (MACHINE_ID_HEX_SIZE != hex_length) {
		goto end;
	}

	if (!lldevice_id_util_parse_hex(machine_id_hex, hex_length, machine_id, (int32_t)sizeof(machine_id))) {
		goto end;
	}

	if (lldevice_id_util_derive_id_from_machine_id(machine_id, (int32_t)sizeof(machine_id), buffer,
	                                               DERIVED_ID_SIZE)) {
		id_length = DERIVED_ID_SIZE;
	}

end:
	OPENSSL_cleanse(machine_id_hex, sizeof(machine_id_hex));
	OPENSSL_cleanse(machine_id, sizeof(machine_id));

	return id_length;
}

/**
 * Fills the given buffer with the Version of the device as
 * a null-terminated string.
 *
 * @param buffer the buffer to fill with the Version.
 */
void LLDEVICE_IMPL_getVersion(uint8_t *buffer) {
	(void)buffer;
	VEEPORT_ERRORS_throw_runtime_exception(RUNTIME_EXCEPTION_NOT_IMPLEMENTED);
}

/**
 * Reboots the device.
 */
void LLDEVICE_IMPL_reboot(void) {
	VEEPORT_ERRORS_throw_runtime_exception(RUNTIME_EXCEPTION_NOT_IMPLEMENTED);
}

/**
 * Shutdown the device.
 */
void LLDEVICE_IMPL_shutdown(void) {
	VEEPORT_ERRORS_throw_runtime_exception(RUNTIME_EXCEPTION_NOT_IMPLEMENTED);
}

#ifdef __cplusplus
}
#endif
