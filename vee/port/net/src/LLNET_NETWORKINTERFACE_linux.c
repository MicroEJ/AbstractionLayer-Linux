/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLNET_NETWORKINTERFACE 2.1.0 implementation over Linux.
 * @author MicroEJ Developer Team
 * @version 3.0.0
 * @date 11 September 2026
 */

#include <LLNET_NETWORKINTERFACE_impl.h>

#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "LLNET_ERRORS.h"
#include "LLNET_Common.h"
#include "LLNET_configuration.h"
#include "LLNET_linux_configuration.h"
#include "sni_extras.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLNET_LOG_MODULE_NAME, LLNET_LOG_LEVEL)

/**
 * @brief Checks the configuration header against the version this file expects.
 *
 * A failure here means a newer version of the CCO was installed. Update
 * LLNET_linux_configuration.h from the one that version provides.
 */
#if LLNET_LINUX_CONFIGURATION_VERSION != 1

	#error "Version of the configuration file LLNET_linux_configuration.h is not compatible with this implementation."

#endif

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------------------------
 * Constants.
 * -------------------------------------------------------------------------------------------- */

/** @brief Size of an IPv4 address, in bytes. */
#define IPV4_ADDRESS_SIZE           (4)

/** @brief Size of an IPv6 address, in bytes. */
#define IPV6_ADDRESS_SIZE           (16)

/** @brief Number of prefix bits carried by one byte of a netmask. */
#define PREFIX_BITS_PER_BYTE        (8)

/** @brief Netmask byte whose every prefix bit is set. */
#define PREFIX_BYTE_ALL_ONES        (0xFFU)

/** @brief Most significant bit of a netmask byte. */
#define PREFIX_BYTE_HIGH_BIT        (0x80U)

/**
 * @brief Largest IPv4 prefix length that still leaves room for a broadcast address.
 *
 * A /31 subnet holds two addresses and a /32 holds one, so neither has a broadcast address.
 */
#define IPV4_BROADCAST_PREFIX_MAX   (30)

/** @brief Value of the addrInfo broadcast flag when a broadcast address follows it. */
#define HAS_BROADCAST               (1U)

/** @brief Value of the addrInfo broadcast flag when no broadcast address follows it. */
#define NO_BROADCAST                (0U)

/** @brief Capacity of the buffer holding an exception message that names an interface. */
#define ERROR_MESSAGE_MAX_SIZE      (64 + IFNAMSIZ)

/* --------------------------------------------------------------------------------------------
 * Exceptions.
 *
 * Every failure of this file is raised by one of these functions. A caller then reports the
 * error by returning SNI_IGNORED_RETURNED_VALUE.
 * -------------------------------------------------------------------------------------------- */

/**
 * @brief Holds an exception message that names an interface.
 *
 * The Core Engine copies the message after the native returns, so a message on the stack is
 * forbidden. See the description of SNI_throwNativeIOException() in sni.h. One static buffer is
 * enough, because a native raises at most one exception before it returns.
 */
static char error_message[ERROR_MESSAGE_MAX_SIZE] = { 0 };

/**
 * @brief Raises a NativeIOException carrying the given error code and message.
 *
 * The exception is raised after the native returns, so a function that must still return a value
 * returns SNI_IGNORED_RETURNED_VALUE. The caller never reads it.
 *
 * @param[in] error_code an error code of LLNET_ERRORS.h.
 * @param[in] message a message with static storage duration.
 */
static void throw_io_exception(int32_t error_code, const char *message) {
	int32_t sni_result = SNI_throwNativeIOException(error_code, message);

	LLNET_ASSERT(SNI_OK == sni_result);
}

/**
 * @brief Raises a NativeIOException for a failed system call.
 *
 * @param[in] error_number the errno value, read before any close() call.
 * @param[in] message a message with static storage duration.
 */
static void throw_errno(int32_t error_number, const char *message) {
	throw_io_exception(LLNET_map_to_java_exception(error_number), message);
}

/**
 * @brief Raises a NativeIOException with J_EINVAL, naming an interface that does not exist.
 *
 * @param[in] name a null-terminated interface name.
 */
static void throw_no_such_interface(const char *name) {
	int32_t written = snprintf(error_message, sizeof(error_message), "no such network interface: %s", name);

	LLNET_ASSERT(0 < written);
	/* LLNET_ERRORS.h defines no code meaning "no such device", so J_EINVAL is the closest of the 22
	 * it holds. The message survives as the chained cause only, because NativeIOExceptionHandler
	 * builds the message the application sees from the error code alone. */
	throw_io_exception(J_EINVAL, error_message);
}

/* --------------------------------------------------------------------------------------------
 * Address decoding.
 *
 * These functions turn one struct ifaddrs entry into the addrInfo payload that
 * LLNET_NETWORKINTERFACE_impl.h describes.
 * -------------------------------------------------------------------------------------------- */

/**
 * @brief One network interface address, in the addrInfo layout of LLNET_NETWORKINTERFACE_impl.h.
 */
struct address_record {
	uint8_t info[IPV6_ADDR_INFO_SIZE];  /**< the addrInfo payload, ready to copy out */
	int32_t size;                       /**< IPV4_ADDR_INFO_SIZE or IPV6_ADDR_INFO_SIZE */
};

/**
 * @brief Tells whether the address family is enabled.
 *
 * @param[in] family an address family of a struct sockaddr.
 *
 * @return true when the family is enabled.
 */
static bool is_family_enabled(int32_t family) {
	bool enabled = false;

	if (AF_INET == family) {
		enabled = (0 != (LLNET_AF & LLNET_AF_IPV4));
	} else if (AF_INET6 == family) {
		enabled = (0 != (LLNET_AF & LLNET_AF_IPV6));
	} else {
		enabled = false;
	}
	return enabled;
}

/**
 * @brief Counts the leading one bits of a netmask held in network byte order.
 *
 * A mask with a gap reports only the run of ones before the gap, because the bits after it do not
 * describe a prefix length. So 0xFF 0xFF 0xC0 0x00 reports 18, and 0xFF 0x00 0xFF 0x00 reports 8.
 *
 * @param[in] mask the netmask bytes, most significant first.
 * @param[in] mask_size the number of bytes of the netmask.
 *
 * @return the prefix length in bits, from 0 to mask_size * PREFIX_BITS_PER_BYTE.
 */
static uint8_t prefix_length(const uint8_t *mask, int32_t mask_size) {
	int32_t bits = 0;
	int32_t index = 0;

	for (index = 0; index < mask_size; index++) {
		if (PREFIX_BYTE_ALL_ONES == mask[index]) {
			bits += PREFIX_BITS_PER_BYTE;
		} else {
			uint8_t remaining = mask[index];

			/* The leading ones of this byte end the run, so count them and stop. */
			while (0U != (remaining & PREFIX_BYTE_HIGH_BIT)) {
				bits++;
				remaining = (uint8_t)(remaining << 1U);
			}
			break;
		}
	}
	return (uint8_t)bits;
}

/**
 * @brief Tells whether the ifa_broadaddr of an IPv4 entry holds a broadcast address.
 *
 * @param[in] entry an interface list entry whose family is AF_INET.
 * @param[in] prefix the prefix length of that address.
 *
 * @return true when entry->ifa_broadaddr holds a broadcast address.
 */
static bool has_broadcast_address(const struct ifaddrs *entry, uint8_t prefix) {
	const struct sockaddr_in *address = NULL;
	const struct sockaddr_in *broadcast = NULL;

	/* The kernel reports several different things through this one union member. Each test below
	 * excludes one of them. */
	if (NULL == entry->ifa_broadaddr) {
		/* The device reports neither a broadcast nor a peer address. */
		return false;
	}
	if (0 == (entry->ifa_flags & IFF_BROADCAST)) {
		/* The device cannot broadcast at all. */
		return false;
	}
	if (0 != (entry->ifa_flags & IFF_POINTOPOINT)) {
		/* The union holds the peer address. */
		return false;
	}
	if (IPV4_BROADCAST_PREFIX_MAX < prefix) {
		/* The subnet is too small to hold a broadcast address. */
		return false;
	}
	address = (const struct sockaddr_in *)entry->ifa_addr;
	broadcast = (const struct sockaddr_in *)entry->ifa_broadaddr;
	/* When the two are equal the address was configured without a broadcast address, and the kernel
	 * echoed the interface address back into the union. */
	return (broadcast->sin_addr.s_addr != address->sin_addr.s_addr);
}

/**
 * @brief Encodes an IPv4 address into the layout of LLNET_NETWORKINTERFACE_impl.h.
 *
 * @param[in] entry an interface list entry whose family is AF_INET.
 * @param[out] record the record to fill, zeroed by encode_address().
 */
static void encode_ipv4_address(const struct ifaddrs *entry, struct address_record *record) {
	const struct sockaddr_in *address = (const struct sockaddr_in *)entry->ifa_addr;
	uint8_t prefix = 0;
	int32_t offset = 0;

	record->info[offset] = IPV4_ADDR_TAG;
	offset++;
	memcpy(&record->info[offset], &address->sin_addr.s_addr, IPV4_ADDRESS_SIZE);
	offset += IPV4_ADDRESS_SIZE;

	if (NULL != entry->ifa_netmask) {
		const struct sockaddr_in *netmask = (const struct sockaddr_in *)entry->ifa_netmask;

		prefix = prefix_length((const uint8_t *)&netmask->sin_addr.s_addr, IPV4_ADDRESS_SIZE);
	}
	record->info[offset] = prefix;
	offset++;

	if (has_broadcast_address(entry, prefix)) {
		const struct sockaddr_in *broadcast = (const struct sockaddr_in *)entry->ifa_broadaddr;

		record->info[offset] = HAS_BROADCAST;
		offset++;
		memcpy(&record->info[offset], &broadcast->sin_addr.s_addr, IPV4_ADDRESS_SIZE);
	} else {
		record->info[offset] = NO_BROADCAST;
	}
	record->size = IPV4_ADDR_INFO_SIZE;
}

/**
 * @brief Encodes an IPv6 address into the layout of LLNET_NETWORKINTERFACE_impl.h.
 *
 * @param[in] entry an interface list entry whose family is AF_INET6.
 * @param[out] record the record to fill, zeroed by encode_address(). Its size is set to
 * IPV6_ADDR_INFO_SIZE.
 */
static void encode_ipv6_address(const struct ifaddrs *entry, struct address_record *record) {
	const struct sockaddr_in6 *address = (const struct sockaddr_in6 *)entry->ifa_addr;
	uint8_t prefix = 0;
	int32_t offset = 0;

	record->info[offset] = IPV6_ADDR_TAG;
	offset++;
	memcpy(&record->info[offset], &address->sin6_addr.s6_addr, IPV6_ADDRESS_SIZE);
	offset += IPV6_ADDRESS_SIZE;

	if (NULL != entry->ifa_netmask) {
		const struct sockaddr_in6 *netmask = (const struct sockaddr_in6 *)entry->ifa_netmask;

		prefix = prefix_length(netmask->sin6_addr.s6_addr, IPV6_ADDRESS_SIZE);
	}
	record->info[offset] = prefix;
	/* The IPv6 layout ends at the prefix length. It carries no broadcast flag, unlike the IPv4 one. */
	record->size = IPV6_ADDR_INFO_SIZE;
}

/**
 * @brief Encodes one address, choosing the layout from its family.
 *
 * @param[in] entry an interface list entry carrying an address of an enabled family.
 * @param[out] record the record to fill, zeroed here.
 *
 * @return true when the family has a layout, false otherwise.
 */
static bool encode_address(const struct ifaddrs *entry, struct address_record *record) {
	bool encoded = true;

	memset(record, 0, sizeof(*record));
	if (AF_INET == entry->ifa_addr->sa_family) {
		encode_ipv4_address(entry, record);
	} else if (AF_INET6 == entry->ifa_addr->sa_family) {
		encode_ipv6_address(entry, record);
	} else {
		/* is_address_of() admits no other family, so only a caller that skipped it arrives here. */
		VEEPORT_LOGGER_LOG_DBG("unexpected address family %d\n", entry->ifa_addr->sa_family);
		encoded = false;
	}
	return encoded;
}

/* --------------------------------------------------------------------------------------------
 * The two interface lists.
 *
 * Each one is a getifaddrs(3) result, pinned by one count call and read by its matching getter.
 * Neither count call refreshes the list the other one pinned, so a position stays valid for the
 * count that produced it. One shared list hands out a stale position as soon as the two pairs of
 * calls interleave.
 *
 * The lists need no read or write protection: the Core Engine runs one native at a time, and the
 * @warning of every function of LLNET_NETWORKINTERFACE_impl.h keeps every caller inside the VM
 * task. No check anywhere reads the calling task, so a caller outside the VM task corrupts the
 * lists silently.
 *
 * The lists hold the interfaces and their addresses. The six attribute getters read the system on
 * each call instead, so each one answers about the interface as it is now.
 *
 * A getter whose count call was skipped finds an empty list, and answers over the list the system
 * reports at that moment.
 *
 * The last list each pointer holds is never released. Nothing in the LLAPI reports that the Core
 * Engine is stopping. Linux reclaims the memory of a process when it ends, so a teardown hook would
 * free a block the kernel frees anyway. A leak checker reports them.
 * -------------------------------------------------------------------------------------------- */

/**
 * @brief The list getVMInterface() walks by position.
 *
 * Only getVMInterfacesCount() refreshes it.
 */
static struct ifaddrs *interface_list = NULL;

/**
 * @brief The list getVMInterfaceAddress() walks by position.
 *
 * Only getVMInterfaceAddressesCount() refreshes it.
 */
static struct ifaddrs *address_list = NULL;

/**
 * @brief Tells whether an entry is the first one of its interface in a list.
 *
 * getifaddrs(3) reports one link entry per interface plus one entry per address, so one interface
 * appears several times. This holds for exactly one entry of each interface name.
 *
 * For the list lo(link), lo(IPv4), lo(IPv6), eth0(link), eth0(IPv4), it holds for lo(link) and for
 * eth0(link), and not for the others.
 *
 * @param[in] list an interface list.
 * @param[in] entry an entry of that list.
 *
 * @return true when no earlier entry carries the same name.
 */
static bool is_first_entry_of(const struct ifaddrs *list, const struct ifaddrs *entry) {
	const struct ifaddrs *earlier = NULL;

	for (earlier = list; earlier != entry; earlier = earlier->ifa_next) {
		if (0 == strncmp(earlier->ifa_name, entry->ifa_name, IFNAMSIZ)) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Tells whether an interface of the given name exists in an interface list.
 *
 * getifaddrs() reports one link entry per interface, so an interface with no IP address is present
 * in the list too.
 *
 * @param[in] list an interface list.
 * @param[in] name a null-terminated interface name.
 *
 * @return true when the list holds at least one entry of that interface.
 */
static bool is_interface_present(const struct ifaddrs *list, const char *name) {
	const struct ifaddrs *entry = NULL;

	for (entry = list; NULL != entry; entry = entry->ifa_next) {
		if (0 == strncmp(entry->ifa_name, name, IFNAMSIZ)) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Replaces a list with the interfaces and addresses the system reports now.
 *
 * On failure the list is left as it was, so a position into it stays valid.
 *
 * @param[in,out] list the list to replace.
 *
 * @return true on success, false after an exception was raised.
 */
static bool list_refresh(struct ifaddrs **list) {
	struct ifaddrs *refreshed = NULL;

	if (0 != llnet_getifaddrs(&refreshed)) {
		throw_errno(errno, "cannot list the network interfaces");
		return false;
	}
	/* The old list is released only once the new one is in hand. So the failure path above leaves a
	 * readable list rather than a dangling pointer. */
	llnet_freeifaddrs(*list);
	*list = refreshed;
	return true;
}

/**
 * @brief Builds the list when it is empty, and leaves a list that already holds entries untouched.
 *
 * @param[in,out] list the list to build when it is empty.
 *
 * @return true on success, false after an exception was raised.
 */
static bool list_ensure(struct ifaddrs **list) {
	bool ready = true;

	if (NULL == *list) {
		ready = list_refresh(list);
	}
	return ready;
}

/**
 * @brief Counts the distinct interface names of an interface list.
 *
 * @param[in] list an interface list.
 *
 * @return the number of interfaces.
 */
static int32_t count_interfaces(const struct ifaddrs *list) {
	const struct ifaddrs *entry = NULL;
	int32_t count = 0;

	for (entry = list; NULL != entry; entry = entry->ifa_next) {
		if (is_first_entry_of(list, entry)) {
			count++;
		}
	}
	return count;
}

/**
 * @brief Finds the name of the interface at a position in an interface list.
 *
 * @param[in] list an interface list.
 * @param[in] index the position, counted over the distinct names.
 *
 * @return a null-terminated name, valid until the list is refreshed, or NULL when the position
 * names no interface.
 */
static const char *interface_name_at(const struct ifaddrs *list, int32_t index) {
	const struct ifaddrs *entry = NULL;
	int32_t position = 0;

	if (0 > index) {
		return NULL;
	}
	for (entry = list; NULL != entry; entry = entry->ifa_next) {
		if (is_first_entry_of(list, entry)) {
			if (position == index) {
				return entry->ifa_name;
			}
			position++;
		}
	}
	return NULL;
}

/**
 * @brief Tells whether an entry carries an address of the given interface, in an enabled family.
 *
 * @param[in] entry an interface list entry.
 * @param[in] name a null-terminated interface name.
 *
 * @return true when the entry matches, false otherwise.
 */
static bool is_address_of(const struct ifaddrs *entry, const char *name) {
	if (0 != strncmp(entry->ifa_name, name, IFNAMSIZ)) {
		return false;
	}
	if (NULL == entry->ifa_addr) {
		return false;
	}
	return is_family_enabled(entry->ifa_addr->sa_family);
}

/**
 * @brief Counts the addresses of one interface that fall in an enabled family.
 *
 * @param[in] list an interface list.
 * @param[in] name a null-terminated interface name.
 *
 * @return the number of addresses, which is zero for an interface that carries none and for one
 * whose addresses are all outside the enabled families.
 */
static int32_t count_addresses(const struct ifaddrs *list, const char *name) {
	const struct ifaddrs *entry = NULL;
	int32_t count = 0;

	for (entry = list; NULL != entry; entry = entry->ifa_next) {
		if (is_address_of(entry, name)) {
			count++;
		}
	}
	return count;
}

/**
 * @brief Finds the address at a position among the addresses of one interface.
 *
 * @param[in] list an interface list.
 * @param[in] name a null-terminated interface name.
 * @param[in] index the position, counted over the reportable addresses of that interface.
 *
 * @return an entry of the list, valid until the list is refreshed, or NULL when the position
 * names no address.
 */
static const struct ifaddrs *address_at(const struct ifaddrs *list, const char *name, int32_t index) {
	const struct ifaddrs *entry = NULL;
	int32_t position = 0;

	if (0 > index) {
		return NULL;
	}
	for (entry = list; NULL != entry; entry = entry->ifa_next) {
		if (is_address_of(entry, name)) {
			if (position == index) {
				return entry;
			}
			position++;
		}
	}
	return NULL;
}

/* --------------------------------------------------------------------------------------------
 * The arguments a caller passes.
 *
 * SNI passes a managed array as a bare pointer. A native therefore checks two things before it
 * reads or writes one byte: what the caller declared, and what the array really holds.
 * -------------------------------------------------------------------------------------------- */

/**
 * @brief Checks the interface name a caller passed.
 *
 * After this returns true, the name is a null-terminated C string of at most IFNAMSIZ - 1 bytes,
 * and the array really holds it.
 *
 * @param[in] ifname the interface name.
 * @param[in] ifname_length the length of that name, without the null byte.
 *
 * @return true on success, false after an exception was raised.
 */
static bool is_interface_name_valid(uint8_t *ifname, int32_t ifname_length) {
	/* The name is read where the caller put it, and never saved, so no copy is needed. The SNI rule
	 * forbids saving a managed array, and forbids reaching it from another task. It does not forbid
	 * reading it during the native call, and no function of this file suspends the current thread. */

	/* The contract gives the length without the null byte, so the array holds one element more. The
	 * range check runs before the read of that null byte, so the read is safe. */
	if ((NULL == ifname) || (0 >= ifname_length) || ((int32_t)IFNAMSIZ <= ifname_length) ||
	    !sni_array_contains_range(ifname, 0, ifname_length + 1) || ('\0' != ifname[ifname_length])) {
		throw_io_exception(J_EINVAL, "the network interface name is not a null-terminated name that fits IFNAMSIZ");
		return false;
	}
	return true;
}

/**
 * @brief Checks that an output array can take the bytes a native is about to write into it.
 *
 * @param[in] array the array the native writes into.
 * @param[in] declared_length the number of elements the caller declared.
 * @param[in] needed the number of elements the native writes.
 * @param[in] message a message with static storage duration, used when the array cannot take them.
 *
 * @return true on success, false after an exception was raised.
 */
static bool is_output_array_usable(void *array, int32_t declared_length, int32_t needed,
                                   const char *message) {
	/* Two things have to hold, and a caller can get either one wrong. The caller must have declared
	 * room for what it asked for. The array must really hold what the caller declared. SNI passes an
	 * array as a bare pointer. So sni_array_contains_range() of sni_extras.h checks the second one,
	 * by reading the element count SNI stores before the array. */
	if ((needed > declared_length) || !sni_array_contains_range(array, 0, declared_length)) {
		throw_io_exception(J_EINVAL, message);
		return false;
	}
	return true;
}

/* --------------------------------------------------------------------------------------------
 * The state of one interface.
 *
 * These functions reach the system by name on every call, and read neither list. isUp() therefore
 * reports the carrier as it is now, not as it was when the list was pinned.
 *
 * Each call costs a socket, an ioctl and a close. Answering the four predicates from ifa_flags in
 * a pinned list would cost none, and would report a carrier that dropped only at the next call to
 * getVMInterfacesCount().
 * -------------------------------------------------------------------------------------------- */

/**
 * @brief Names an interface in a struct ifreq and runs an ioctl on it.
 *
 * This function owns the request. A caller passes an uninitialized one and never writes ifr_name.
 *
 * @param[in] request_code the ioctl request, one of the SIOCGIF* codes.
 * @param[in] ifname the interface name, checked by is_interface_name_valid().
 * @param[in] ifname_length the length of that name, without the null byte.
 * @param[out] request the request, filled by the ioctl.
 * @param[in] message a message with static storage duration, used when the ioctl fails.
 *
 * @return true on success, false after an exception was raised. A missing interface raises
 * J_EINVAL, every other failure the code that LLNET_map_to_java_exception() gives for its errno.
 */
static bool interface_ioctl(unsigned long request_code, const uint8_t *ifname, int32_t ifname_length,
                            struct ifreq *request, const char *message) {
	/* netdevice(7) states the standard device ioctls "can be used on any socket's file descriptor
	 * regardless of the family or type", so an AF_UNIX socket serves every address family
	 * configuration. The kernel sets SOCK_CLOEXEC inside the socket() call, so a fork() from another
	 * task cannot land between the creation and the flag. */
	int32_t fd = llnet_socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);

	if (-1 == fd) {
		throw_errno(errno, "cannot open a socket for the network interface request");
		return false;
	}
	/* Zeroed and named here, so a caller cannot hand the kernel an unnamed or unterminated request. */
	memset(request, 0, sizeof(*request));
	memcpy(request->ifr_name, ifname, (size_t)ifname_length);
	request->ifr_name[ifname_length] = '\0';

	if (-1 == llnet_ioctl(fd, request_code, request)) {
		int32_t error_number = errno;

		if (-1 == llnet_close(fd)) {
			VEEPORT_LOGGER_LOG_DBG("cannot close the socket, errno=%d\n", errno);
		}
		if (ENODEV == error_number) {
			/* ENODEV reports a missing interface, so the exception names it too. The name comes back
			 * from ifr_name, where it cannot disagree with the name the ioctl was given. The interface
			 * either never existed, or it disappeared since the caller read the interface list. */
			throw_no_such_interface(request->ifr_name);
		} else {
			throw_errno(error_number, message);
		}
		return false;
	}
	if (-1 == llnet_close(fd)) {
		VEEPORT_LOGGER_LOG_DBG("cannot close the socket, errno=%d\n", errno);
	}
	return true;
}

/**
 * @brief Tells whether an interface carries every flag of a mask.
 *
 * The flags are read from the system on each call, so the answer is the state now.
 *
 * @param[in] ifname the interface name.
 * @param[in] ifname_length the length of that name.
 * @param[in] mask the interface flags to require. Every flag of the mask must be set, which is
 * what lets isUp() ask for IFF_UP and IFF_RUNNING together.
 *
 * @return 0 when every flag of the mask is set, 1 otherwise, or SNI_IGNORED_RETURNED_VALUE after
 * an exception. LLNET_NETWORKINTERFACE_impl.h defines 0 as true for the four predicates that call
 * this function.
 */
static int32_t has_all_flags(uint8_t *ifname, int32_t ifname_length, int32_t mask) {
	struct ifreq request = { 0 };
	int32_t flags = 0;

	if (!is_interface_name_valid(ifname, ifname_length)) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (!interface_ioctl(SIOCGIFFLAGS, ifname, ifname_length, &request,
	                     "cannot read the network interface flags")) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	flags = (int32_t)(uint16_t)request.ifr_flags;
	return (mask == (flags & mask)) ? 0 : 1;
}

/* --------------------------------------------------------------------------------------------
 * The natives of LLNET_NETWORKINTERFACE_impl.h.
 *
 * The four enumeration functions come first, then the six that report the state of one interface.
 * Wherever a name is passed, the name is the key and the index is ignored. When the interface
 * list changed since the caller read it, the index and the name can point at different
 * interfaces.
 * -------------------------------------------------------------------------------------------- */

int32_t LLNET_NETWORKINTERFACE_IMPL_getVMInterfacesCount(void) {
	VEEPORT_LOGGER_LOG_DBG("\n");

	if (!list_refresh(&interface_list)) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	return count_interfaces(interface_list);
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getVMInterface(int32_t index, uint8_t *ifname_buffer,
                                                   int32_t ifname_buffer_length) {
	VEEPORT_LOGGER_LOG_DBG("(index=%d)\n", index);

	const char *name = NULL;
	size_t name_length = 0;

	if (!list_ensure(&interface_list)) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	name = interface_name_at(interface_list, index);
	if (NULL == name) {
		/* The @return description of getVMInterface() in LLNET_NETWORKINTERFACE_impl.h allows 0
		 * for an index that names no interface, and the caller skips the slot and continues
		 * its enumeration. */
		return 0;
	}
	name_length = strnlen(name, IFNAMSIZ - 1U);

	if (!is_output_array_usable(ifname_buffer, ifname_buffer_length, (int32_t)name_length + 1,
	                            "the network interface name buffer cannot take the name")) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	/* The copy writes name_length + 1 bytes, which fit because is_output_array_usable() required
	 * ifname_buffer_length to be at least that. */
	memcpy(ifname_buffer, name, name_length + 1U);
	return (int32_t)name_length;
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getVMInterfaceAddressesCount(int32_t index, uint8_t *ifname,
                                                                 int32_t ifname_length) {
	VEEPORT_LOGGER_LOG_DBG("(index=%d)\n", index);

	const char *name = (const char *)ifname;

	(void)index;

	if (!is_interface_name_valid(ifname, ifname_length)) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (!list_refresh(&address_list)) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (!is_interface_present(address_list, name)) {
		throw_no_such_interface(name);
		return SNI_IGNORED_RETURNED_VALUE;
	}
	return count_addresses(address_list, name);
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getVMInterfaceAddress(int32_t index_if, uint8_t *ifname,
                                                          int32_t ifname_length, int32_t index_addr,
                                                          int8_t *addr_info, int32_t addr_info_length) {
	VEEPORT_LOGGER_LOG_DBG("(idxIf=%d, idxAddr=%d)\n", index_if, index_addr);

	const char *name = (const char *)ifname;
	const struct ifaddrs *entry = NULL;
	struct address_record record = { { 0 }, 0 };

	(void)index_if;

	if (!is_interface_name_valid(ifname, ifname_length)) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (!list_ensure(&address_list)) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (!is_interface_present(address_list, name)) {
		throw_no_such_interface(name);
		return SNI_IGNORED_RETURNED_VALUE;
	}
	entry = address_at(address_list, name, index_addr);
	if (NULL == entry) {
		throw_io_exception(J_EINVAL, "the network interface address index is out of range");
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (!encode_address(entry, &record)) {
		throw_io_exception(J_EAFNOSUPPORT, "the network interface address family is not supported");
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (!is_output_array_usable(addr_info, addr_info_length, record.size,
	                            "the network interface address buffer cannot take the address")) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	memcpy(addr_info, record.info, (size_t)record.size);
	return record.size;
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getHardwareAddress(uint8_t *ifname, int32_t ifname_length,
                                                       int8_t *hw_addr, int32_t hw_addr_max_length) {
	VEEPORT_LOGGER_LOG_DBG("\n");

	struct ifreq request = { 0 };

	if (!is_interface_name_valid(ifname, ifname_length)) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (!interface_ioctl(SIOCGIFHWADDR, ifname, ifname_length, &request,
	                     "cannot read the network interface hardware address")) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (ARPHRD_ETHER != request.ifr_hwaddr.sa_family) {
		/* The @return description of getHardwareAddress() in LLNET_NETWORKINTERFACE_impl.h allows
		 * 0, and the caller maps it to a null hardware address. */
		return 0;
	}
	if (!is_output_array_usable(hw_addr, hw_addr_max_length, IFHWADDRLEN,
	                            "the hardware address buffer cannot take the address")) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	memcpy(hw_addr, request.ifr_hwaddr.sa_data, IFHWADDRLEN);
	return IFHWADDRLEN;
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getMTU(uint8_t *ifname, int32_t ifname_length) {
	VEEPORT_LOGGER_LOG_DBG("\n");

	struct ifreq request = { 0 };

	if (!is_interface_name_valid(ifname, ifname_length)) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (!interface_ioctl(SIOCGIFMTU, ifname, ifname_length, &request,
	                     "cannot read the network interface MTU")) {
		return SNI_IGNORED_RETURNED_VALUE;
	}
	return request.ifr_mtu;
}

int32_t LLNET_NETWORKINTERFACE_IMPL_isUp(uint8_t *ifname, int32_t ifname_length) {
	VEEPORT_LOGGER_LOG_DBG("\n");
	/* java.net.NetworkInterface.isUp() reports an interface that is up and running, so both flags
	 * are required. An interface that is administratively up without a carrier is not up. */
	return has_all_flags(ifname, ifname_length, IFF_UP | IFF_RUNNING);
}

int32_t LLNET_NETWORKINTERFACE_IMPL_isLoopback(uint8_t *ifname, int32_t ifname_length) {
	VEEPORT_LOGGER_LOG_DBG("\n");
	return has_all_flags(ifname, ifname_length, IFF_LOOPBACK);
}

int32_t LLNET_NETWORKINTERFACE_IMPL_isPointToPoint(uint8_t *ifname, int32_t ifname_length) {
	VEEPORT_LOGGER_LOG_DBG("\n");
	return has_all_flags(ifname, ifname_length, IFF_POINTOPOINT);
}

int32_t LLNET_NETWORKINTERFACE_IMPL_supportsMulticast(uint8_t *ifname, int32_t ifname_length) {
	VEEPORT_LOGGER_LOG_DBG("\n");
	return has_all_flags(ifname, ifname_length, IFF_MULTICAST);
}

#ifdef __cplusplus
}
#endif
