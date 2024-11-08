/*
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLNET_NETWORKINTERFACE 2.1.0 implementation over Linux.
 * @author MicroEJ Developer Team
 * @version 3.0.0
 * @date 23 July 2024
 */

#include <LLNET_NETWORKINTERFACE_impl.h>

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "LLNET_ERRORS.h"
#include "LLNET_Common.h"
#include "LLNET_linux_configuration.h"

/**
 * Sanity check between the expected version of the configuration and the actual version of
 * the configuration.
 * If an error is raised here, it means that a new version of the CCO has been installed and
 * the configuration LLNET_configuration.h must be updated based on the one provided
 * by the new CCO version.
 */
#if LLNET_LINUX_CONFIGURATION_VERSION != 1

	#error "Version of the configuration file LLNET_linux_configuration.h is not compatible with this implementation."

#endif

#ifdef __cplusplus
extern "C" {
#endif

// Constants for the getVMInterfaceAddress protocol between Java and the native stacks
// ipv4 address info size (tag (1) + IP (4) + prefix (1) + hasBroadcast (1) + broadcast IP (4))
#define IPV4_ADDR_INFO_SIZE 11
// ipv6 address info size (tag (1) + IP (16) + prefix (1)
#define IPV6_ADDR_INFO_SIZE 18

// ipv4 address tag
#define IPV4_ADDR_TAG 4
// ipv6 address tag
#define IPV6_ADDR_TAG 6

extern int32_t LLNET_map_to_java_exception(int32_t err);

static int32_t openSocketDatagram(int32_t *fdPtr, int32_t family);
static int32_t iff_flags(int8_t *name, int32_t length, int32_t *flags);
static int32_t checkFeature(int8_t *name, int32_t length, int32_t feature);
static int8_t getMaskLen(struct ifaddrs *ifaddrs);
static int8_t getMaskLen6(struct ifaddrs *ifaddrs);

int32_t LLNET_NETWORKINTERFACE_IMPL_getVMInterface(int32_t id, uint8_t *nameReturned, int32_t length) {
	LLNET_DEBUG_TRACE("%s(id=%d)\n", __func__, id);

// IPv6 Only or dual stack
#if LLNET_AF & LLNET_AF_IPV6
	int retVal = 0;

	struct if_nameindex *if_ni, *i;

	if_ni = if_nameindex();
	if (if_ni == NULL) {
		LLNET_DEBUG_TRACE("%s(id=%d) if_nameindex returned NULL\n", __func__, id);
		return retVal;
	}

	// Walk the pointer chain looking for a matching index
	for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++) {
		if (i->if_index == (id + 1)) {  // if_index is one-based, id is zero-based
			break;
		}
	}

	if (NULL != i->if_name) {
		strncpy(nameReturned, i->if_name, length);
		// From strncpy() man:
		// * Warning: If there is no null byte among the first n bytes
		// * of src, the string placed in dest will not be null terminated.
		//
		// To avoid any issue, we set to 0 the last char.
		nameReturned[length - 1] = 0;
		retVal = strlen(nameReturned);
	}

	if_freenameindex(if_ni);
	return retVal;

#else // IPv4 only

	struct ifaddrs *ifaddrs;
	struct sockaddr *ifAddr;
	if (getifaddrs(&ifaddrs) != 0) {
		return J_EUNKNOWN;
	}
	int32_t ifCount = 0;
	for (struct ifaddrs *i = ifaddrs; i != NULL; i = i->ifa_next) {
		ifAddr = i->ifa_addr;
		if (ifAddr != NULL && ifAddr->sa_family == AF_INET) {
			if (ifCount++ == id) {
				int32_t maxNameLength = length;
				strncpy(nameReturned, i->ifa_name, maxNameLength);
				freeifaddrs(ifaddrs);

				// From strncpy() man:
				// * Warning: If there is no null byte among the first n bytes
				// * of src, the string placed in dest will not be null terminated.
				//
				// To avoid any issue, we set to 0 the last char.
				nameReturned[length - 1] = 0;
				return strlen(nameReturned);
			}
		}
	}
	freeifaddrs(ifaddrs);
	// invalid id?
	return 0;
#endif /* if LLNET_AF & LLNET_AF_IPV6 */
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getVMInterfaceAddress(int32_t idIf, uint8_t *ifname, int32_t ifname_length,
                                                          int32_t idAddr, int8_t *addrInfo, int32_t length) {
	struct sockaddr *ifAddr;
	struct sockaddr_dl *ifAddr1;
	struct ifaddrs *i;
	char currentIfNameString[IFADDRNAMEMAX];
	int nameStringLength;
	int thisAddrCount = -1;
	int32_t addrSize = 0;
	LLNET_DEBUG_TRACE("%s(idIF=%d idAddr = %d)\n", __func__, idIf, idAddr);

	// Get the interface name string for interface number idIf
	nameStringLength = LLNET_NETWORKINTERFACE_IMPL_getVMInterface(idIf, currentIfNameString, IFADDRNAMEMAX);

	struct ifaddrs *ifaddrs = NULL;

	if (getifaddrs(&ifaddrs) != 0) {
		return J_EUNKNOWN;
	}
	// Walk the interface address structure until we match the interface name string
	for (i = ifaddrs; i != NULL; i = i->ifa_next) {
		if (NULL == i->ifa_addr) {
			continue;
		}
		if (0 == strncmp(currentIfNameString, i->ifa_name, IFADDRNAMEMAX)) {
#if LLNET_AF & LLNET_AF_IPV4
			if (AF_INET == i->ifa_addr->sa_family) {
				thisAddrCount++;
			}
#endif
#if LLNET_AF & LLNET_AF_IPV6
			if (AF_INET6 == i->ifa_addr->sa_family) {
				thisAddrCount++;
			}
#endif
			if (thisAddrCount == idAddr) {
				break;
			}
		}
	}
#if LLNET_AF & LLNET_AF_IPV4
	// set the address tag
	if (AF_INET == i->ifa_addr->sa_family) {
		addrInfo[0] = IPV4_ADDR_TAG;
		addrSize = IPV4_ADDR_INFO_SIZE;
		addrInfo += 1;
		struct sockaddr_in *ifAddrIn = (struct sockaddr_in *)i->ifa_addr;
		//get the ip address
		in_addr_t saddr = ifAddrIn->sin_addr.s_addr;
		memcpy(addrInfo, &saddr, sizeof(ifAddrIn->sin_addr.s_addr));
		addrInfo += sizeof(ifAddrIn->sin_addr.s_addr);
		//get the prefix (the mask len)
		//prefix can be from 0 to 128
		//so we encode it on 1 byte 0 to 0x80
		addrInfo[0] = getMaskLen(i);
		addrInfo += 1;
	}
#endif /* if LLNET_AF & LLNET_AF_IPV4 */
#if LLNET_AF & LLNET_AF_IPV6
	if (AF_INET6 == i->ifa_addr->sa_family) {
		addrInfo[0] = IPV6_ADDR_TAG;
		addrSize = IPV6_ADDR_INFO_SIZE;
		addrInfo += 1;
		struct sockaddr_in6 *ifAddrIn = (struct sockaddr_in6 *)i->ifa_addr;
		//get the ip address
		memcpy(addrInfo, &ifAddrIn->sin6_addr.s6_addr, sizeof(ifAddrIn->sin6_addr.s6_addr));
		addrInfo += sizeof(ifAddrIn->sin6_addr.s6_addr);
		//get the prefix (the mask len)
		//prefix can be from 0 to 128
		//so we encode it on 1 byte 0 to 0x80
		addrInfo[0] = getMaskLen6(i);
		addrInfo += 1;
	}
#endif /* if LLNET_AF & LLNET_AF_IPV6 */

	addrInfo[0] = 0; //no broadcast
#if LLNET_AF & LLNET_AF_IPV4
	if (AF_INET == i->ifa_addr->sa_family) {
		// now the broadcast
		if ((i->ifa_flags & IFF_BROADCAST) != 0) {
			addrInfo[0] = 1; //hasBroadcast
			addrInfo += 1;
			struct sockaddr_in *broadcastAddrIn = (struct sockaddr_in *)i->ifa_broadaddr;
			memcpy(addrInfo, &broadcastAddrIn->sin_addr.s_addr, sizeof(broadcastAddrIn->sin_addr.s_addr));
			addrInfo += sizeof(broadcastAddrIn->sin_addr.s_addr);
		}
	}
#endif /* if LLNET_AF & LLNET_AF_IPV4 */

	freeifaddrs(ifaddrs);
	return addrSize;
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getVMInterfaceAddressesCount(int32_t id, uint8_t *ifname, int32_t ifname_length) {
	LLNET_DEBUG_TRACE("%s id = %d\n", __func__, id);
	unsigned addressCount = 0;
	char currentIfNameString[IFADDRNAMEMAX];
	struct ifaddrs *i;

	// Get the interface name string for interface number idIf
	LLNET_NETWORKINTERFACE_IMPL_getVMInterface(id, currentIfNameString, IFADDRNAMEMAX);

	struct ifaddrs *ifaddrs = NULL;
	if (getifaddrs(&ifaddrs) != 0) {
		return J_EUNKNOWN;
	}
	int ifCount = 0;    // ONE is the first interface number

	// Walk the interface address structures counting the matches to the interface name string
	for (i = ifaddrs; i != NULL; i = i->ifa_next) {
		if (NULL == i->ifa_addr) {
			continue;
		}
		if (0 == strncmp(currentIfNameString, i->ifa_name, IFADDRNAMEMAX)) {
			// This element has a matching interface name string.

			// Don't count the unconfigured type of interfaces.
#if LLNET_AF & LLNET_AF_IPV4
			if (AF_INET == i->ifa_addr->sa_family) {
				addressCount++;
			}
#endif
#if LLNET_AF & LLNET_AF_IPV6
			if (AF_INET6 == i->ifa_addr->sa_family) {
				addressCount++;
			}
#endif
		}
	}
	freeifaddrs(ifaddrs);

	LLNET_DEBUG_TRACE("%s returning addressCount = %d\n", __func__, addressCount);
	return addressCount;
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getVMInterfacesCount() {
	LLNET_DEBUG_TRACE("%s\n", __func__);
	int ifCount = 0;

	struct if_nameindex *if_ni, *i;

	if_ni = if_nameindex();
	if (if_ni == NULL) {
		LLNET_DEBUG_TRACE("%s, if_nameindex Returned NULL\n", __func__);
		return ifCount;
	}

	for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++) {
		ifCount++;
	}

	if_freenameindex(if_ni);
	LLNET_DEBUG_TRACE("%s, ifCount=%d\n", __func__, ifCount);
	return ifCount;
}

int32_t LLNET_NETWORKINTERFACE_IMPL_isLoopback(uint8_t *name, int32_t length) {
	LLNET_DEBUG_TRACE("%s\n", __func__);
	return checkFeature(name, length, IFF_LOOPBACK);
}

int32_t LLNET_NETWORKINTERFACE_IMPL_isPointToPoint(uint8_t *name, int32_t length) {
	LLNET_DEBUG_TRACE("%s\n", __func__);
	return checkFeature(name, length, IFF_POINTOPOINT);
}

int32_t LLNET_NETWORKINTERFACE_IMPL_isUp(uint8_t *name, int32_t length) {
	LLNET_DEBUG_TRACE("%s\n", __func__);
	return checkFeature(name, length, (IFF_UP | IFF_RUNNING));
}

int32_t LLNET_NETWORKINTERFACE_IMPL_supportsMulticast(uint8_t *name, int32_t length) {
	LLNET_DEBUG_TRACE("%s\n", __func__);
	return checkFeature(name, length, IFF_MULTICAST);
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getHardwareAddress(uint8_t *name, int32_t length, int8_t *hwAddr,
                                                       int32_t hwAddrMaxLength) {
	LLNET_DEBUG_TRACE("%s\n", __func__);
	jint socket;
	jint error;
	jint retval;
	if ((error = openSocketDatagram(&socket, AF_INET)) != 0) {
		return J_EUNKNOWN;
	}

	struct ifreq iff;
	if (length < sizeof(iff.ifr_name)) {
		memcpy(iff.ifr_name, name, length);
		iff.ifr_name[length] = 0; //null terminated

		if (ioctl(socket, SIOCGIFHWADDR, &iff) >= 0) {
			if (iff.ifr_hwaddr.sa_family == ARPHRD_ETHER && IFHWADDRLEN <= hwAddrMaxLength) {
				memcpy(hwAddr, iff.ifr_hwaddr.sa_data, IFHWADDRLEN);
				retval = IFHWADDRLEN;
			} else {
				retval = 0; //not an Ethernet interface OR HWD buffer is too small
				LLNET_DEBUG_TRACE(
					"Not an Ethernet interface OR HWD buffer is too small(IFHWADDRLEN=%d, hwAddrMaxLength=%d)\n",
					IFHWADDRLEN, hwAddrMaxLength);
			}
		} else {
			retval = J_EUNKNOWN;
		}
	} else {
		retval = 0; //interface name is too long
		LLNET_DEBUG_TRACE("Interface name is too long\n");
	}

	close(socket);
	LLNET_DEBUG_TRACE("%s, retval=%d, errno=%d\n", __func__, retval, errno);
	return retval;
}

int32_t LLNET_NETWORKINTERFACE_IMPL_getMTU(uint8_t *name, int32_t length) {
	LLNET_DEBUG_TRACE("%s\n", __func__);
	jint socket;
	jint error;
	jint retval;
	if ((error = openSocketDatagram(&socket, AF_INET)) != 0) {
		return J_EUNKNOWN;
	}

	struct ifreq iff;
	if (length < sizeof(iff.ifr_name)) {
		memcpy(iff.ifr_name, name, length);
		iff.ifr_name[length] = 0; //null terminated

		if (ioctl(socket, SIOCGIFMTU, &iff) >= 0) {
			retval = iff.ifr_mtu;
		} else {
			retval = J_EUNKNOWN;
		}
	} else {
		retval = J_EUNKNOWN; //interface name is too long
		LLNET_DEBUG_TRACE("Interface name is too long\n");
	}

	close(socket);
	LLNET_DEBUG_TRACE("%s, retval=%d, errno=%d\n", __func__, retval, errno);
	return retval;
}

static int checkFeature(int8_t *name, int32_t length, int32_t feature) {
	int32_t flags;
	if (iff_flags(name, length, &flags) != 0) {
		return J_EUNKNOWN;
	} else {
		return (flags & feature) != 0 ? 0 : 1;
	}
}

static int32_t iff_flags(int8_t *name, int32_t length, int32_t *flags) {
	int32_t socket;
	int32_t error;
	int32_t retval;
	if ((error = openSocketDatagram(&socket, AF_INET)) != 0) {
		return error;
	}

	struct ifreq iff;
	if (length < sizeof(iff.ifr_name)) {
		memcpy(iff.ifr_name, name, length);
		iff.ifr_name[length] = 0; //null terminated

		if (ioctl(socket, SIOCGIFFLAGS, &iff) >= 0) {
			*flags = iff.ifr_flags;
			retval = 0;
		} else {
			retval = LLNET_map_to_java_exception(errno);
		}
	} else {
		retval = -1; //interface name is too long
	}

	close(socket);

	return retval;
}

int32_t openSocketDatagram(int32_t *fdPtr, int32_t family) {
	int32_t fd = socket(family, SOCK_DGRAM, 0);
	*fdPtr = fd;
	if (fd == -1) {
		return LLNET_map_to_java_exception(errno);
	}
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	return 0;
}

static int8_t getMaskLen(struct ifaddrs *ifaddrs) {
	struct sockaddr *netmaskAddr;
	int8_t len = 0;

	if (ifaddrs != NULL && (netmaskAddr = ifaddrs->ifa_netmask) != NULL) {
		uint32_t mask = (uint32_t)((struct sockaddr_in *)netmaskAddr)->sin_addr.s_addr;
		while (mask) {
			mask >>= 1;
			len++;
		}
	} else {
		LLNET_DEBUG_TRACE("%s, No pointer to netmask for this address\n", __func__);
	}
	return len;
}

static int8_t getMaskLen6(struct ifaddrs *ifaddrs) {
	struct sockaddr *netmaskAddr;
	uint8_t maskLenInBytes = sizeof(((struct in6_addr *)0)->s6_addr);
	uint8_t *maskPointer = NULL;
	int8_t len = 0;
	uint8_t mask;

	if (ifaddrs != NULL && (netmaskAddr = ifaddrs->ifa_netmask) != NULL) {
		maskPointer = (uint8_t *)&((struct sockaddr_in6 *)netmaskAddr)->sin6_addr.s6_addr;
		for (int i = 0; i < maskLenInBytes; i++) {
			mask = *maskPointer++;
			while (mask) {
				mask >>= 1;
				len++;
			}
		}
	} else {
		LLNET_DEBUG_TRACE("%s, No pointer to netmask for this address\n", __func__);
	}
	return len;
}

#ifdef __cplusplus
}
#endif
