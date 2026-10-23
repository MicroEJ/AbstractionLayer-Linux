/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLNET_MULTICASTSOCKETCHANNEL 3.0.0 implementation over BSD-like API.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

#include "LLNET_MULTICASTSOCKETCHANNEL_impl.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sni.h"
#include "LLNET_ERRORS.h"
#include "LLNET_Common.h"
#include "LLNET_CHANNEL_impl.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLNET_LOG_MODULE_NAME, LLNET_LOG_LEVEL)
#if LLNET_AF & LLNET_AF_IPV6
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

int32_t LLNET_MULTICASTSOCKETCHANNEL_IMPL_getTimeToLive(int32_t fd) {
	VEEPORT_LOGGER_LOG_DBG("(fd=0x%X)", fd);
	return LLNET_CHANNEL_IMPL_getOption(fd, LLNET_SOCKETOPTION_IP_TTL);
}

void LLNET_MULTICASTSOCKETCHANNEL_IMPL_setTimeToLive(int32_t fd, int32_t ttl) {
	VEEPORT_LOGGER_LOG_DBG("(fd=0x%X)", fd);
	LLNET_CHANNEL_IMPL_setOption(fd, LLNET_SOCKETOPTION_IP_TTL, ttl);
}

void LLNET_MULTICASTSOCKETCHANNEL_IMPL_joinOrLeave(int32_t fd, uint8_t join, int8_t *mcastAddr, int32_t mcastAddrLength,
                                                   int8_t *netIfAddr, int32_t netIfAddrLength) {
	VEEPORT_LOGGER_LOG_DBG("(fd=0x%X)", fd);
	int32_t fd_errno;
#if LLNET_AF & LLNET_AF_IPV4

	if (mcastAddrLength == sizeof(in_addr_t) && (netIfAddrLength == sizeof(in_addr_t) || netIfAddrLength == 0)) {
		struct ip_mreq optval;
		optval.imr_multiaddr.s_addr = *(in_addr_t *)mcastAddr;
		if (netIfAddrLength != 0) {
			optval.imr_interface.s_addr = *(in_addr_t *)netIfAddr;
		} else {
			// No interface specified, use INADDR_ANY
			optval.imr_interface.s_addr = llnet_htonl(INADDR_ANY);
		}
		if (llnet_setsockopt(fd, IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &optval,
		                     sizeof(optval)) == -1) {
			fd_errno = llnet_errno(fd);
			VEEPORT_LOGGER_LOG_DBG("errno=%d", fd_errno);
			LLNET_throw_socket_error(fd_errno);
		}
		return;
	}
#endif /* if LLNET_AF & LLNET_AF_IPV4 */
#if LLNET_AF & LLNET_AF_IPV6
	if (mcastAddrLength == sizeof(struct in6_addr) &&
	    (netIfAddrLength == sizeof(struct in6_addr) || netIfAddrLength == 0)) {
		struct ipv6_mreq optval;
		memcpy(optval.ipv6mr_multiaddr.s6_addr, mcastAddr, sizeof(struct in6_addr));
		if (netIfAddrLength != 0) {
			// get interface name
			struct ifaddrs *ifaddrs = NULL;
			struct ifaddrs *i;
			if (getifaddrs(&ifaddrs) != 0) {
				fd_errno = llnet_errno(fd);
				LLNET_throw_socket_error(fd_errno);
				return;
			}
			// Walk the interface address structure until we match the interface address
			for (i = ifaddrs; i != NULL; i = i->ifa_next) {
				if (NULL != i->ifa_addr && AF_INET6 == i->ifa_addr->sa_family) {
					if (memcmp(netIfAddr, ((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr.s6_addr,
					           netIfAddrLength) == 0) {
						optval.ipv6mr_interface = if_nametoindex(i->ifa_name);
						break;
					}
				}
			}
			freeifaddrs(ifaddrs);
		} else {
			optval.ipv6mr_interface = 0;
		}
		if (llnet_setsockopt(fd, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &optval,
		                     sizeof(optval)) == -1) {
			fd_errno = llnet_errno(fd);
			VEEPORT_LOGGER_LOG_DBG("errno=%d", fd_errno);
			LLNET_throw_socket_error(fd_errno);
		}
		return;
	}
#endif /* if LLNET_AF & LLNET_AF_IPV6 */
	VEEPORT_LOGGER_LOG_DBG("wrong address length");
	VEEPORT_ERRORS_throw_caught_exception(J_EINVAL);
}

#ifdef __cplusplus
}
#endif
