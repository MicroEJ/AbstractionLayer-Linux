/*
 * C
 *
 * Copyright 2016-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLNET_Common implementation over BSD-like API.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

#include "LLNET_Common.h"
#include "async_select.h"
#include <string.h>
#include "LLNET_CHANNEL_impl.h"
#include "LLNET_ERRORS.h"
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdint.h>
#if LLNET_AF & LLNET_AF_IPV6
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#endif
#ifndef LLNET_USE_IOCTL_FOR_BLOCKING_OPTION
#include <fcntl.h>
#endif // LLNET_USE_IOCTL_FOR_BLOCKING_OPTION

VEEPORT_LOGGER_DEFINE_MODULE(LLNET_LOG_MODULE_NAME, LLNET_LOG_LEVEL)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Convert a network error code into a java error code.
 *
 * @param[in] err the error code returned by a BSD-like function.
 *
 * @return an error code defined in LLNET_ERRORS.h.
 */
int32_t LLNET_map_to_java_exception(int32_t err) {
	switch (err) {
	case (EACCES):
		return J_EACCES;
	case (EBADF):
		return J_EBADF;
	case (EHOSTDOWN):
		return J_EHOSTDOWN;
	case (ENETDOWN):
		return J_ENETDOWN;
	case (ENETUNREACH):
		return J_ENETUNREACH;
	case (EADDRINUSE):
		return J_EADDRINUSE;
	case (EINVAL):
		return J_EINVAL;
	case (ECONNABORTED):
		return J_ECONNABORTED;
	case (ENOPROTOOPT):
		return J_ENOPROTOOPT;
	case (ENOTCONN):
		return J_ENOTCONN;
	case (EAFNOSUPPORT):
		return J_EAFNOSUPPORT;
	case (ECONNREFUSED):
		return J_ECONNREFUSED;
	case (EISCONN):
		return J_EISCONN;
	case (ECONNRESET):
		return J_ECONNRESET;
	case (EMSGSIZE):
		return J_EMSGSIZE;
	case (EPIPE):
		return J_EPIPE;
	case (ETIMEDOUT):
		return J_ETIMEDOUT;
	case (ENOBUFS):
	case (ENOSPC):
	case (ENOMEM):
	case (ENFILE):
		return J_ENOMEM;
	case (EHOSTUNREACH):
		return J_EHOSTUNREACH;
	default:
		return J_EUNKNOWN;
	}
}

#if LLNET_AF & LLNET_AF_IPV6
uint32_t LLNET_getScopeForIp(const char *ip) {
	struct ifaddrs *addrs;
	char ipAddress[NI_MAXHOST];
	uint32_t scope = 0;

	// walk over the list of all interface addresses
	getifaddrs(&addrs);
	for (struct ifaddrs *addr = addrs; addr; addr = addr->ifa_next) {
		if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET6) { // only interested in ipv6 ones
			getnameinfo(addr->ifa_addr, sizeof(struct sockaddr_in6), ipAddress,
			            sizeof(ipAddress), NULL, 0, NI_NUMERICHOST);
			// result actually contains the interface name, so strip it
			for (int i = 0; ipAddress[i]; i++) {
				if (ipAddress[i] == '%') {
					ipAddress[i] = '\0';
					break;
				}
			}
			// if the ip matches, convert the interface name to a scope index
			if (strcmp(ipAddress, ip) == 0) {
				scope = if_nametoindex(addr->ifa_name);
				break;
			}
		}
	}
	// If the scope wasn't set in the name search, set it to LLNET_IPV6_INTERFACE_NAME
	if (0 == scope) {
		scope = if_nametoindex(LLNET_IPV6_INTERFACE_NAME);
	}
	freeifaddrs(addrs);
	return scope;
}

void LLNET_map_ipv4_into_ipv6(in_addr_t *ipv4_addr, struct in6_addr *ipv6_addr) {
	// Convert IPv4 into IPv6 directly in the addr array

	if (*(ipv4_addr) == llnet_htonl(INADDR_ANY)) {
		// Use IPv6 wildcard address
		*ipv6_addr = in6addr_any;
	} else {
		uint8_t *ipv6_addr_u8 = (uint8_t *)ipv6_addr;
		// Destination offset of the IPv4 address: end of struct in6_addr
		int ipv4_dest_offset = sizeof(struct in6_addr) - sizeof(in_addr_t);
		// Copy the IPv4 address at the end of struct in6_addr
		memcpy(ipv6_addr_u8 + ipv4_dest_offset, ipv4_addr, sizeof(in_addr_t));

		// Add 0xFF:0xFF before
		ipv6_addr_u8[ipv4_dest_offset - 1] = 0xFF;
		ipv6_addr_u8[ipv4_dest_offset - 2] = 0xFF;

		// Set to 0 all the other bytes
		memset(ipv6_addr_u8, 0, ipv4_dest_offset - 2);
	}
}

#endif /* if LLNET_AF & LLNET_AF_IPV6 */

void LLNET_throw_socket_error(int32_t fd_errno) {
	int32_t error_code = LLNET_map_to_java_exception(fd_errno);
	if (J_EUNKNOWN == error_code) {
		VEEPORT_ERRORS_throw_caught_exception_message(error_code, "%s (%d)", strerror(fd_errno), fd_errno);
	} else {
		VEEPORT_LOGGER_LOG_DBG("socket error %d: %s", fd_errno, strerror(fd_errno));
		VEEPORT_ERRORS_throw_caught_exception(error_code);
	}
}

/**
 * Blocking wait seam.  Decides how a would-block suspends the calling Java
 * thread until the fd is ready for the async_select <code>operation</code> (or
 * the absolute deadline passes); the Core Engine then re-invokes
 * <code>callback</code> to retry.  The default issues an <code>async_select</code>
 * request.  A backend with its own readiness mechanism (e.g. an event-driven
 * I/O multiplexer) overrides this macro — through a compile flag or its
 * configuration header — to route the wait elsewhere, in which case the
 * SELECT_* operations and async_select are no longer required.
 *
 * The default is kept here (not in LLNET_configuration.h) so an existing,
 * unchanged configuration header stays source-compatible: the macro is always
 * defined regardless of the config header's vintage, while an override defined
 * ahead of this point still wins.
 */
#ifndef LLNET_WAIT_OPERATION
#define LLNET_WAIT_OPERATION(fd, operation, absolute_timeout_ms, callback, callback_suspend_arg) \
		async_select((fd), (operation), (absolute_timeout_ms), (callback), (callback_suspend_arg))
#endif

/**
 * @brief Handles the error code of a non-blocking I/O operation.
 * This function is called only when a non-blocking read/write/connect/accept operation results in an error.
 *
 * This function checks first the given absolute timeout and throws an SNI NativeIOException if the timeout is reached.
 *
 * <code>absolute_timeout_ms</code> is an absolute time in milliseconds computed from the system time returned by
 * <code>LLMJVM_IMPL_getCurrentTime(1)</code>. A timeout of zero is interpreted as an infinite timeout.
 *
 * If the error code is <code>EAGAIN</code>, <code>EWOULDBLOCK</code> or <code>EINPROGRESS</code>,
 * then the wait is performed through the <code>LLNET_WAIT_OPERATION</code> seam (by default an
 * <code>async_select()</code> request) on the given <code>operation</code>; otherwise an SNI
 * NativeIOException is thrown.
 *
 * @param[in] fd The file descriptor on which the error has occurred.
 * @param[in] fd_errno the error code to be handled.
 * @param[in] operation the async_select operation on which the async_select request will be performed.
 * @param[in] absolute_timeout_ms the absolute timeout in milliseconds or 0 if no timeout.
 * @param[in] callback the async_select SNI callback function.
 * @param[in] callback_suspend_arg the async_select SNI suspend callback argument.
 */
void LLNET_handle_blocking_operation_error(int32_t fd, int32_t fd_errno, select_operation operation,
                                           int64_t absolute_timeout_ms, SNI_callback callback,
                                           void *callback_suspend_arg) {
	//check if timeout occurs
	if (absolute_timeout_ms != 0 && absolute_timeout_ms < LLNET_current_time_ms()) {
		//timeout occurs
		VEEPORT_ERRORS_throw_caught_exception(J_ETIMEDOUT);
		return;
	}

	if ((EAGAIN == fd_errno) || (EINPROGRESS == fd_errno) || (EWOULDBLOCK == fd_errno)) {
		//need to wait until the fd is ready for the operation
		//(LLNET_WAIT_OPERATION seam — default async_select, see above)
		LLNET_WAIT_OPERATION(fd, operation, absolute_timeout_ms, callback, callback_suspend_arg);
		return;
	}

	LLNET_throw_socket_error(fd_errno);
}

/**
 * @brief Sets the given socket file descriptor in non-blocking mode.
 *
 * @param[in] fd socket file descriptor
 *
 * @return 0 on success, a negative value on error.
 */
int32_t LLNET_set_non_blocking(int32_t fd) {
#ifdef LLNET_USE_IOCTL_FOR_BLOCKING_OPTION
	int32_t non_blocking_option = 1;
	return llnet_ioctl(fd, FIONBIO, &non_blocking_option);
#else
	int32_t flags = llnet_fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}
	flags |= O_NONBLOCK;
	return llnet_fcntl(fd, F_SETFL, flags);
#endif // LLNET_USE_IOCTL_FOR_BLOCKING_OPTION
}

#ifdef __cplusplus
}
#endif
