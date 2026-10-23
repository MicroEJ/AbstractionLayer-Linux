/*
 * C
 *
 * Copyright 2017-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief Platform implementation specific macro.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

#ifndef  LLNET_CONFIGURATION_H
#define  LLNET_CONFIGURATION_H

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compatibility sanity check value.
 * This define value is checked in the implementation to validate that the version of this configuration
 * is compatible with the implementation.
 *
 * This value must not be changed by the user of the CCO.
 * This value must be incremented by the implementor of the CCO when a configuration define is added, deleted or
 * modified.
 */
#define LLNET_CONFIGURATION_VERSION (3)

/**
 * Platform headers that declare the functions the llnet_* macros map to.
 * Each BSP includes its own platform headers here so that any file
 * pulling in LLNET_configuration.h gets both the macros and the
 * function declarations they expand to.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>

/*
 * Readiness mechanism.  When rio is built (LLNET_WAIT_WITH_RIO, set by CMake
 * when BUILD_RIO is ON), route the bsp-net-bsd wait/init/close-notify seams to
 * rio (rio_wait_ready / rio_init / rio_close_fd).  This override is included
 * ahead of LLNET_Common.h's defaults so it wins.  When rio is not built, the
 * seams fall back to LLNET_Common.h's default async_select implementation.
 * Either way the canonical LLNET_*_bsd.c natives run over the BSD llnet_*
 * sockets above.
 */
#if defined(LLNET_WAIT_WITH_RIO)
#include "LLNET_rio.h"
#endif

/**
 * By default all the llnet_* functions are mapped on the BSD functions.
 * Documentation (signature, etc.) for each llnet_* function is available
 * in the mapped BSD function documentation.
 */
#define llnet_accept        accept
#define llnet_bind          bind
#define llnet_close         close
#define llnet_connect       connect
#define llnet_fcntl         fcntl
#define llnet_gethostname   gethostname
#define llnet_getpeername   getpeername
#define llnet_getsockname   getsockname
#define llnet_getsockopt    getsockopt
#define llnet_htonl         htonl
#define llnet_htons         htons
#define llnet_ioctl         ioctl
#define llnet_listen        listen
#define llnet_ntohs         ntohs
#define llnet_recv          recv
#define llnet_recvfrom      recvfrom
#define llnet_send          send
#define llnet_sendto        sendto
#define llnet_setsockopt    setsockopt
#define llnet_socket        socket
#define llnet_shutdown      shutdown

/*
 * IPv4 address byte-order hooks: copy the 4 raw bytes of an IPv4 address
 * between a Java byte[] (network order) and a `struct in_addr`.  On POSIX
 * both sides are already network order, so each is a plain 4-byte copy;
 * a stack that keeps the address in host order overrides these with the
 * matching htonl/ntohl conversion.
 */
#define llnet_htonl_addr(dst, src)  memcpy((dst), (src), 4)
#define llnet_ntohl_addr(dst, src)  memcpy((dst), (src), 4)

/**
 * IPv6 scope-id resolution helpers.  Only referenced by rio-net-bsd
 * when the configured address family includes IPv6.
 */
#include <ifaddrs.h>
#include <net/if.h>
#define llnet_inet_ntop         inet_ntop
#define llnet_if_nametoindex    if_nametoindex
#define llnet_getifaddrs        getifaddrs
#define llnet_freeifaddrs       freeifaddrs

/* Readable-byte-count on POSIX: ioctl(FIONREAD). */
#define llnet_socket_available(fd, count)   ioctl((fd), FIONREAD, (count))

/**
 * Don't modify the LLNET_AF_* constants.
 */
#define LLNET_AF_IPV4   (0x1)
#define LLNET_AF_IPV6   (0x2)
#define LLNET_AF_DUAL   ((LLNET_AF_IPV4) | (LLNET_AF_IPV6))

/**
 *  Address family:
 *  - LLNET_AF_IPV4 for only IPv4
 *  - LLNET_AF_IPV6 for only IPv6
 *  - LLNET_AF_DUAL for both IPv4 and IPv6
 */
#ifndef LLNET_AF /* LLNET_AF can be defined with a compile flag */
#define LLNET_AF (LLNET_AF_IPV4)
#endif

/**
 * Returns the errno value for the given file descriptor.
 * Given file descriptor may be -1 if no file descriptor is defined.
 */
#include <errno.h>
#define llnet_errno(fd)     errno

/**
 * Use this macro to define the initialization function of the network stack.
 * Called from LLNET_CHANNEL_IMPL_initialize().
 *
 * For example, It can be used to initialize ecom-network & ecom-wifi:
 * 	#include "LLECOM_NETWORK.h"
 *	#include "LLECOM_WIFI.h"
 *	static inline int32_t llnet_init() {
 *		LLECOM_NETWORK_initialize();
 *		LLECOM_WIFI_initialize();
 *		return 0;
 *	}
 *
 * By default this macro does nothing.
 */
#include "LLECOM_NETWORK.h"
#define llnet_init  LLECOM_NETWORK_initialize

/**
 * Returns true if we can call the services of the network stack without jeopardizing the system,
 * otherwise returns false.
 * Returning true does not mean that a network interface is up.
 * By default this macro always return true.
 */
#define llnet_is_ready()    (true)

/** @brief Set this define if the system sends SIGPIPE signal when a connection is closed by the remote host. */
#if defined(__linux__) || defined(__QNXNTO__)
#define LLNET_IGNORE_SIGPIPE
#endif // defined(__linux__) || defined(__QNXNTO__)

/**
 *  Alternative implementation type of LLNET_STREAMSOCKETCHANNEL_IMPL_available() function.
 *  The default implementation of this function uses ioctl() to get available data length.
 *  In case where ioctl() cannot be used, you can switch to one of these following alternative implementations:
 *  - LLNET_USE_MSG_PEEK_FOR_AVAILABLE: implementation based on llnet_recv() with MSG_PEEK flag to get available data
 * length
 *  - LLNET_USE_SOCK_OPTION_FOR_AVAILABLE: implementation based on llnet_getsockopt with SO_RXDATA option to get
 * available data length
 *
 *  Don't modify the LLNET_USE_*_FOR_AVAILABLE constants.
 */
#define LLNET_USE_MSG_PEEK_FOR_AVAILABLE    (0x1)
#define LLNET_USE_SOCK_OPTION_FOR_AVAILABLE (0x2)

/**
 * Use this macro to switch to an alternate implementation of LLNET_STREAMSOCKETCHANNEL_IMPL_available() function.
 * Example: switch to an alternative implementation based on MSG_PEEK
 * 		#define LLNET_AVAILABLE_IMPL_ALT LLNET_USE_MSG_PEEK_FOR_AVAILABLE
 */
//#define LLNET_AVAILABLE_IMPL_ALT LLNET_USE_MSG_PEEK_FOR_AVAILABLE

#if LLNET_AVAILABLE_IMPL_ALT == LLNET_USE_MSG_PEEK_FOR_AVAILABLE

/**
 * Use this macro to define in bytes the size of the buffer to be used to get the available data length.
 * Only needed when the implementation based on MSG_PEEK is selected.
 * By default the size is 4096 bytes.
 */
#define LLNET_MSG_PEEK_AVAILABLE_BUFFER_SIZE (4096)

/*
 * Use this optional macro to define a preferred section in which the buffer used to get available data will be put.
 * Only used when the implementation based on MSG_PEEK is selected.
 * This macro is not mandatory.
 * Example:
 * 		#define LLNET_MSG_PEEK_AVAILABLE_BUFFER_SECTION ".psram"
 */
//#define LLNET_MSG_PEEK_AVAILABLE_BUFFER_SECTION		"section_name"
#endif

/**
 * Enable this macro to use "localhost" as default localhost name
 * in LLNET_NETWORKADDRESS_IMPL_getLocalHostnameNative() implementation.
 * This is useful when no function is available to retrieve the localhost name.
 */
#define LLNET_USE_DEFAULT_LOCALHOST_NAME

/**
 * Define LLNET_USE_IOCTL_FOR_BLOCKING_OPTION to use ioctl() instead of fcntl() to configure socket
 * blocking or non-blocking mode.
 */
//#define LLNET_USE_IOCTL_FOR_BLOCKING_OPTION

#if LLNET_AF & LLNET_AF_IPV6
/**
 * Use this define to set the used IPV6 interface name.
 * Only one IPV6 interface is supported.
 * Default interface name is "eth0"
 */
#define LLNET_IPV6_INTERFACE_NAME (char *)"eth0"
#endif // LLNET_AF & LLNET_AF_IPV6

/**
 * Define the maximum number of sockets that can be handled by the net module
 */
#define LLNET_MAX_SOCKETS (20)

#ifdef __cplusplus
}
#endif

#endif // LLNET_CONFIGURATION_H
