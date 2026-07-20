/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief Platform implementation specific macros for rio-net.
 * @author @CCO_AUTHOR@
 * @version @CCO_VERSION@
 * @date @CCO_DATE@
 *
 * This is the P0341 (Linux/POSIX) customisation of the rio-net-bsd
 * configuration: the default BSD bindings below match this veeport's
 * network stack, so the llrio_net_* macros are left at their BSD defaults.
 *
 * It is rio-owned and self-contained: it supplies the llrio_net_* mapping,
 * the address family, and `union llrio_net_sockaddr` — the full socket-address
 * surface the rio-net sources compile against, all defined here.
 */

#ifndef  LLRIO_NET_CONFIGURATION_H
#define  LLRIO_NET_CONFIGURATION_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Compatibility sanity check value.
 * Checked by the implementation to make sure this configuration header
 * matches the version rio-net-bsd was built against.  The CCO maintainer
 * bumps this when a macro is added, deleted, or its contract changes.
 * BSP authors must not alter this value.
 */
#define LLRIO_NET_CONFIGURATION_VERSION (1)

/**
 * Platform headers that declare the functions the llrio_net_* macros map to.
 * Each BSP includes the headers its own network stack needs here so
 * any translation unit that pulls in LLRIO_NET_configuration.h gets both
 * the macros and the function declarations they expand to.
 *
 * The default includes match the BSD defaults below.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>

/**
 * By default all the llrio_net_* functions are mapped on the BSD functions.
 * Documentation (signature, etc.) for each llrio_net_* function is available
 * in the mapped BSD function documentation.
 */
#define llrio_net_accept        accept
#define llrio_net_bind          bind
#define llrio_net_close         close
#define llrio_net_connect       connect
#define llrio_net_fcntl         fcntl
#define llrio_net_gethostname   gethostname
#define llrio_net_getpeername   getpeername
#define llrio_net_getsockname   getsockname
#define llrio_net_getsockopt    getsockopt
#define llrio_net_htonl         htonl
#define llrio_net_htons         htons
/* IPv4 address marshal between Java's 4 network-order bytes and
 * struct in_addr.  On BSD/POSIX in_addr already holds the bytes in
 * network order, so this is a plain copy; a backend that stores the
 * address in host byte order overrides these with the swapping form. */
#define llrio_net_htonl_addr(dst_in_addr, src4)   memcpy((dst_in_addr), (src4), 4)
#define llrio_net_ntohl_addr(dst4, src_in_addr)   memcpy((dst4), (src_in_addr), 4)
#define llrio_net_ioctl         ioctl
#define llrio_net_listen        listen
#define llrio_net_ntohs         ntohs
#define llrio_net_recv          recv
#define llrio_net_recvfrom      recvfrom
#define llrio_net_send          send
#define llrio_net_sendto        sendto
#define llrio_net_setsockopt    setsockopt
#define llrio_net_socket        socket
#define llrio_net_shutdown      shutdown

/**
 * IPv6 scope-id resolution helpers.  Only referenced by code compiled
 * with an IPv6-enabled address family (RIO_AF_IPV6 or RIO_AF_DUAL).
 * BSPs without ifaddrs / if_nametoindex equivalents must redefine
 * these, or compile with RIO_AF_IPV4 only.
 */
#include <ifaddrs.h>
#include <net/if.h>
#define llrio_net_inet_ntop         inet_ntop
#define llrio_net_if_nametoindex    if_nametoindex
#define llrio_net_getifaddrs        getifaddrs
#define llrio_net_freeifaddrs       freeifaddrs

/**
 * Write the number of bytes available for reading into *count.
 * Returns 0 on success, -1 on error (with llrio_net_errno set).
 *
 * POSIX default: ioctl(fd, FIONREAD, count).  A BSP whose network
 * stack exposes the readable byte count through a different API
 * (a dedicated entry point) redefines this macro to call its own helper.
 */
#define llrio_net_socket_available(fd, count)   ioctl((fd), FIONREAD, (count))

/**
 * Don't modify the LLRIO_NET_AF_* constants.
 */
#define LLRIO_NET_AF_IPV4   (0x1)
#define LLRIO_NET_AF_IPV6   (0x2)
#define LLRIO_NET_AF_DUAL   ((LLRIO_NET_AF_IPV4) | (LLRIO_NET_AF_IPV6))

/**
 *  Address family:
 *  - LLRIO_NET_AF_IPV4 for only IPv4
 *  - LLRIO_NET_AF_IPV6 for only IPv6
 *  - LLRIO_NET_AF_DUAL for both IPv4 and IPv6
 */
#ifndef LLRIO_NET_AF /* LLRIO_NET_AF can be defined with a compile flag */
#define LLRIO_NET_AF (LLRIO_NET_AF_IPV4)
#endif

/**
 * Storage for an IPv4 or IPv6 socket address.  rio fills/reads it through
 * the llrio_net_* calls.  The family-specific members track LLRIO_NET_AF so an
 * IPv4-only build does not pull in sockaddr_in6, and vice versa.  `addr`
 * is the generic view passed to the BSD socket calls.
 */
union llrio_net_sockaddr {
	struct sockaddr addr;
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV4
	struct sockaddr_in in;
#endif
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV6
	struct sockaddr_in6 in6;
#endif
};

/**
 * Returns the errno value for the given file descriptor.
 * Given file descriptor may be -1 if no file descriptor is defined.
 */
#define llrio_net_errno(fd)     errno

/**
 * Binds the network-stack init function.  When LLRIO_NET_REQUIRES_INIT is
 * set, rio runs it once before the first socket operation.  By default does
 * nothing and returns success.
 */
#define llrio_net_init()    (0)

/**
 * Returns true if the network stack can be called without jeopardising
 * the system, false otherwise.  Does not imply a network interface is
 * up.  By default always returns true.
 */
#define llrio_net_is_ready()    (true)

/**
 * Set to 1 if the network stack needs an explicit bring-up and/or has a
 * "not ready yet" state — rio then runs llrio_net_init() once before the first
 * socket operation and gates every operation on llrio_net_is_ready(), throwing
 * NativeIOException(J_NETWORK_NOT_INITIALIZED) until the stack is up.
 *
 * Leave 0 for an always-ready stack (e.g. BSD sockets, where the kernel
 * stack is up before main()): the gate then compiles out entirely, so the
 * socket natives carry no per-call readiness check.
 */
#define LLRIO_NET_REQUIRES_INIT   (0)

/** @brief Set this define if the system sends SIGPIPE when the peer closes the connection. */
#if defined(__linux__) || defined(__QNXNTO__)
#define LLRIO_NET_IGNORE_SIGPIPE
#endif

#ifdef __cplusplus
}
#endif

#endif // LLRIO_NET_CONFIGURATION_H
