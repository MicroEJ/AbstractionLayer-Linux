/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/*
 * LLRIO_NET_impl.c — Network I/O for the rio Foundation Library.
 *
 * Implements socket operations (create, connect, bind, listen, accept,
 * read, write, close, sendTo, recvFrom, setOption) through the llrio_net_*
 * macros declared in LLRIO_NET_configuration.h.  Defaults bind those macros
 * to the POSIX/BSD socket API; BSPs whose network stack has different
 * symbol names override the macros in their LLRIO_NET_configuration.h copy
 * without touching this file.
 *
 * The address family is selected at compile time via LLRIO_NET_AF in
 * LLRIO_NET_configuration.h:
 *   - LLRIO_NET_AF_IPV4: AF_INET sockets, sockaddr_in.
 *   - LLRIO_NET_AF_IPV6: AF_INET6 sockets, sockaddr_in6.
 *   - LLRIO_NET_AF_DUAL: AF_INET6 + IPV6_V6ONLY=0, IPv4 mapped to
 *     ::ffff:x.x.x.x.
 *
 * Poll registry and event loop are in the rio-core CCO.
 */

#include "LLRIO_NET_impl.h"
#include "LLRIO_NET_configuration.h"
#include "rio.h"
#include "rio_errors.h"
#include "sni.h"

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

VEEPORT_LOGGER_DEFINE_MODULE(LLRIO_LOG_MODULE_NAME, LLRIO_LOG_LEVEL)

/* IPv6 16-byte address access.  POSIX `struct in6_addr` exposes the
 * bytes as `.s6_addr`; a backend whose in6_addr names them differently
 * (e.g. via a byte-array member) overrides this macro in its
 * LLRIO_NET_configuration.h. */
#ifndef llrio_net_in6_bytes
#define llrio_net_in6_bytes(sin6_addr)  ((sin6_addr).s6_addr)
#endif

/* TCP_NODELAY / IPPROTO_TCP are optional on BSPs whose network stack
 * does not expose the TCP nagle-off option.  When absent the two
 * TCP_NODELAY cases (set / get) throw `NativeIOException` with
 * J_ENOPROTOOPT; see the `#if defined(TCP_NODELAY) ...` gates below. */

/* Map POSIX errno to a MicroEJ Java error code.  Exposed (non-static) so the
 * net layer that composes rio shares this single mapping instead of carrying
 * its own duplicate switch. */
int32_t LLRIO_NET_map_errno_to_java(int32_t posix_errno) {
	switch (posix_errno) {
	case EACCES:
		return J_EACCES;
	case EBADF:
		return J_EBADF;
#ifdef ENETDOWN
	case ENETDOWN:
		return J_ENETDOWN;
#endif
	case ENETUNREACH:
		return J_ENETUNREACH;
	case EADDRINUSE:
		return J_EADDRINUSE;
	case ECONNABORTED:
		return J_ECONNABORTED;
	case EINVAL:
		return J_EINVAL;
	case ENOPROTOOPT:
		return J_ENOPROTOOPT;
	case ENOTCONN:
		return J_ENOTCONN;
	case ECONNREFUSED:
		return J_ECONNREFUSED;
	case EISCONN:
		return J_EISCONN;
	case ECONNRESET:
		return J_ECONNRESET;
	case EMSGSIZE:
		return J_EMSGSIZE;
	case EPIPE:
		return J_EPIPE;
	case ETIMEDOUT:
		return J_ETIMEDOUT;
	case ENOMEM:
		return J_ENOMEM;
#ifdef EHOSTUNREACH
	case EHOSTUNREACH:
		return J_EHOSTUNREACH;
#endif
	case EADDRNOTAVAIL:
		return J_EADDRNOTAVAIL;
	case EAFNOSUPPORT:
		return J_EAFNOSUPPORT;
#ifdef EHOSTDOWN
	case EHOSTDOWN:
		return J_EHOSTDOWN;
#endif
	/* Buffer / descriptor / store exhaustion all surface to Java as
	 * out-of-memory — the app's recourse is the same. */
	case ENOBUFS:
#ifdef ENOSPC
	case ENOSPC:
#endif
#ifdef ENFILE
	case ENFILE:
#endif
		return J_ENOMEM;
	default:
		return J_EUNKNOWN;
	}
}

void LLRIO_throw_errno(int32_t posix_errno) {
	int32_t error_code = LLRIO_NET_map_errno_to_java(posix_errno);
	if (J_EUNKNOWN == error_code) {
		VEEPORT_ERRORS_throw_caught_exception_message(error_code, "%s (%d)", strerror(posix_errno), posix_errno);
	} else {
		VEEPORT_LOGGER_LOG_DBG("errno %d: %s", posix_errno, strerror(posix_errno));
		VEEPORT_ERRORS_throw_caught_exception(error_code);
	}
}

/*
 * Network-stack readiness gate.
 *
 * Only compiled in when the BSP sets LLRIO_NET_REQUIRES_INIT (its stack
 * needs an explicit bring-up and/or has a not-ready-yet state).  Then rio owns
 * bringing the stack up: the first net native runs llrio_net_init() once (lazily —
 * there is no separate subsystem-init entry point on the rio side), and every
 * net native confirms the stack is usable before touching it.
 *
 * On an always-ready stack (LLRIO_NET_REQUIRES_INIT == 0, e.g. BSD sockets)
 * this is a constant `return true`, so the guard at the top of each native
 * optimizes away — the socket path carries no per-call readiness check.
 *
 * Returns true when the caller may proceed; otherwise throws
 * NativeIOException(J_NETWORK_NOT_INITIALIZED) and returns false so the caller
 * bails with its ignored return value.  The lazy flag is only ever touched
 * from the VM C task (where these natives run), so it needs no locking.
 */
static bool rio_net_ready(void) {
#if LLRIO_NET_REQUIRES_INIT
	static bool initialized = false;
	if (!initialized) {
		if (llrio_net_init() != 0) {
			VEEPORT_ERRORS_throw_caught_exception(J_NETWORK_NOT_INITIALIZED);
			return false;
		}
		initialized = true;
	}
	if (!llrio_net_is_ready()) {
		VEEPORT_ERRORS_throw_caught_exception(J_NETWORK_NOT_INITIALIZED);
		return false;
	}
#endif
	return true;
}

/* ── Helper: set a socket to non-blocking mode ──────────────── */

static int set_nonblocking(int fd) {
	int flags = llrio_net_fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}
	return llrio_net_fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Sockaddr union (`union llrio_net_sockaddr` — `addr`, `in`, `in6`) is
 * supplied by the BSP through LLRIO_NET_configuration.h.  This lets a BSP
 * whose network stack uses a different sockaddr layout (e.g. one with host
 * byte order) plug in its own types without editing this file. */

/* A backend may define resolve_ipv6_scope_id() itself (e.g. a
 * single-interface stack where the scope is constant) — only provide
 * this getifaddrs-walk default when it hasn't. */
#if (LLRIO_NET_AF & LLRIO_NET_AF_IPV6) && !defined(resolve_ipv6_scope_id)
/**
 * Resolves the scope ID for a link-local IPv6 address.
 *
 * Link-local addresses (fe80::/10) require sin6_scope_id so the kernel
 * knows which interface to use.  Walks llrio_net_getifaddrs(), matches the IP,
 * and returns llrio_net_if_nametoindex() for the matching interface.
 *
 * @param addr the IPv6 address (16 bytes).
 * @return the scope ID, or 0 if not found.
 */
static uint32_t resolve_ipv6_scope_id(const jbyte *addr) {
	char addr_str[INET6_ADDRSTRLEN];
	llrio_net_inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));

	uint32_t scope = 0;
	struct ifaddrs *addrs;
	if (llrio_net_getifaddrs(&addrs) == 0) {
		for (struct ifaddrs *ifa = addrs; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
				char ifa_str[INET6_ADDRSTRLEN];
				struct sockaddr_in6 *sa6 =
					(struct sockaddr_in6 *)ifa->ifa_addr;
				llrio_net_inet_ntop(AF_INET6, &sa6->sin6_addr,
				                    ifa_str, sizeof(ifa_str));
				if (strcmp(addr_str, ifa_str) == 0) {
					scope = llrio_net_if_nametoindex(ifa->ifa_name);
					break;
				}
			}
		}
		llrio_net_freeifaddrs(addrs);
	}
	return scope;
}

#endif

/* ── Helper: build a sockaddr from ip bytes + port ──────────────
 *
 * Selects the sockaddr type based on LLRIO_NET_AF and the address length:
 *   - LLRIO_NET_AF_IPV4:  4-byte addr → sockaddr_in.
 *   - LLRIO_NET_AF_IPV6:  16-byte addr → sockaddr_in6.
 *   - LLRIO_NET_AF_DUAL:  4-byte → sockaddr_in6 with ::ffff: mapping,
 *                   16-byte → sockaddr_in6 directly.
 *
 * Returns the sockaddr size, or 0 on invalid address length. */

static socklen_t build_sockaddr(union llrio_net_sockaddr *out,
                                const jbyte *ip, jint ip_len, jint port) {
	memset(out, 0, sizeof(*out));

#if LLRIO_NET_AF == LLRIO_NET_AF_IPV4
	if (ip_len == 4) {
		out->in.sin_family = AF_INET;
		out->in.sin_port = llrio_net_htons((uint16_t)port);
		llrio_net_htonl_addr(&out->in.sin_addr, ip);
		return sizeof(struct sockaddr_in);
	}
#endif

#if LLRIO_NET_AF == LLRIO_NET_AF_DUAL
	if (ip_len == 4) {
		/* Map IPv4 to ::ffff:x.x.x.x on dual-stack socket. */
		out->in6.sin6_family = AF_INET6;
		out->in6.sin6_port = llrio_net_htons((uint16_t)port);
		llrio_net_in6_bytes(out->in6.sin6_addr)[10] = 0xFF;
		llrio_net_in6_bytes(out->in6.sin6_addr)[11] = 0xFF;
		memcpy(&llrio_net_in6_bytes(out->in6.sin6_addr)[12], ip, 4);
		return sizeof(struct sockaddr_in6);
	}
#endif

#if LLRIO_NET_AF & LLRIO_NET_AF_IPV6
	if (ip_len == 16) {
		out->in6.sin6_family = AF_INET6;
		out->in6.sin6_port = llrio_net_htons((uint16_t)port);
		memcpy(&out->in6.sin6_addr, ip, 16);
		/* Resolve scope ID for this address.  Link-local (fe80::/10)
		 * requires it; for other addresses it returns 0 (harmless). */
		out->in6.sin6_scope_id = resolve_ipv6_scope_id(ip);
		return sizeof(struct sockaddr_in6);
	}
#endif

	return 0; /* invalid address length for configured LLRIO_NET_AF */
}

/* ── Helper: unpack a sockaddr into 19-byte layout ──────────────
 *
 * Layout: [0]=addrLen, [1..16]=addr (zero-padded), [17..18]=port BE.
 *
 * Handles both sockaddr_in (AF_INET) and sockaddr_in6 (AF_INET6).
 * For AF_INET6, detects IPv4-mapped (::ffff:x.x.x.x) and writes
 * 4-byte IPv4 instead of 16-byte IPv6. */

static void unpack_sockaddr(const union llrio_net_sockaddr *addr,
                            jbyte *out) {
	memset(out, 0, 19);

	if (addr->addr.sa_family == AF_INET) {
		out[0] = 4;
		llrio_net_ntohl_addr(&out[1], &addr->in.sin_addr);
		uint16_t port = llrio_net_ntohs(addr->in.sin_port);
		out[17] = (jbyte)(port >> 8);
		out[18] = (jbyte)(port & 0xFF);
		return;
	}

#if LLRIO_NET_AF & LLRIO_NET_AF_IPV6
	/* AF_INET6 */
	const uint8_t *a = llrio_net_in6_bytes(addr->in6.sin6_addr);

	/* Detect IPv4-mapped: first 10 bytes zero, bytes 10-11 are 0xFF. */
	bool is_v4_mapped = true;
	for (int i = 0; i < 10; i++) {
		if (a[i] != 0) {
			is_v4_mapped = false;
			break;
		}
	}
	if (is_v4_mapped && a[10] == 0xFF && a[11] == 0xFF) {
		out[0] = 4;
		memcpy(&out[1], &a[12], 4);
	} else {
		out[0] = 16;
		memcpy(&out[1], a, 16);
	}

	uint16_t port = llrio_net_ntohs(addr->in6.sin6_port);
	out[17] = (jbyte)(port >> 8);
	out[18] = (jbyte)(port & 0xFF);
#endif
}

/* ── Helper: extract port from a sockaddr ────────────────────── */

static uint16_t sockaddr_port(const union llrio_net_sockaddr *addr) {
	if (addr->addr.sa_family == AF_INET) {
		return llrio_net_ntohs(addr->in.sin_port);
	}
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV6
	return llrio_net_ntohs(addr->in6.sin6_port);
#else
	return 0;
#endif
}

/* ── Helper: create a socket for the configured address family ── */

static int create_socket(int type) {
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV6
	/* IPv6 or dual-stack: create AF_INET6 socket. */
	int fd = llrio_net_socket(AF_INET6, type, 0);
	if (fd < 0) {
		return -1;
	}
#if LLRIO_NET_AF == LLRIO_NET_AF_DUAL
	/* Dual-stack: allow both IPv4 and IPv6 on a single socket. */
	int off = 0;
	llrio_net_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
#endif
	return fd;
#else
	/* IPv4 only. */
	return llrio_net_socket(AF_INET, type, 0);
#endif
}

/* ── getWildcardAddress ──────────────────────────────────────── */

jint LLRIO_NET_IMPL_getWildcardAddress(jbyte *dst, jint dstLength) {
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV6
	/* IPv6 or dual-stack: return :: (16 zero bytes). */
	const jint needed = 16;
#else
	/* IPv4 only: return 0.0.0.0 (4 zero bytes). */
	const jint needed = 4;
#endif
	/* Honor the caller's buffer length rather than trusting it: refuse to
	 * write past a short buffer. */
	if (dstLength < needed) {
		VEEPORT_LOGGER_LOG_DBG("wildcard buffer too small");
		VEEPORT_ERRORS_throw_caught_exception(J_EINVAL);
		return SNI_IGNORED_RETURNED_VALUE;
	}
	/* The wildcard is all-zero bytes (0.0.0.0 / ::).  memset writes them
	 * backend-neutrally: INADDR_ANY / IN6ADDR_ANY_INIT are not available under
	 * standard names on backends without a POSIX <netinet/in.h>. */
	memset(dst, 0, needed);
	return needed;
}

/* ── createSocket ────────────────────────────────────────────── */

/* Defined below near close(): the SNI close function for socket fds
 * registered for close-on-GC.  Forward-declared so createSocket/accept can
 * register the fd at creation time. */
static void net_close_resource(void *resource);

jint LLRIO_NET_IMPL_createSocket(jint type) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	int sock_type = (type == LLRIO_NET_TYPE_STREAM)
	                    ? SOCK_STREAM : SOCK_DGRAM;

	int fd = create_socket(sock_type);
	if (fd < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
		return SNI_IGNORED_RETURNED_VALUE;
	}

	if (set_nonblocking(fd) < 0) {
		int saved_errno = llrio_net_errno(fd);
		llrio_net_close(fd);
		LLRIO_throw_errno(saved_errno);
		return SNI_IGNORED_RETURNED_VALUE;
	}

	/* Register the fd for close-on-GC / close-on-stop in the same native that
	 * creates it: the fd is its own resource id (SNI_registerResource keys on
	 * it), so the returned fd doubles as the resource id the Java side passes to
	 * NativeResource.closeOnGC.  A full registry fails creation loudly. */
	if (SNI_registerResource((void *)(intptr_t)fd, net_close_resource, NULL) != SNI_OK) {
		llrio_net_close(fd);
		VEEPORT_LOGGER_LOG_ERR("rio: native resource registry full");
		VEEPORT_ERRORS_throw_caught_exception(J_ENOMEM);
		return SNI_IGNORED_RETURNED_VALUE;
	}

	return (jint)fd;
}

/* ── connect ─────────────────────────────────────────────────── */

void LLRIO_NET_IMPL_connect(jint fd, jbyte *ip_address,
                            jint ip_address_length, jint port) {
	if (!rio_net_ready()) {
		return;
	}

	union llrio_net_sockaddr addr;
	socklen_t addr_len = build_sockaddr(&addr, ip_address, ip_address_length, port);
	if (addr_len == 0) {
		VEEPORT_LOGGER_LOG_DBG("invalid address length for configured LLRIO_NET_AF");
		VEEPORT_ERRORS_throw_caught_exception(J_EINVAL);
		return;
	}

	int ret = llrio_net_connect((int)fd, &addr.addr, addr_len);
	if (ret < 0 && llrio_net_errno(fd) != EINPROGRESS && llrio_net_errno(fd) != EISCONN) {
		LLRIO_throw_errno(llrio_net_errno(fd));
	}
}

/* ── disconnect ──────────────────────────────────────────────── */

void LLRIO_NET_IMPL_disconnect(jint fd) {
	if (!rio_net_ready()) {
		return;
	}

	/* Dissolve any peer association (java.net DatagramSocket.disconnect):
	 * connect() to an AF_UNSPEC address — the POSIX UDP-disconnect idiom,
	 * which returns 0 on the reference BSD/POSIX stacks. */
	union llrio_net_sockaddr addr;
	memset(&addr, 0, sizeof(addr));
	addr.addr.sa_family = AF_UNSPEC;

	int ret = llrio_net_connect((int)fd, &addr.addr, sizeof(addr.addr));
	if (ret < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
	}
}

/* ── bind ────────────────────────────────────────────────────── */

void LLRIO_NET_IMPL_bind(jint fd, jbyte *ip_address,
                         jint ip_address_length, jint port) {
	if (!rio_net_ready()) {
		return;
	}

	union llrio_net_sockaddr addr;
	socklen_t addr_len = build_sockaddr(&addr, ip_address, ip_address_length, port);
	if (addr_len == 0) {
		VEEPORT_LOGGER_LOG_DBG("invalid address length for configured LLRIO_NET_AF");
		VEEPORT_ERRORS_throw_caught_exception(J_EINVAL);
		return;
	}

	int ret = llrio_net_bind((int)fd, &addr.addr, addr_len);
	if (ret < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
	}
}

/* ── listen ──────────────────────────────────────────────────── */

void LLRIO_NET_IMPL_listen(jint fd, jint backlog) {
	if (!rio_net_ready()) {
		return;
	}

	if (llrio_net_listen((int)fd, (int)backlog) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
	}
}

/* ── accept ──────────────────────────────────────────────────── */

jint LLRIO_NET_IMPL_accept(jint server_fd) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	/* Use plain accept() + set_nonblocking() rather than Linux-specific
	 * accept4(SOCK_NONBLOCK).  Two reasons: (1) accept4 is a GNU/Linux
	 * extension not portable to every BSP's network stack; (2) the tiny
	 * window where the new fd is blocking is harmless because the fd
	 * is not yet published to any Java thread. */
	int client_fd = llrio_net_accept((int)server_fd, NULL, NULL);
	if (client_fd < 0) {
		if (llrio_net_errno(server_fd) == EAGAIN || llrio_net_errno(server_fd) == EWOULDBLOCK) {
			return -1;
		}
		LLRIO_throw_errno(llrio_net_errno(server_fd));
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (set_nonblocking(client_fd) < 0) {
		int saved_errno = llrio_net_errno(client_fd);
		llrio_net_close(client_fd);
		LLRIO_throw_errno(saved_errno);
		return SNI_IGNORED_RETURNED_VALUE;
	}
	/* Register the accepted fd for close-on-GC at creation (same as createSocket):
	 * the fd is its own resource id. */
	if (SNI_registerResource((void *)(intptr_t)client_fd, net_close_resource, NULL) != SNI_OK) {
		llrio_net_close(client_fd);
		VEEPORT_LOGGER_LOG_ERR("rio: native resource registry full");
		VEEPORT_ERRORS_throw_caught_exception(J_ENOMEM);
		return SNI_IGNORED_RETURNED_VALUE;
	}
	return (jint)client_fd;
}

/* ── shutdown ────────────────────────────────────────────────── */

void LLRIO_NET_IMPL_shutdown(jint fd, jint how) {
	/* how: 0 = SHUT_RD, 1 = SHUT_WR — matches POSIX values.
	 * Best-effort: don't throw on failure.  Shutdown on an
	 * unconnected or already-closed socket returns ENOTCONN/EBADF
	 * which is harmless during cleanup. */
	llrio_net_shutdown((int)fd, (int)how);
}

/* ── close ───────────────────────────────────────────────────── */

/* SNI close function for a socket fd registered at creation (createSocket /
 * accept).  The VM runs it on the VM C task when the owning Java object is
 * garbage collected, and on application/VM stop.  Resource is the fd. */
static void net_close_resource(void *resource) {
	int fd = (int)(intptr_t)resource;
	rio_close_fd(fd);   /* wake any waiter — none on GC; torn down on stop */
	llrio_net_close(fd);
}

jint LLRIO_NET_IMPL_close(jint fd) {
	/* Wake any thread suspended on this fd before closing it —
	 * the kernel's poll()/select() does not auto-unblock on
	 * a concurrent close on Linux, so we have to surface the
	 * close to rio explicitly. */
	rio_close_fd((int)fd);
	/* Cancel the close-on-GC / close-on-stop registration (if any) so the VM
	 * does not close the fd a second time. */
	SNI_unregisterResource((void *)(intptr_t)fd, net_close_resource);
	int ret = llrio_net_close((int)fd);
	return ret == 0 ? 0 : -1;
}

jlong LLRIO_NET_IMPL_nativeResourceCloseFunctionId(void) {
	/* closeFunction for NativeResource.closeOnGC: the net_close_resource
	 * address (the close registered by createSocket / accept). */
	return (jlong)(intptr_t)net_close_resource;
}

/* ── getLocalPort ────────────────────────────────────────────── */

jint LLRIO_NET_IMPL_getLocalPort(jint fd) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	union llrio_net_sockaddr addr;
	socklen_t len = sizeof(addr);

	if (llrio_net_getsockname((int)fd, &addr.addr, &len) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
		return SNI_IGNORED_RETURNED_VALUE;
	}

	return (jint)sockaddr_port(&addr);
}

/* ── getLocalAddress ─────────────────────────────────────────── */

void LLRIO_NET_IMPL_getLocalAddress(jint fd, jbyte *local_addr) {
	if (!rio_net_ready()) {
		return;
	}

	union llrio_net_sockaddr addr;
	socklen_t len = sizeof(addr);

	if (llrio_net_getsockname((int)fd, &addr.addr, &len) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
		return;
	}

	unpack_sockaddr(&addr, local_addr);
}

/* ── getRemoteAddress ────────────────────────────────────────── */

void LLRIO_NET_IMPL_getRemoteAddress(jint fd, jbyte *remote_addr) {
	if (!rio_net_ready()) {
		return;
	}

	union llrio_net_sockaddr addr;
	socklen_t len = sizeof(addr);

	if (llrio_net_getpeername((int)fd, &addr.addr, &len) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
		return;
	}

	unpack_sockaddr(&addr, remote_addr);
}

/* ── setOption ───────────────────────────────────────────────── */

void LLRIO_NET_IMPL_setOption(jint fd, jint option, jint value) {
	if (!rio_net_ready()) {
		return;
	}

	int val = (int)value;
	int level;
	int optname;

	switch (option) {
	case LLRIO_NET_OPTION_SO_REUSEADDR:
		level = SOL_SOCKET;
		optname = SO_REUSEADDR;
		val = val ? 1 : 0;
		break;
	case LLRIO_NET_OPTION_SO_KEEPALIVE:
		level = SOL_SOCKET;
		optname = SO_KEEPALIVE;
		val = val ? 1 : 0;
		break;
	case LLRIO_NET_OPTION_SO_BROADCAST:
		level = SOL_SOCKET;
		optname = SO_BROADCAST;
		val = val ? 1 : 0;
		break;
	case LLRIO_NET_OPTION_SO_LINGER:
	{
		/* val == -1: linger disabled.
		 * val >= 0: linger enabled, timeout = val seconds. */
		struct linger lg;
		lg.l_onoff = (val >= 0) ? 1 : 0;
		lg.l_linger = (val >= 0) ? val : 0;
		if (llrio_net_setsockopt((int)fd, SOL_SOCKET, SO_LINGER,
		                         &lg, sizeof(lg)) < 0) {
			LLRIO_throw_errno(llrio_net_errno(fd));
		}
		return;
	}
	case LLRIO_NET_OPTION_TCP_NODELAY:
#if defined(TCP_NODELAY) && defined(IPPROTO_TCP)
		level = IPPROTO_TCP;
		optname = TCP_NODELAY;
		val = val ? 1 : 0;
		break;
#else
		/* BSP did not supply TCP_NODELAY / IPPROTO_TCP — the option is
		 * unsupported on this platform.  Throw cleanly rather than
		 * forwarding arbitrary constants to setsockopt. */
		VEEPORT_LOGGER_LOG_DBG("TCP_NODELAY not supported");
		VEEPORT_ERRORS_throw_caught_exception(J_ENOPROTOOPT);
		return;
#endif
	case LLRIO_NET_OPTION_SO_SNDBUF:
		level = SOL_SOCKET;
		optname = SO_SNDBUF;
		break;
	case LLRIO_NET_OPTION_SO_RCVBUF:
		level = SOL_SOCKET;
		optname = SO_RCVBUF;
		break;
	case LLRIO_NET_OPTION_IP_TOS:
		level = IPPROTO_IP;
		optname = IP_TOS;
		break;
	case LLRIO_NET_OPTION_SO_OOBINLINE:
		level = SOL_SOCKET;
		optname = SO_OOBINLINE;
		val = val ? 1 : 0;
		break;
	case LLRIO_NET_OPTION_IP_TTL:
		/* TTL option maps to IP_MULTICAST_TTL; delegate to setMulticastTtl
		 * which handles both IPv4 and IPv6. */
		LLRIO_NET_IMPL_setMulticastTtl(fd, value);
		return;
	case LLRIO_NET_OPTION_IP_MULTICAST_LOOP:
	{
		int loop_val = val ? 1 : 0;
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV4
		if (llrio_net_setsockopt((int)fd, IPPROTO_IP, IP_MULTICAST_LOOP,
		                         &loop_val, sizeof(loop_val)) < 0) {
			LLRIO_throw_errno(llrio_net_errno(fd));
			return;
		}
#endif
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV6
		if (llrio_net_setsockopt((int)fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		                         &loop_val, sizeof(loop_val)) < 0) {
			LLRIO_throw_errno(llrio_net_errno(fd));
		}
#endif
	}
		return;
	default:
		VEEPORT_LOGGER_LOG_DBG("unknown socket option");
		VEEPORT_ERRORS_throw_caught_exception(J_ENOPROTOOPT);
		return;
	}

	if (llrio_net_setsockopt((int)fd, level, optname, &val, sizeof(val)) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
	}
}

/* ── getOption ────────────────────────────────────────────────── */

jint LLRIO_NET_IMPL_getOption(jint fd, jint option) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	int val = 0;
	int level;
	int optname;
	socklen_t optlen = sizeof(val);

	switch (option) {
	case LLRIO_NET_OPTION_SO_REUSEADDR:
		level = SOL_SOCKET;
		optname = SO_REUSEADDR;
		break;
	case LLRIO_NET_OPTION_SO_KEEPALIVE:
		level = SOL_SOCKET;
		optname = SO_KEEPALIVE;
		break;
	case LLRIO_NET_OPTION_SO_BROADCAST:
		level = SOL_SOCKET;
		optname = SO_BROADCAST;
		break;
	case LLRIO_NET_OPTION_SO_SNDBUF:
		level = SOL_SOCKET;
		optname = SO_SNDBUF;
		break;
	case LLRIO_NET_OPTION_SO_RCVBUF:
		level = SOL_SOCKET;
		optname = SO_RCVBUF;
		break;
	case LLRIO_NET_OPTION_TCP_NODELAY:
#if defined(TCP_NODELAY) && defined(IPPROTO_TCP)
		level = IPPROTO_TCP;
		optname = TCP_NODELAY;
		break;
#else
		VEEPORT_LOGGER_LOG_DBG("TCP_NODELAY not supported");
		VEEPORT_ERRORS_throw_caught_exception(J_ENOPROTOOPT);
		return SNI_IGNORED_RETURNED_VALUE;
#endif
	case LLRIO_NET_OPTION_IP_MULTICAST_LOOP:
		level = IPPROTO_IP;
		optname = IP_MULTICAST_LOOP;
		break;
	case LLRIO_NET_OPTION_IP_TOS:
		level = IPPROTO_IP;
		optname = IP_TOS;
		break;
	case LLRIO_NET_OPTION_SO_OOBINLINE:
		level = SOL_SOCKET;
		optname = SO_OOBINLINE;
		break;
	case LLRIO_NET_OPTION_IP_TTL:
		return LLRIO_NET_IMPL_getMulticastTtl(fd);
	case LLRIO_NET_OPTION_SO_LINGER:
	{
		struct linger lg = { 0 };
		socklen_t lg_len = sizeof(lg);
		if (llrio_net_getsockopt((int)fd, SOL_SOCKET, SO_LINGER, &lg, &lg_len) < 0) {
			LLRIO_throw_errno(llrio_net_errno(fd));
			return SNI_IGNORED_RETURNED_VALUE;
		}
		return lg.l_onoff == 0 ? -1 : (jint)lg.l_linger;
	}
	default:
		VEEPORT_LOGGER_LOG_DBG("unknown socket option");
		VEEPORT_ERRORS_throw_caught_exception(J_ENOPROTOOPT);
		return SNI_IGNORED_RETURNED_VALUE;
	}

	if (llrio_net_getsockopt((int)fd, level, optname, &val, &optlen) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
		return SNI_IGNORED_RETURNED_VALUE;
	}
	return (jint)val;
}

/* ── getOptionAsByteArray ────────────────────────────────────── */

jint LLRIO_NET_IMPL_getOptionAsByteArray(jint fd, jint option,
                                         jbyte *dst, jint dstLength) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	switch (option) {
	case LLRIO_NET_OPTION_IP_MULTICAST_IF:
	case LLRIO_NET_OPTION_IP_MULTICAST_IF2:
	{
		/* IPv4 multicast interface: returns the 4-byte interface
		 * address.  Using uint32_t instead of `struct in_addr` keeps
		 * the code portable to BSPs whose IPv4 address type is a bare
		 * integer without a `.s_addr` sub-field. */
		if ((uint32_t)dstLength < 4) {
			VEEPORT_LOGGER_LOG_DBG("buffer too small");
			VEEPORT_ERRORS_throw_caught_exception(J_EINVAL);
			return SNI_IGNORED_RETURNED_VALUE;
		}
		socklen_t opt_len = 4;
		if (llrio_net_getsockopt((int)fd, IPPROTO_IP, IP_MULTICAST_IF, dst, &opt_len) < 0) {
			LLRIO_throw_errno(llrio_net_errno(fd));
			return SNI_IGNORED_RETURNED_VALUE;
		}
		return (jint)opt_len;
	}
	default:
		VEEPORT_LOGGER_LOG_DBG("unknown socket option");
		VEEPORT_ERRORS_throw_caught_exception(J_ENOPROTOOPT);
		return SNI_IGNORED_RETURNED_VALUE;
	}
}

/* ── setOptionAsByteArray ────────────────────────────────────── */

void LLRIO_NET_IMPL_setOptionAsByteArray(jint fd, jint option,
                                         jbyte *value, jint valueLength) {
	if (!rio_net_ready()) {
		return;
	}

	switch (option) {
	case LLRIO_NET_OPTION_IP_MULTICAST_IF:
	case LLRIO_NET_OPTION_IP_MULTICAST_IF2:
		if (valueLength == 4) {
			/* IPv4: set IP_MULTICAST_IF directly with the 4-byte
			 * interface address.  Same rationale as getOptionAsByteArray
			 * above — avoid the POSIX-only `struct in_addr`. */
			if (llrio_net_setsockopt((int)fd, IPPROTO_IP, IP_MULTICAST_IF,
			                         value, 4) < 0) {
				LLRIO_throw_errno(llrio_net_errno(fd));
			}
			return;
		}
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV6
		if (valueLength == 16) {
			/* IPv6 address: resolve to interface index via getifaddrs,
			 * then set IPV6_MULTICAST_IF. */
			unsigned int idx = resolve_ipv6_scope_id(value);
			if (llrio_net_setsockopt((int)fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			                         &idx, sizeof(idx)) < 0) {
				LLRIO_throw_errno(llrio_net_errno(fd));
			}
			return;
		}
#endif
		VEEPORT_LOGGER_LOG_DBG("wrong option length");
		VEEPORT_ERRORS_throw_caught_exception(J_EINVAL);
		return;
	default:
		VEEPORT_LOGGER_LOG_DBG("unknown socket option");
		VEEPORT_ERRORS_throw_caught_exception(J_ENOPROTOOPT);
	}
}

/* ── getMulticastTtl ─────────────────────────────────────────── */

jint LLRIO_NET_IMPL_getMulticastTtl(jint fd) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	int ttl = 0;
	socklen_t optlen = sizeof(ttl);
	if (llrio_net_getsockopt((int)fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, &optlen) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
		return SNI_IGNORED_RETURNED_VALUE;
	}
	return (jint)ttl;
}

/* ── setMulticastInterfaceV4 ──────────────────────────────────── */

void LLRIO_NET_IMPL_setMulticastInterfaceV4(jint fd, jbyte *if_address) {
	if (!rio_net_ready()) {
		return;
	}

	/* Pass the 4-byte interface address through to setsockopt as-is.
	 * The intermediate `struct in_addr` copy was unnecessary even on
	 * POSIX (sockopt takes `void *` + length), and non-portable to
	 * stacks that don't declare `struct in_addr`. */
	if (llrio_net_setsockopt((int)fd, IPPROTO_IP, IP_MULTICAST_IF,
	                         if_address, 4) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
	}
}

/* ── setMulticastInterfaceV6 ──────────────────────────────────── */

void LLRIO_NET_IMPL_setMulticastInterfaceV6(jint fd, jint interface_index) {
	if (!rio_net_ready()) {
		return;
	}

	unsigned int idx = (unsigned int)interface_index;
	if (llrio_net_setsockopt((int)fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
	                         &idx, sizeof(idx)) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
	}
}

/* ── setMulticastTtl ─────────────────────────────────────────── */

void LLRIO_NET_IMPL_setMulticastTtl(jint fd, jint ttl) {
	if (!rio_net_ready()) {
		return;
	}

	int val = (int)ttl;
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV4
	if (llrio_net_setsockopt((int)fd, IPPROTO_IP, IP_MULTICAST_TTL,
	                         &val, sizeof(val)) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
		return;
	}
#endif
#if LLRIO_NET_AF & LLRIO_NET_AF_IPV6
	if (llrio_net_setsockopt((int)fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
	                         &val, sizeof(val)) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
	}
#endif
}

/* ── joinOrLeave ─────────────────────────────────────────────── */

void LLRIO_NET_IMPL_joinOrLeave(jint fd, jboolean join,
                                jbyte *mcast_addr, jint mcast_addr_len,
                                jbyte *netif_addr, jint netif_addr_len) {
	if (!rio_net_ready()) {
		return;
	}

	if (mcast_addr_len == 4) {
		/* IPv4: IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP.
		 * Populate both imr_multiaddr and imr_interface through memcpy
		 * so we don't touch the POSIX-only `.s_addr` sub-field.  For
		 * the "any interface" case, INADDR_ANY is all-zero bytes in
		 * every byte order, so memset gives the same result as
		 * setting s_addr = htonl(INADDR_ANY). */
		struct ip_mreq mreq;
		memcpy(&mreq.imr_multiaddr, mcast_addr, 4);
		if (netif_addr_len >= 4) {
			memcpy(&mreq.imr_interface, netif_addr, 4);
		} else {
			memset(&mreq.imr_interface, 0, 4);
		}
		int optname = join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
		if (llrio_net_setsockopt((int)fd, IPPROTO_IP, optname,
		                         &mreq, sizeof(mreq)) < 0) {
			LLRIO_throw_errno(llrio_net_errno(fd));
		}
	} else if (mcast_addr_len == 16) {
		/* IPv6: IPV6_JOIN_GROUP / IPV6_LEAVE_GROUP */
		struct ipv6_mreq mreq6;
		memcpy(&mreq6.ipv6mr_multiaddr, mcast_addr, 16);
		if (netif_addr_len >= 4) {
			/* Interface index passed as 4-byte big-endian. */
			mreq6.ipv6mr_interface = (unsigned int)(
				((unsigned char)netif_addr[0] << 24) |
				((unsigned char)netif_addr[1] << 16) |
				((unsigned char)netif_addr[2] << 8) |
				(unsigned char)netif_addr[3]);
		} else {
			mreq6.ipv6mr_interface = 0;
		}
		int optname = join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP;
		if (llrio_net_setsockopt((int)fd, IPPROTO_IPV6, optname,
		                         &mreq6, sizeof(mreq6)) < 0) {
			LLRIO_throw_errno(llrio_net_errno(fd));
		}
	} else {
		VEEPORT_LOGGER_LOG_DBG("Invalid multicast address length");
		VEEPORT_ERRORS_throw_caught_exception(J_EINVAL);
	}
}

/* ── socketAvailable ─────────────────────────────────────────── */

jint LLRIO_NET_IMPL_socketAvailable(jint fd) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	/* llrio_net_socket_available writes the peer-ready byte count into
	 * *count.  POSIX default is ioctl(FIONREAD); a BSP whose stack
	 * exposes the byte count through a different API redefines the
	 * macro in LLRIO_NET_configuration.h. */
	int count = 0;
	if (llrio_net_socket_available((int)fd, &count) < 0) {
		LLRIO_throw_errno(llrio_net_errno(fd));
		return SNI_IGNORED_RETURNED_VALUE;
	}
	return (jint)count;
}

/* ── socketWrite ─────────────────────────────────────────────── */

jint LLRIO_NET_IMPL_socketWrite(jint fd, jbyte *data, jint offset, jint length) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	/* Use send() with MSG_NOSIGNAL instead of write() so that
	 * writing to a broken connection returns EPIPE as errno
	 * instead of raising SIGPIPE (which would kill the process
	 * or cause a busy-loop if the signal is ignored). */
	ssize_t n = llrio_net_send((int)fd, data + offset, (size_t)length, MSG_NOSIGNAL);
	if (n < 0) {
		int err = llrio_net_errno(fd);
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return 0;
		}
		/* Map ENOTCONN to EBADF for async close consistency. */
		if (err == ENOTCONN) {
			err = EBADF;
		}
		LLRIO_throw_errno(err);
		return SNI_IGNORED_RETURNED_VALUE;
	}
	return (jint)n;
}

/* ── socketRead ──────────────────────────────────────────────── */

jint LLRIO_NET_IMPL_socketRead(jint fd, jbyte *buffer, jint offset, jint length) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	/* Use llrio_net_recv() with flags=0 instead of read() so the BSP's
	 * llrio_net_recv mapping covers both one-shot and peer-byte-count
	 * read paths without needing a separate llrio_net_read macro. */
	ssize_t n = llrio_net_recv((int)fd, buffer + offset, (size_t)length, 0);
	if (n < 0) {
		int err = llrio_net_errno(fd);
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return 0;
		}
		/* Map ENOTCONN to EBADF: after async close (close from
		 * another thread), shutdown(SHUT_RDWR) makes the socket
		 * return ENOTCONN.  Java expects EBADF ("Socket closed"). */
		if (err == ENOTCONN) {
			err = EBADF;
		}
		LLRIO_throw_errno(err);
		return SNI_IGNORED_RETURNED_VALUE;
	}
	if (n == 0) {
		return -1;  /* EOF — peer closed the connection. */
	}
	return (jint)n;
}

/* ── sendTo ──────────────────────────────────────────────────── */

jint LLRIO_NET_IMPL_sendTo(jint fd, jbyte *data, jint offset, jint length,
                           jbyte *ip_address, jint ip_address_length,
                           jint port) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	union llrio_net_sockaddr addr;
	socklen_t addr_len = build_sockaddr(&addr, ip_address, ip_address_length, port);
	if (addr_len == 0) {
		VEEPORT_LOGGER_LOG_DBG("invalid address length for configured LLRIO_NET_AF");
		VEEPORT_ERRORS_throw_caught_exception(J_EINVAL);
		return SNI_IGNORED_RETURNED_VALUE;
	}

	ssize_t n = llrio_net_sendto((int)fd, data + offset, (size_t)length, 0,
	                             &addr.addr, addr_len);
	if (n < 0) {
		if (llrio_net_errno(fd) == EAGAIN || llrio_net_errno(fd) == EWOULDBLOCK) {
			return 0;
		}
		LLRIO_throw_errno(llrio_net_errno(fd));
		return SNI_IGNORED_RETURNED_VALUE;
	}
	return (jint)n;
}

/* ── recvFrom ────────────────────────────────────────────────── */

jint LLRIO_NET_IMPL_recvFrom(jint fd, jbyte *buffer, jint offset, jint length,
                             jbyte *src_addr) {
	if (!rio_net_ready()) {
		return SNI_IGNORED_RETURNED_VALUE;
	}

	union llrio_net_sockaddr sender;
	socklen_t sender_len = sizeof(sender);

	ssize_t n = llrio_net_recvfrom((int)fd, buffer + offset, (size_t)length, 0,
	                               &sender.addr, &sender_len);
	if (n < 0) {
		if (llrio_net_errno(fd) == EAGAIN || llrio_net_errno(fd) == EWOULDBLOCK) {
			return 0;
		}
		LLRIO_throw_errno(llrio_net_errno(fd));
		return SNI_IGNORED_RETURNED_VALUE;
	}

	unpack_sockaddr(&sender, src_addr);

	return (jint)n;
}
