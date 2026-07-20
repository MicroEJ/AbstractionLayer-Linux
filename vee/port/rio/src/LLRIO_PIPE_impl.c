/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/*
 * LLRIO_PIPE_impl.c — Pipe operations for the rio Foundation Library.
 *
 * POSIX implementation using pipe2().  For platforms without native
 * pipe support (FreeRTOS+lwIP, ThreadX NetX), replace this file with
 * a socket-pair implementation that uses socketpair() or loopback TCP.
 * The Java API is identical either way.
 */

#include "LLRIO_PIPE_impl.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sni.h>

/* ── Pipe creation ─────────────────────────────────────────── */

void LLRIO_PIPE_IMPL_createPipe(jint *fds) {
	int pipefd[2];
	if (pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) == -1) {
		SNI_throwNativeIOException(errno, strerror(errno));
		return;
	}
	fds[0] = pipefd[0];  /* read end */
	fds[1] = pipefd[1];  /* write end */
}

/* ── Read ──────────────────────────────────────────────────── */

jint LLRIO_PIPE_IMPL_read(jint fd, jbyte *buffer, jint offset, jint length) {
	ssize_t n = read(fd, buffer + offset, (size_t)length);
	if (n > 0) {
		return (jint)n;
	}
	if (n == 0) {
		/* EOF — writer closed. */
		return -1;
	}
	/* n < 0: check errno. */
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return 0;  /* No data available, non-blocking. */
	}
	/* Real error. */
	SNI_throwNativeIOException(errno, strerror(errno));
	return -1;
}

/* ── Write ─────────────────────────────────────────────────── */

jint LLRIO_PIPE_IMPL_write(jint fd, jbyte *data, jint offset, jint length) {
	ssize_t n = write(fd, data + offset, (size_t)length);
	if (n >= 0) {
		return (jint)n;
	}
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return 0;  /* Pipe buffer full, non-blocking. */
	}
	SNI_throwNativeIOException(errno, strerror(errno));
	return 0;
}

/* ── Close ─────────────────────────────────────────────────── */

/* SNI close function for a pipe-end fd registered via registerCloseOnGc.  Run
 * by the VM on owner GC and on application/VM stop.  Resource is the fd. */
static void pipe_close_resource(void *resource) {
	close((int)(intptr_t)resource);  /* Best-effort. */
}

void LLRIO_PIPE_IMPL_close(jint fd) {
	/* Cancel the close-on-GC / close-on-stop registration (if any) to avoid a
	 * double close. */
	SNI_unregisterResource((void *)(intptr_t)fd, pipe_close_resource);
	close(fd);  /* Best-effort, ignore errors. */
}

jlong LLRIO_PIPE_IMPL_registerCloseOnGc(jint fd) {
	/* Resource id is the fd itself (SNI_registerResource keys on it); 0 on
	 * failure so the caller skips arming close-on-GC. */
	if (SNI_registerResource((void *)(intptr_t)fd, pipe_close_resource, NULL) != SNI_OK) {
		return 0;
	}
	return (jlong)fd;
}

jlong LLRIO_PIPE_IMPL_nativeResourceCloseFunctionId(void) {
	/* closeFunction for NativeResource.closeOnGC: the pipe_close_resource
	 * address registered by registerCloseOnGc. */
	return (jlong)(intptr_t)pipe_close_resource;
}
