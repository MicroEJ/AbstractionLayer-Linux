/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/*
 * LLRIO_impl.c — Poll event-loop bridge for the rio Foundation
 * Library.
 *
 * The Java side (`Poll`) owns the registry: each call passes a
 * single `int[n*3]` buffer (`fd`, `interestMask`, `revents` per
 * source) which rio-core fills in place with each source's revents
 * before resuming the suspended Java thread.  Both the poll and
 * the per-fd wait delegate to rio-core, which suspends the calling
 * Java thread via SNI and runs the kernel selector on a worker.
 *
 * Generic glue: it only delegates the LLRIO_IMPL_* SNI entry points
 * to the engine's rio_*() API, with no platform-specific code, so it
 * ships from rio-core for every rio BSP rather than being re-authored
 * per veeport.  Socket operations (create, bind, accept, read, write,
 * close, sendTo, recvFrom) are in LLRIO_NET_impl.c.
 */

#include <stddef.h>

#include "LLRIO_impl.h"
#include "rio.h"

/* ── Lifecycle ─────────────────────────────────────────────── */

jint LLRIO_IMPL_init(void) {
	return (jint)rio_init();
}

/* ── Poll ──────────────────────────────────────────────────── */

jint LLRIO_IMPL_poll(jint *entries, jint n, jint timeoutMs) {
	return (jint)rio_poll((int *)entries, (int)n, (int)timeoutMs);
}

/* ── Per-fd blocking wait ──────────────────────────────────── */

jint LLRIO_IMPL_waitReady(jint fd, jint interests, jint timeout_ms) {
	return (jint)rio_wait_ready((int)fd, (int)interests, (int)timeout_ms,
	                            NULL, (void *)0);
}
