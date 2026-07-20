/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief rio selector backend: POSIX poll().
 * @author @CCO_AUTHOR@
 * @version 1.0.0
 * @date @CCO_DATE@
 *
 * Default backend.  Uses a wake pipe for inter-thread signalling and
 * rebuilds a `struct pollfd` array from the active source list on
 * each cycle.
 */

/*
 * Backend selection is the BSP build's job — its source set must
 * contain exactly one of rio_poll.c / rio_select.c.  No `#ifdef`
 * guard here; linking more than one of them in the same image
 * produces duplicate-symbol errors at link time, which surfaces the
 * mistake immediately.
 */

#include "rio_selector.h"
#include "rio_util.h"

#include <assert.h>
#include <poll.h>
#include <stdint.h>
#include <unistd.h>

/* ── Internal state ───────────────────────────────────────────
 *
 * wake_pipe: writing a byte interrupts the worker's poll().
 * pfds/source_map/nfds: built by prepare(), consumed by wait()/collect(). */

static int wake_pipe[2] = { -1, -1 };

static struct pollfd pfds[RIO_MAX_SOURCES + 1];
static rio_source_t *source_ptrs[RIO_MAX_SOURCES + 1];  /* pfds index → source pointer */
static int nfds = 0;

/* ── Interface implementation ─────────────────────────────────── */

int rio_selector_init(void) {
	if (pipe(wake_pipe) < 0) {
		return -1;
	}
	rio_set_nonblocking(wake_pipe[0]);
	rio_set_nonblocking(wake_pipe[1]);
	return 0;
}

void rio_selector_wake(void) {
	char c = 1;
	/* Best-effort wake; keep the result so -Werror=unused-result is satisfied. */
	ssize_t written = write(wake_pipe[1], &c, 1);
	(void)written;
}

void rio_selector_drain_wake(void) {
	/* The wake pipe entry is always pfds[0].  Drain every byte queued since
	 * the last cycle so it doesn't fire again on the next poll().  We are the
	 * only writer and write one byte per wake, but loop until the non-blocking
	 * read drains (EAGAIN) in case several wakes coalesced. */
	if (pfds[0].revents & POLLIN) {
		char buf[32];
		while (read(wake_pipe[0], buf, sizeof(buf)) > 0) {
			/* keep draining */
		}
	}
}

int rio_selector_prepare(rio_source_t *active_head) {
	/* Wake pipe is always entry 0. */
	pfds[0].fd = wake_pipe[0];
	pfds[0].events = POLLIN;
	pfds[0].revents = 0;
	nfds = 1;

	/* Walk the active-source list once: build the pollfd[] array
	 * and accumulate the nearest deadline. */
	int64_t earliest = INT64_MAX;
	for (rio_source_t *s = active_head; s != NULL; s = s->next_active) {
		assert(s->fd >= 0); /* the VM C task rejects fd<0 at registration */
		int idx = nfds;
		pfds[idx].fd = s->fd;
		pfds[idx].events = s->interests;
		pfds[idx].revents = 0;
		source_ptrs[idx] = s;
		s->polled = true; /* in this cycle's poll set */
		nfds++;
		if (s->deadline_ms < earliest) {
			earliest = s->deadline_ms;
		}
	}

	if (earliest == INT64_MAX) {
		return -1;
	}
	int64_t now = LLMJVM_IMPL_getCurrentTime__Z(1);
	int64_t remaining = earliest - now;
	if (remaining < 0) {
		remaining = 0;
	} else if (remaining > INT32_MAX) {
		remaining = INT32_MAX;
	}
	return (int)remaining;
}

int rio_selector_wait(int timeout_ms) {
	return poll(pfds, nfds, timeout_ms);
}

int rio_selector_collect(void) {
	/* Walk every entry built by `prepare()` (skipping entry 0 = wake
	 * pipe).  For each ready fd, write the kernel revents directly
	 * into the matching source — `rio.c::rio_worker` picks them up
	 * by walking the active list. */
	int count = 0;
	for (int j = 1; j < nfds; j++) {
		if (pfds[j].revents != 0) {
			source_ptrs[j]->revents = (short)pfds[j].revents;
			count++;
		}
	}
	return count;
}

/* No registration hooks: poll rebuilds its pollfd[] array from the active list
 * each cycle, so RIO_SELECTOR_TRACKS_REGISTRATION is left undefined and the
 * on_register/on_deregister hooks are not provided. */
