/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief rio selector backend: POSIX select().
 * @author @CCO_AUTHOR@
 * @version 1.0.0
 * @date @CCO_DATE@
 *
 * For RTOS POSIX layers that provide select() but not poll().
 * Uses the same wake pipe mechanism as the poll backend.
 *
 * Limitation: FD_SETSIZE (typically 1024) caps the maximum file
 * descriptor value.  Descriptors above FD_SETSIZE are silently
 * ignored — this is a fundamental select() constraint.
 */

/* See rio_poll.c for a note on backend selection (BSP build system,
 * one .c file at a time). */

#include "rio_selector.h"
#include "rio_util.h"

#include <assert.h>
#include <stdint.h>
#include <sys/select.h>
#include <unistd.h>

/* ── Internal state ──────────────────────────────────────────── */

static int wake_pipe[2] = { -1, -1 };

/* fd_sets built by prepare(), consumed by wait()/collect(). */
static fd_set rfds, wfds;
static fd_set result_rfds, result_wfds;
static int maxfd;

/* Track which sources were included, so collect() can iterate
 * only the relevant ones. */
static rio_source_t *included[RIO_MAX_SOURCES];
static int included_count;

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
	(void)write(wake_pipe[1], &c, 1);
}

void rio_selector_drain_wake(void) {
	/* Drain every byte queued since the last cycle so the pipe doesn't fire
	 * again on the next select().  We are the only writer and write one byte
	 * per wake, but loop until the non-blocking read drains (EAGAIN) in case
	 * several wakes coalesced. */
	if (FD_ISSET(wake_pipe[0], &result_rfds)) {
		char buf[32];
		while (read(wake_pipe[0], buf, sizeof(buf)) > 0) {
			/* keep draining */
		}
	}
}

int rio_selector_prepare(rio_source_t *active_head) {
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	included_count = 0;

	/* Wake pipe — always monitored for readability. */
	FD_SET(wake_pipe[0], &rfds);
	maxfd = wake_pipe[0];

	/* Walk the active list via `next`: build the fd_sets and
	 * accumulate the nearest deadline in one pass. */
	int64_t earliest = INT64_MAX;
	for (rio_source_t *s = active_head; s != NULL; s = s->next_active) {
		int fd = s->fd;
		assert(fd >= 0); /* the VM C task rejects fd<0 at registration */
		if (fd >= FD_SETSIZE) {
			continue;
		}
		if (s->interests & RIO_EVENT_READABLE) {
			FD_SET(fd, &rfds);
		}
		if (s->interests & RIO_EVENT_WRITABLE) {
			FD_SET(fd, &wfds);
		}
		if (fd > maxfd) {
			maxfd = fd;
		}
		included[included_count++] = s;
		s->polled = true; /* in this cycle's select set */
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
	/* select() destroys the fd_sets, so copy them. */
	result_rfds = rfds;
	result_wfds = wfds;

	struct timeval tv;
	struct timeval *tvp = NULL;
	if (timeout_ms >= 0) {
		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;
		tvp = &tv;
	}

	return select(maxfd + 1, &result_rfds, &result_wfds, NULL, tvp);
}

int rio_selector_collect(void) {
	int count = 0;
	for (int k = 0; k < included_count; k++) {
		rio_source_t *s = included[k];
		int fd = s->fd;
		int ev = 0;

		/* select()'s fd_sets are keyed by fd, not by source: when the
		 * same fd is watched for READABLE by one source and WRITABLE by
		 * another, a writable result lands in result_wfds for *both*.
		 * Mask each direction against this source's own interest so a
		 * reader is never resumed by the fd merely being writable (and
		 * vice versa) — matching the per-source revents the poll backend
		 * gets for free from its per-source pollfd. */
		if ((s->interests & RIO_EVENT_READABLE) && FD_ISSET(fd, &result_rfds)) {
			ev |= RIO_EVENT_READABLE;
		}
		if ((s->interests & RIO_EVENT_WRITABLE) && FD_ISSET(fd, &result_wfds)) {
			ev |= RIO_EVENT_WRITABLE;
		}
		if (ev != 0) {
			s->revents = (short)ev;
			count++;
		}
	}
	return count;
}

/* No registration hooks: select rebuilds its fd set from the active list each
 * cycle, so RIO_SELECTOR_TRACKS_REGISTRATION is left undefined and the
 * on_register/on_deregister hooks are not provided. */
