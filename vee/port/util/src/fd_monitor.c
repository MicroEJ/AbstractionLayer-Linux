/*
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include <fd_monitor.h>
#include <sni.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

VEEPORT_LOGGER_DEFINE_MODULE(FD_MONITOR_LOG_MODULE_NAME, FD_MONITOR_LOG_LEVEL)

/* ── internal helpers ────────────────────────────────────────────────── */

#define FD_MONITOR_UNUSED_RETURN(x)  (void)(x)

/** Sentinel handle for the command pipe in epoll data. */
#define FD_MONITOR_CMD_PIPE_INDEX    UINT32_MAX

/* ── internal command types ──────────────────────────────────────────── */

enum fd_monitor_cmd_type {
	FD_MONITOR_CMD_WATCH,
	FD_MONITOR_CMD_UNWATCH,
	FD_MONITOR_CMD_QUIT,
};

/* ── internal command struct (< PIPE_BUF → atomic write) ─────────────── */

struct fd_monitor_cmd {
	enum fd_monitor_cmd_type type;
	int fd;                  /* WATCH: dup'd fd; UNWATCH: dup'd fd to close */
	int32_t java_thread_id;  /* WATCH only */
	uint32_t watch_index;    /* WATCH: slot index */
	uint32_t interests;      /* WATCH only: FD_MONITOR_IN / FD_MONITOR_OUT */
};

/* ── system-wide default instance ────────────────────────────────────── */

FD_MONITOR_DEFINE(fd_monitor_sys, FD_MONITOR_SYS_MAX_WATCHES);

/* ── freelist helpers (VM-task only, index-based) ────────────────────── */

static int fd_monitor_alloc_slot(struct fd_monitor *mon) {
	int hdl = mon->free_head;
	if (hdl >= 0) {
		mon->free_head = mon->watches[hdl].next;
	}
	return hdl;
}

static void fd_monitor_free_slot(struct fd_monitor *mon, int hdl) {
	mon->watches[hdl].next = mon->free_head;
	mon->free_head = hdl;
}

/* ── internal: map interest flags to epoll events ────────────────────── */

static uint32_t fd_monitor_to_epoll(uint32_t interests) {
	uint32_t ev = EPOLLET;
	if (interests & FD_MONITOR_IN) {
		ev |= EPOLLIN | EPOLLRDHUP | EPOLLPRI;
	}
	if (interests & FD_MONITOR_OUT) {
		ev |= EPOLLOUT;
	}
	return ev;
}

/* ── internal: send command to monitor thread ────────────────────────── */

static int fd_monitor_send_cmd(struct fd_monitor *mon,
                               const struct fd_monitor_cmd *cmd) {
	int ret = FD_MONITOR_OK;
	ssize_t n = write(mon->cmd_pipe[1], cmd, sizeof(*cmd));
	if (n != (ssize_t)sizeof(*cmd)) {
		VEEPORT_LOGGER_LOG_ERR("cannot write to the command pipe: %s", strerror(errno));
		ret = FD_MONITOR_ERROR;
	}
	return ret;
}

/* ── monitor-thread: process commands ────────────────────────────────── */

static void fd_monitor_process_commands(struct fd_monitor *mon) {
	struct fd_monitor_cmd cmd;
	ssize_t n;

	while ((n = read(mon->cmd_pipe[0], &cmd, sizeof(cmd))) == (ssize_t)sizeof(cmd)) {
		switch (cmd.type) {
		case FD_MONITOR_CMD_WATCH:
		{
			struct fd_monitor_watch *w = &mon->watches[cmd.watch_index];
			struct epoll_event ev;
			ev.events = fd_monitor_to_epoll(cmd.interests);
			ev.data.u32 = cmd.watch_index;
			if (epoll_ctl(mon->epoll_fd, EPOLL_CTL_ADD, w->dup_fd, &ev) < 0) {
				VEEPORT_LOGGER_LOG_ERR("cannot add dup_fd=%d to the epoll set: %s", w->dup_fd, strerror(errno));
			}
			break;
		}

		case FD_MONITOR_CMD_UNWATCH:
			/* Must explicitly remove from epoll before closing: when
			 * the original fd is still open, close(dup_fd) alone does
			 * NOT remove the file description from the interest list. */
			(void)epoll_ctl(mon->epoll_fd, EPOLL_CTL_DEL, cmd.fd, NULL);
			close(cmd.fd);
			break;

		case FD_MONITOR_CMD_QUIT:
			mon->quit = true;
			break;
		}
	}
}

/* ── monitor-thread: handle epoll event ──────────────────────────────── */

static void fd_monitor_handle_event(struct fd_monitor *mon,
                                    struct fd_monitor_watch *w,
                                    uint32_t ev) {
	(void)mon;
	(void)ev;

	if (w->java_thread_id != SNI_ERROR) {
		FD_MONITOR_UNUSED_RETURN(SNI_resumeJavaThread(w->java_thread_id));
	}
}

/* ── monitor thread ─────────────────────────────────────────────────── */

static void *fd_monitor_thread_entry(void *arg) {
	struct fd_monitor *mon = (struct fd_monitor *)arg;
	struct epoll_event events[FD_MONITOR_MAX_EPOLL_EVENTS];

	while (!mon->quit) {
		int n = epoll_wait(mon->epoll_fd, events,
		                   FD_MONITOR_MAX_EPOLL_EVENTS, -1);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			VEEPORT_LOGGER_LOG_ERR("epoll_wait failed: %s", strerror(errno));
			break;
		}

		for (int i = 0; i < n; i++) {
			uint32_t idx = events[i].data.u32;
			if (idx == FD_MONITOR_CMD_PIPE_INDEX) {
				fd_monitor_process_commands(mon);
			} else {
				fd_monitor_handle_event(mon, &mon->watches[idx],
				                        events[i].events);
			}
		}
	}

	return NULL;
}

/* ── public API ──────────────────────────────────────────────────────── */

int fd_monitor_init(struct fd_monitor *mon) {
	int ret = FD_MONITOR_ERROR;

	if (mon->epoll_fd > 0) {
		/* Already initialized */
		ret = FD_MONITOR_OK;
		goto done;
	}

	/* Build index-based freelist */
	for (int i = 0; i < mon->max_watches; i++) {
		mon->watches[i].dup_fd = -1;
		mon->watches[i].java_thread_id = SNI_ERROR;
		mon->watches[i].next = (i + 1 < mon->max_watches) ? (i + 1) : -1;
	}
	mon->free_head = (mon->max_watches > 0) ? 0 : -1;

	/* Create epoll instance */
	mon->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (mon->epoll_fd < 0) {
		goto fail;
	}

	/* Create command pipe (read end non-blocking) */
	if (pipe2(mon->cmd_pipe, O_CLOEXEC) < 0) {
		goto close_epoll;
	}
	(void)fcntl(mon->cmd_pipe[0], F_SETFL, O_NONBLOCK);

	/* Register cmd_pipe read-end in epoll with sentinel index */
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.u32 = FD_MONITOR_CMD_PIPE_INDEX;
	if (epoll_ctl(mon->epoll_fd, EPOLL_CTL_ADD,
	              mon->cmd_pipe[0], &ev) < 0) {
		goto close_cmd_pipe;
	}

	/* Start monitor thread */
	pthread_attr_t attr;
	(void)pthread_attr_init(&attr);
	(void)pthread_attr_setstacksize(&attr, FD_MONITOR_STACK_SIZE);

	if (pthread_create(&mon->thread, &attr,
	                   fd_monitor_thread_entry, mon) != 0) {
		(void)pthread_attr_destroy(&attr);
		goto close_cmd_pipe;
	}

	(void)pthread_attr_destroy(&attr);
	mon->quit = false;
	VEEPORT_LOGGER_LOG_DBG("monitor started");
	ret = FD_MONITOR_OK;
	goto done;

close_cmd_pipe:
	close(mon->cmd_pipe[0]);
	close(mon->cmd_pipe[1]);
close_epoll:
	close(mon->epoll_fd);
fail:
	mon->epoll_fd = 0;
	ret = FD_MONITOR_ERROR;
done:
	return ret;
}

int fd_monitor_destroy(struct fd_monitor *mon) {
	int ret = FD_MONITOR_ERROR;

	if (mon->epoll_fd <= 0) {
		goto done;
	}

	/* Refuse to destroy if any watch slots are still allocated */
	int free_count = 0;
	for (int i = mon->free_head; i >= 0; i = mon->watches[i].next) {
		free_count++;
	}
	if (free_count != mon->max_watches) {
		goto done;
	}

	/* Signal monitor thread to exit and wait for it */
	struct fd_monitor_cmd quit_cmd = { .type = FD_MONITOR_CMD_QUIT };
	fd_monitor_send_cmd(mon, &quit_cmd);
	(void)pthread_join(mon->thread, NULL);

	/* Close OS resources */
	close(mon->cmd_pipe[0]);
	close(mon->cmd_pipe[1]);
	close(mon->epoll_fd);

	/* Reset so init can be called again */
	mon->epoll_fd = 0;
	mon->quit = false;

	VEEPORT_LOGGER_LOG_DBG("monitor destroyed");
	ret = FD_MONITOR_OK;
done:
	return ret;
}

int fd_monitor_watch(struct fd_monitor *mon, int fd, uint32_t interests, int *chain) {
	int hdl = fd_monitor_alloc_slot(mon);
	if (hdl < 0) {
		goto done;
	}

	int dup_fd = dup(fd);
	if (dup_fd < 0) {
		VEEPORT_LOGGER_LOG_ERR("dup(%d) failed: %s", fd, strerror(errno));
		fd_monitor_free_slot(mon, hdl);
		hdl = -1;
		goto done;
	}

	struct fd_monitor_watch *w = &mon->watches[hdl];
	w->dup_fd = dup_fd;
	w->java_thread_id = SNI_getCurrentJavaThreadID();

	/* Prepend to caller's chain */
	w->next = *chain;
	*chain = hdl;

	struct fd_monitor_cmd cmd = {
		.type = FD_MONITOR_CMD_WATCH,
		.fd = dup_fd,
		.java_thread_id = w->java_thread_id,
		.watch_index = (uint32_t)hdl,
		.interests = interests,
	};
	fd_monitor_send_cmd(mon, &cmd);

done:
	return hdl;
}

int fd_monitor_unwatch(struct fd_monitor *mon, int hdl, int *chain) {
	int ret = FD_MONITOR_ERROR;

	if (hdl < 0 || hdl >= mon->max_watches) {
		goto done;
	}

	int dup_fd = mon->watches[hdl].dup_fd;

	/* Unlink from caller's chain */
	if (*chain == hdl) {
		*chain = mon->watches[hdl].next;
	} else {
		for (int i = *chain; i >= 0; i = mon->watches[i].next) {
			if (mon->watches[i].next == hdl) {
				mon->watches[i].next = mon->watches[hdl].next;
				break;
			}
		}
	}

	struct fd_monitor_cmd cmd = {
		.type = FD_MONITOR_CMD_UNWATCH,
		.fd = dup_fd,
	};
	fd_monitor_send_cmd(mon, &cmd);

	fd_monitor_free_slot(mon, hdl);
	ret = FD_MONITOR_OK;
done:
	return ret;
}

int fd_monitor_resume_all(struct fd_monitor *mon, int chain_head) {
	/* Walk the chain on the caller's side (VM task) and resume
	 * directly.  SNI_resumeJavaThread is thread-safe; java_thread_id
	 * is write-once (set in fd_monitor_watch), so no data race with
	 * the monitor thread which only reads it. */
	for (int i = chain_head; i >= 0; i = mon->watches[i].next) {
		if (mon->watches[i].java_thread_id != SNI_ERROR) {
			FD_MONITOR_UNUSED_RETURN(
				SNI_resumeJavaThread(mon->watches[i].java_thread_id));
		}
	}
	return FD_MONITOR_OK;
}
