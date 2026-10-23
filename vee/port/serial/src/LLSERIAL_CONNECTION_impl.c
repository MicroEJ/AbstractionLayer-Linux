/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include <LLSERIAL_CONNECTION_impl.h>
#include <LLSERIAL_configuration.h>
#include <fd_monitor.h>
#include <sni.h>
#include <veeport_errors.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

VEEPORT_LOGGER_DEFINE_MODULE(LLSERIAL_LOG_MODULE_NAME, LLSERIAL_LOG_LEVEL)

/* ── helper macros ──────────────────────────────────────────────────── */

#define LLSERIAL_UNUSED_RETURN(x) (void)(x)

/**
 * @brief Throws the generic serial NativeIOException for a failed C library call, with its errno in the message.
 *
 * @param[in] what what failed, one of the LLSERIAL_CONNECTION_* messages, or NULL for the errno text alone.
 */
static void throw_errno_io_exception(const char *what) {
	int32_t err = errno;
	if (NULL != what) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, "%s: %s (%d)", what, strerror(err),
		                                              err);
	} else {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, "%s (%d)", strerror(err), err);
	}
}

#define LLSERIAL_RETCODE_ERROR (-1)
#define LLSERIAL_RETCODE_OK    (0)

/* ── per-connection I/O operation slot ─────────────────────────────── */

#define SERIAL_MAX_OPS 2

struct serial_op {
	int watch_hdl;       /* fd_monitor handle, -1 = unused */
	int32_t written;     /* write progress (write ops only) */
};

/* ── per-connection context ─────────────────────────────────────────── */

struct serial_conn {
	int fd;
	bool is_open;
#ifdef LLSERIAL_SOFT_EXCLUSIVE
	dev_t rdev;                  /* device identity, to release the soft-exclusive slot on close */
#endif
	int32_t refcount;            /* conn struct lifetime: 1 from open, +1 per pending I/O */
	int watch_chain;             /* fd_monitor chain head, -1 = empty */
	struct serial_op ops[SERIAL_MAX_OPS];
};

#ifdef LLSERIAL_SOFT_EXCLUSIVE
/* ── userspace exclusive-open registry ───────────────────────────────── *
 * TIOCEXCL cannot enforce single-open access against virtual ports: a PTY
 * broker (e.g. socat) keeps the slave open, so the kernel never clears the
 * exclusive flag on close. Instead, track currently-open devices by identity
 * (st_rdev) within this process and reject a second open. VM-task only, so no
 * locking. */

#define LLSERIAL_MAX_OPEN_PORTS 16

static struct {
	dev_t rdev;
	int32_t count;
} llserial_open_ports[LLSERIAL_MAX_OPEN_PORTS];

/** Reserve the device behind fd for exclusive use. Returns 0 on success, or -1
 *  with errno set (EBUSY if already open, ENOSPC if the registry is full). */
static int soft_excl_acquire(int fd, dev_t *out_rdev) {
	struct stat st;
	if (fstat(fd, &st) < 0) {
		return -1;
	}

	int free_slot = -1;
	for (int i = 0; i < LLSERIAL_MAX_OPEN_PORTS; i++) {
		if (llserial_open_ports[i].count > 0) {
			if (llserial_open_ports[i].rdev == st.st_rdev) {
				errno = EBUSY;
				return -1;
			}
		} else if (free_slot < 0) {
			free_slot = i;
		}
	}
	if (free_slot < 0) {
		errno = ENOSPC;
		return -1;
	}

	llserial_open_ports[free_slot].rdev = st.st_rdev;
	llserial_open_ports[free_slot].count = 1;
	*out_rdev = st.st_rdev;
	return 0;
}

/** Release a device reserved by soft_excl_acquire(). */
static void soft_excl_release(dev_t rdev) {
	for (int i = 0; i < LLSERIAL_MAX_OPEN_PORTS; i++) {
		if ((llserial_open_ports[i].count > 0) && (llserial_open_ports[i].rdev == rdev)) {
			llserial_open_ports[i].count--;
			break;
		}
	}
}

#endif /* LLSERIAL_SOFT_EXCLUSIVE */

/* ── forward declarations ───────────────────────────────────────────── */

static int32_t read_callback(int32_t connection_id, uint8_t *b, int32_t off, int32_t len);
static void    write_callback(int32_t connection_id, uint8_t *b, int32_t off, int32_t len);

/* ── baudrate helper ────────────────────────────────────────────────── */

static int baudrate_to_bconst(int32_t baudrate, speed_t *out) {
	int rc = 0;

	switch (baudrate) {
	case 50:
		*out = B50;
		break;
	case 75:
		*out = B75;
		break;
	case 110:
		*out = B110;
		break;
	case 134:
		*out = B134;
		break;
	case 150:
		*out = B150;
		break;
	case 200:
		*out = B200;
		break;
	case 300:
		*out = B300;
		break;
	case 600:
		*out = B600;
		break;
	case 1200:
		*out = B1200;
		break;
	case 1800:
		*out = B1800;
		break;
	case 2400:
		*out = B2400;
		break;
	case 4800:
		*out = B4800;
		break;
	case 9600:
		*out = B9600;
		break;
	case 19200:
		*out = B19200;
		break;
	case 38400:
		*out = B38400;
		break;
	case 57600:
		*out = B57600;
		break;
	case 115200:
		*out = B115200;
		break;
	case 230400:
		*out = B230400;
		break;
	case 460800:
		*out = B460800;
		break;
	case 500000:
		*out = B500000;
		break;
	case 576000:
		*out = B576000;
		break;
	case 921600:
		*out = B921600;
		break;
	case 1000000:
		*out = B1000000;
		break;
	case 1152000:
		*out = B1152000;
		break;
	case 1500000:
		*out = B1500000;
		break;
	case 2000000:
		*out = B2000000;
		break;
	default:
		rc = -1;
		break;
	}

	return rc;
}

/* ── op slot helpers (VM task only) ─────────────────────────────────── */

static int op_alloc(struct serial_conn *conn) {
	int result = -1;

	for (int i = 0; i < SERIAL_MAX_OPS; i++) {
		if (conn->ops[i].watch_hdl == -1) {
			result = i;
			break;
		}
	}

	return result;
}

static void op_free(struct serial_conn *conn, int idx) {
	conn->ops[idx].watch_hdl = -1;
	conn->ops[idx].written = 0;
}

/* ── refcount helper (VM task only) ──────────────────────────────────── */

static void conn_release(struct serial_conn *conn) {
	if (--conn->refcount == 0) {
		if (conn->fd >= 0) {
			close(conn->fd);
#ifdef LLSERIAL_SOFT_EXCLUSIVE
			soft_excl_release(conn->rdev);
#endif
		}
		free(conn);
	}
}

/* ── LLAPI: init ────────────────────────────────────────────────────── */

void LLSERIAL_CONNECTION_IMPL_init(void) {
	VEEPORT_LOGGER_LOG_DBG("");
	fd_monitor_init(LLSERIAL_FD_MONITOR);
}

/* ── LLAPI: open ────────────────────────────────────────────────────── */

int32_t LLSERIAL_CONNECTION_IMPL_open(uint8_t *port_name) {
	VEEPORT_LOGGER_LOG_DBG("port_name = %s", port_name);

	int32_t result = LLSERIAL_RETCODE_ERROR;

	if (NULL == port_name) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, LLSERIAL_CONNECTION_INVALID_PORT);
		goto end;
	}

	struct serial_conn *conn = calloc(1, sizeof(struct serial_conn));
	if (conn == NULL) {
		throw_errno_io_exception(LLSERIAL_CONNECTION_INTERNAL_ERROR);
		goto end;
	}

	int fd = open((const char *)port_name, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		throw_errno_io_exception(NULL);
		goto free_conn;
	}

#ifdef LLSERIAL_SOFT_EXCLUSIVE
	/* Exclusive access enforced in userspace (see registry above) */
	dev_t rdev;
	if (soft_excl_acquire(fd, &rdev) < 0) {
		throw_errno_io_exception(NULL);
		goto close_fd;
	}
	conn->rdev = rdev;
#else
	/* Exclusive access */
	if (ioctl(fd, TIOCEXCL) < 0) {
		throw_errno_io_exception(NULL);
		goto close_fd;
	}
#endif

	conn->fd = fd;
	conn->is_open = true;
	conn->refcount = 1;
	conn->watch_chain = -1;
	for (int i = 0; i < SERIAL_MAX_OPS; i++) {
		conn->ops[i].watch_hdl = -1;
		conn->ops[i].written = 0;
	}

	/* Register as SNI resource for GC cleanup */
	LLSERIAL_UNUSED_RETURN(SNI_registerResource(
							   (void *)(intptr_t)conn,
							   (SNI_closeFunction)(void (*)(void)) LLSERIAL_CONNECTION_IMPL_close, NULL));

	VEEPORT_LOGGER_LOG_DBG("connection_id = %p", (void *)conn);
	result = (int32_t)(intptr_t)conn;
	goto end;

close_fd:
	close(fd);
free_conn:
	free(conn);
end:
	return result;
}

/* ── LLAPI: configure ───────────────────────────────────────────────── */

void LLSERIAL_CONNECTION_IMPL_configure(int32_t connection_id, int32_t baudrate,
                                        int32_t databits, int32_t parity, int32_t stopbits) {
	VEEPORT_LOGGER_LOG_DBG("id=%x baud=%d data=%d par=%d stop=%d", connection_id, baudrate, databits, parity, stopbits);

	struct serial_conn *conn = (struct serial_conn *)(intptr_t)connection_id;
	if (!conn->is_open) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC,
		                                              LLSERIAL_CONNECTION_CONNECTION_CLOSED);
		goto end;
	}

	struct termios tty;
	if (tcgetattr(conn->fd, &tty) < 0) {
		throw_errno_io_exception(NULL);
		goto end;
	}

	/* Control modes */
	tty.c_cflag &= ~CSIZE;
	tty.c_cflag &= ~CRTSCTS;
	tty.c_cflag |= CREAD | CLOCAL;

	/* Parity */
	switch (parity) {
	case LLSERIAL_CONNECTION_PARITY_ODD:
		tty.c_cflag |= PARENB | PARODD;
		break;
	case LLSERIAL_CONNECTION_PARITY_EVEN:
		tty.c_cflag |= PARENB;
		tty.c_cflag &= ~PARODD;
		break;
	case LLSERIAL_CONNECTION_PARITY_NONE:
		tty.c_cflag &= ~PARENB;
		break;
	default:
		VEEPORT_LOGGER_LOG_DBG(LLSERIAL_CONNECTION_INVALID_PARITY);
		VEEPORT_ERRORS_throw_caught_exception(LLSERIAL_IOEXCEPTION_UNSUPPORTED_CONFIG);
		goto end;
	}

	/* Stop bits */
	switch (stopbits) {
	case LLSERIAL_CONNECTION_STOPBITS_1:
		tty.c_cflag &= ~CSTOPB;
		break;
	case LLSERIAL_CONNECTION_STOPBITS_2:
		tty.c_cflag |= CSTOPB;
		break;
	case LLSERIAL_CONNECTION_STOPBITS_1_5:
	default:
		VEEPORT_LOGGER_LOG_DBG(LLSERIAL_CONNECTION_INVALID_STOPBITS);
		VEEPORT_ERRORS_throw_caught_exception(LLSERIAL_IOEXCEPTION_UNSUPPORTED_CONFIG);
		goto end;
	}

	/* Data bits */
	switch (databits) {
	case LLSERIAL_CONNECTION_DATABITS_5:
		tty.c_cflag |= CS5;
		break;
	case LLSERIAL_CONNECTION_DATABITS_6:
		tty.c_cflag |= CS6;
		break;
	case LLSERIAL_CONNECTION_DATABITS_7:
		tty.c_cflag |= CS7;
		break;
	case LLSERIAL_CONNECTION_DATABITS_8:
		tty.c_cflag |= CS8;
		break;
	case LLSERIAL_CONNECTION_DATABITS_9:
	default:
		VEEPORT_LOGGER_LOG_DBG(LLSERIAL_CONNECTION_INVALID_DATABITS);
		VEEPORT_ERRORS_throw_caught_exception(LLSERIAL_IOEXCEPTION_UNSUPPORTED_CONFIG);
		goto end;
	}

	/* Local modes — raw */
	tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHONL | ISIG);

	/* Input modes — raw */
	tty.c_iflag &= ~(IXON | IXOFF | IXANY);
	tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);

	/* Output modes — raw */
	tty.c_oflag &= ~OPOST;
	tty.c_oflag &= ~ONLCR;

	/* VMIN/VTIME irrelevant with O_NONBLOCK, but set sane defaults */
	tty.c_cc[VMIN] = 0;
	tty.c_cc[VTIME] = 0;

	/* Baudrate */
	speed_t bspeed;
	if (baudrate_to_bconst(baudrate, &bspeed) < 0) {
		VEEPORT_LOGGER_LOG_DBG(LLSERIAL_CONNECTION_INVALID_BAUDRATE);
		VEEPORT_ERRORS_throw_caught_exception(LLSERIAL_IOEXCEPTION_UNSUPPORTED_CONFIG);
	} else if (cfsetispeed(&tty, bspeed) < 0 || cfsetospeed(&tty, bspeed) < 0) {
		VEEPORT_LOGGER_LOG_DBG("%s", strerror(errno));
		VEEPORT_ERRORS_throw_caught_exception(LLSERIAL_IOEXCEPTION_UNSUPPORTED_CONFIG);
	} else if (tcsetattr(conn->fd, TCSANOW, &tty) < 0) {
		/* Apply */
		VEEPORT_LOGGER_LOG_DBG("%s", strerror(errno));
		VEEPORT_ERRORS_throw_caught_exception(LLSERIAL_IOEXCEPTION_UNSUPPORTED_CONFIG);
	}

end:
	return;
}

/* ── read helpers ───────────────────────────────────────────────────── */

/** Try a non-blocking read.  Returns bytes read (>0), 0 if EAGAIN, or -1 on error (exception thrown). */
static int32_t try_read(struct serial_conn *conn, uint8_t *buf, int32_t len) {
	int32_t result = 0;

	if (!conn->is_open) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC,
		                                              LLSERIAL_CONNECTION_CONNECTION_CLOSED);
		result = -1;
		goto end;
	}

	ssize_t n = read(conn->fd, buf, (size_t)len);

	if (n > 0) {
		VEEPORT_LOGGER_LOG_DBG("read %zd bytes", n);
		result = (int32_t)n;
	} else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		throw_errno_io_exception(LLSERIAL_CONNECTION_RX_ERROR);
		result = -1;
	} else {
		/* no data available */
		result = 0;
	}

end:
	return result;
}

/* ── LLAPI: read (first call) ───────────────────────────────────────── */

int32_t LLSERIAL_CONNECTION_IMPL_read(int32_t connection_id, uint8_t *b,
                                      int32_t off, int32_t len) {
	VEEPORT_LOGGER_LOG_DBG("id=%x off=%d len=%d", connection_id, off, len);

	struct serial_conn *conn = (struct serial_conn *)(intptr_t)connection_id;
	int32_t result = SNI_IGNORED_RETURNED_VALUE;

	/* Zero-length read: return 0 immediately (POSIX read(fd,buf,0) returns 0,
	 * which try_read would misinterpret as EAGAIN and suspend forever). */
	if (len == 0) {
		result = 0;
		goto end;
	}

	int32_t n = try_read(conn, &b[off], len);

	if (n > 0) {
		result = n;
		goto end;
	}
	if (n < 0) {
		goto end;
	}

	/* n == 0: no data available — watch for readiness and suspend */
	int op = op_alloc(conn);
	if (op < 0) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, LLSERIAL_CONNECTION_INTERNAL_ERROR);
		goto end;
	}

	int hdl = fd_monitor_watch(LLSERIAL_FD_MONITOR, conn->fd,
	                           FD_MONITOR_IN, &conn->watch_chain);
	if (hdl < 0) {
		op_free(conn, op);
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, LLSERIAL_CONNECTION_INTERNAL_ERROR);
		goto end;
	}

	conn->ops[op].watch_hdl = hdl;
	conn->refcount++;

	if (SNI_suspendCurrentJavaThreadWithCallback(
			0, (SNI_callback)read_callback,
			(void *)(intptr_t)op) != SNI_OK) {
		VEEPORT_LOGGER_LOG_ERR("cannot suspend the current Java thread");
		fd_monitor_unwatch(LLSERIAL_FD_MONITOR, hdl, &conn->watch_chain);
		op_free(conn, op);
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, LLSERIAL_CONNECTION_INTERNAL_ERROR);
		conn_release(conn);
		goto end;
	}

end:
	return result;
}

/* ── read callback ──────────────────────────────────────────────────── */

static int32_t read_callback(int32_t connection_id, uint8_t *b,
                             int32_t off, int32_t len) {
	struct serial_conn *conn = (struct serial_conn *)(intptr_t)connection_id;
	int32_t result = SNI_IGNORED_RETURNED_VALUE;

	void *suspend_arg;
	SNI_getCallbackArgs(&suspend_arg, NULL);
	int op = (int)(intptr_t)suspend_arg;

	int32_t n = try_read(conn, &b[off], len);

	if (n > 0) {
		result = n;
		goto release;
	}
	if (n < 0) {
		goto release;
	}

	/* n == 0: still no data — re-suspend (edge-triggered, watch stays active) */
	if (SNI_suspendCurrentJavaThreadWithCallback(
			0, (SNI_callback)read_callback,
			(void *)(intptr_t)op) != SNI_OK) {
		VEEPORT_LOGGER_LOG_ERR("cannot suspend the current Java thread");
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, LLSERIAL_CONNECTION_INTERNAL_ERROR);
		goto release;
	}
	goto end;

release:
	fd_monitor_unwatch(LLSERIAL_FD_MONITOR, conn->ops[op].watch_hdl,
	                   &conn->watch_chain);
	op_free(conn, op);
	conn_release(conn);
end:
	return result;
}

/* ── write helpers ──────────────────────────────────────────────────── */

/**
 * Try a non-blocking write.  Returns bytes written (>0), 0 if EAGAIN, or -1 on error (exception thrown).
 */
static int32_t try_write(struct serial_conn *conn, uint8_t *buf, int32_t len) {
	int32_t result = 0;

	if (!conn->is_open) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC,
		                                              LLSERIAL_CONNECTION_CONNECTION_CLOSED);
		result = -1;
		goto end;
	}

	ssize_t n = write(conn->fd, buf, (size_t)len);

	if (n > 0) {
		result = (int32_t)n;
	} else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		throw_errno_io_exception(LLSERIAL_CONNECTION_TX_ERROR);
		result = -1;
	} else {
		/* EAGAIN */
		result = 0;
	}

end:
	return result;
}

/* ── LLAPI: write (first call) ──────────────────────────────────────── */

void LLSERIAL_CONNECTION_IMPL_write(int32_t connection_id, uint8_t *b,
                                    int32_t off, int32_t len) {
	VEEPORT_LOGGER_LOG_DBG("id=%x off=%d len=%d", connection_id, off, len);

	struct serial_conn *conn = (struct serial_conn *)(intptr_t)connection_id;

	if (len == 0) {
		goto end; /* zero-length write is a no-op */
	}

	if (!conn->is_open) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC,
		                                              LLSERIAL_CONNECTION_CONNECTION_CLOSED);
		goto end;
	}

	int32_t n = try_write(conn, &b[off], len);
	if (n < 0) {
		goto end;  /* error, exception thrown */
	}

	if (n >= len) {
		goto end;  /* all data written */
	}

	/* Partial write or EAGAIN — watch for write readiness and suspend */
	int op = op_alloc(conn);
	if (op < 0) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, LLSERIAL_CONNECTION_INTERNAL_ERROR);
		goto end;
	}

	int hdl = fd_monitor_watch(LLSERIAL_FD_MONITOR, conn->fd,
	                           FD_MONITOR_OUT, &conn->watch_chain);
	if (hdl < 0) {
		op_free(conn, op);
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, LLSERIAL_CONNECTION_INTERNAL_ERROR);
		goto end;
	}

	conn->ops[op].watch_hdl = hdl;
	conn->ops[op].written = n;  /* bytes written so far */
	conn->refcount++;

	if (SNI_suspendCurrentJavaThreadWithCallback(
			0, (SNI_callback)write_callback,
			(void *)(intptr_t)op) != SNI_OK) {
		VEEPORT_LOGGER_LOG_ERR("cannot suspend the current Java thread");
		fd_monitor_unwatch(LLSERIAL_FD_MONITOR, hdl, &conn->watch_chain);
		op_free(conn, op);
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, LLSERIAL_CONNECTION_INTERNAL_ERROR);
		conn_release(conn);
		goto end;
	}

end:
	return;
}

/* ── write callback ─────────────────────────────────────────────────── */

static void write_callback(int32_t connection_id, uint8_t *b,
                           int32_t off, int32_t len) {
	struct serial_conn *conn = (struct serial_conn *)(intptr_t)connection_id;

	void *suspend_arg;
	SNI_getCallbackArgs(&suspend_arg, NULL);
	int op = (int)(intptr_t)suspend_arg;
	int32_t written = conn->ops[op].written;

	int32_t n = try_write(conn, &b[off + written], len - written);
	if (n < 0) {
		goto release;  /* error, exception thrown */
	}

	written += n;
	conn->ops[op].written = written;

	if (written >= len) {
		goto release;  /* all data written */
	}

	/* Still data remaining — re-suspend (edge-triggered, watch stays active) */
	if (SNI_suspendCurrentJavaThreadWithCallback(
			0, (SNI_callback)write_callback,
			(void *)(intptr_t)op) != SNI_OK) {
		VEEPORT_LOGGER_LOG_ERR("cannot suspend the current Java thread");
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC, LLSERIAL_CONNECTION_INTERNAL_ERROR);
		goto release;
	}
	goto end;

release:
	fd_monitor_unwatch(LLSERIAL_FD_MONITOR, conn->ops[op].watch_hdl,
	                   &conn->watch_chain);
	op_free(conn, op);
	conn_release(conn);
end:
	return;
}

/* ── LLAPI: available ───────────────────────────────────────────────── */

int32_t LLSERIAL_CONNECTION_IMPL_available(int32_t connection_id) {
	VEEPORT_LOGGER_LOG_DBG("id=%x", connection_id);

	struct serial_conn *conn = (struct serial_conn *)(intptr_t)connection_id;
	int32_t result = LLSERIAL_RETCODE_ERROR;

	if (!conn->is_open) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC,
		                                              LLSERIAL_CONNECTION_CONNECTION_CLOSED);
		goto end;
	}

	int bytes_avail = 0;
	if (ioctl(conn->fd, FIONREAD, &bytes_avail) < 0) {
		throw_errno_io_exception(NULL);
		goto end;
	}

	VEEPORT_LOGGER_LOG_DBG("available=%d", bytes_avail);
	result = (int32_t)bytes_avail;

end:
	return result;
}

/* ── LLAPI: flush (first call) ──────────────────────────────────────── */

void LLSERIAL_CONNECTION_IMPL_flush(int32_t connection_id) {
	(void)connection_id;
	VEEPORT_LOGGER_LOG_DBG("id=%x", connection_id);
	/* The current implementation of serial on Linux doesn't use buffer in
	 * userspace. OutputStream.flush() doesn't need to wait for the transfer
	 * to complete at the physical level. Therefore, there is nothing to
	 * flush.*/
	return;
}

/* ── LLAPI: close ───────────────────────────────────────────────────── */

void LLSERIAL_CONNECTION_IMPL_close(int32_t connection_id) {
	VEEPORT_LOGGER_LOG_DBG("id=%x", connection_id);

	struct serial_conn *conn = (struct serial_conn *)(intptr_t)connection_id;

	if (!conn->is_open) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLSERIAL_IOEXCEPTION_GENERIC,
		                                              LLSERIAL_CONNECTION_CONNECTION_CLOSED);
		goto end;
	}

	conn->is_open = false;

	/* Resume any pending I/O threads so their callbacks can clean up */
	fd_monitor_resume_all(LLSERIAL_FD_MONITOR, conn->watch_chain);

	/* Prevent double-close from GC */
	LLSERIAL_UNUSED_RETURN(SNI_unregisterResource(
							   (void *)(intptr_t)conn,
							   (SNI_closeFunction)(void (*)(void)) LLSERIAL_CONNECTION_IMPL_close));

	/* Release owner reference — conn freed when refcount → 0 */
	conn_release(conn);

end:
	return;
}

/* ── LLAPI: getCloseFunction ────────────────────────────────────────── */

int64_t LLSERIAL_CONNECTION_IMPL_getCloseFunction(int32_t connection_id) {
	(void)connection_id;
	return (int64_t)(intptr_t)LLSERIAL_CONNECTION_IMPL_close;
}
