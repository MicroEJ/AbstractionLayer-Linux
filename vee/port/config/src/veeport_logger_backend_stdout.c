/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief Standard output backend of the VEE Port logger.
 * @author MicroEJ Developer Team
 */

#include <stdio.h>

#include "veeport_logger.h"
#include "veeport_logger_backend_stdout.h"

/** @brief Number of backends registered by this module. */
#define BACKEND_STDOUT_NB_BACKENDS (1U)

static void backend_stdout_init(const VEEPORT_LOGGER_backend_t *const backend);
static void backend_stdout_process(const VEEPORT_LOGGER_backend_t *const backend, const char *msg);

static VEEPORT_LOGGER_backend_t BACKEND_STDOUT = {
	.init = backend_stdout_init,
	.process = backend_stdout_process
};

static VEEPORT_LOGGER_backend_t *BACKEND_STDOUT_LIST[BACKEND_STDOUT_NB_BACKENDS] = { &BACKEND_STDOUT };

/**
 * @brief Initializes the standard output backend.
 *
 * @details Nothing to do: the buffering mode of stdout is set by the VEE Port main function, so that
 * the logs of the VEE Port and the ones of the MicroEJ Application are interleaved in the same order
 * they were emitted.
 *
 * @param backend pointer to the backend.
 */
static void backend_stdout_init(const VEEPORT_LOGGER_backend_t *const backend) {
	(void)backend;
}

/**
 * @brief Writes a formatted message to the standard output.
 *
 * @details The message already ends with a line separator, added by the logger. It is written with a
 * single fputs() call so that the C library serializes the concurrent writes of the VEE Port threads
 * and a log line is never interleaved with another one.
 *
 * @param backend pointer to the backend.
 * @param msg message to write.
 */
static void backend_stdout_process(const VEEPORT_LOGGER_backend_t *const backend, const char *msg) {
	(void)backend;

	if (EOF == fputs(msg, stdout)) {
		// Nothing can be reported: the log output is the failing stream.
	}
}

void VEEPORT_LOGGER_BACKEND_STDOUT_init(void) {
	VEEPORT_LOGGER_init(BACKEND_STDOUT_LIST, BACKEND_STDOUT_NB_BACKENDS);
}
