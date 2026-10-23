/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief Linux MicroEJ main function.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 26 June 2023
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "LLMJVM_configuration.h"
#include "veeport_main.h"
#include "sighandler.h"
#include "veeport_logger_backend_stdout.h"
#ifdef LLKERNEL_VALIDATION
#include "t_llkernel_main.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* cppcheck-suppress misra-c2012-8.9 ; veeport_logger.h requires the module definition at the top of the file, and
 * main() is the only function of this file that logs. */
VEEPORT_LOGGER_DEFINE_MODULE(LLMJVM_LOG_MODULE_NAME, LLMJVM_LOG_LEVEL)

/*
 * Generic Linux MicroEJ main function
 */
int main(int argc, char **argv) {
#ifndef LLKERNEL_VALIDATION
	int app_exit_code = 0;
	int res;

	/* MEJ Application logs need to be flushed instantly in the SDK console */
	if (setvbuf(stdout, NULL, _IONBF, 0) != 0) {
		/* Reported with printf: the logger backend is not registered yet. */
		(void)printf("setvbuf error: (err = %s).\n", strerror(errno));
	}

	/* Route the traces of the abstraction layers to the standard output. */
	VEEPORT_LOGGER_BACKEND_STDOUT_init();
	/* Only a warning: pthread_setname_np() returns EBUSY when the application runs from a debugger. */
	int name_result = pthread_setname_np(pthread_self(), "MICROEJ VEE");
	if (0 != name_result) {
		VEEPORT_LOGGER_LOG_WRN("cannot name the Core Engine thread (%s)", strerror(name_result));
	}
	res = microej_segfault_handler_init();
	if (0 == res) {
		res = microej_usr1_signal_handler_init();
	}
	if (0 != res) {
		res = EXIT_FAILURE;
	} else {
		res = veeport_main(argc - 1, &argv[1], &app_exit_code);
		if (res == 0) {
			res = app_exit_code;
		}
	}
	return res;
#else
	(void)argc;
	(void)argv;
	/* Start the LLkernel tests */
	T_LLKERNEL_main();
	return 0;
#endif
}

#ifdef __cplusplus
}
#endif
