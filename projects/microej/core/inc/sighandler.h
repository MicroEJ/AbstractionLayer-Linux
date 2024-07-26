/**
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef SIGHANDLER_H
#define SIGHANDLER_H

/**
 * @file
 * @brief Signal handler initialization API.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 26 June 2023
 */

#ifdef __cplusplus
	extern "C" {
#endif

/**
 * @brief Initializes the handler called when a segmentation fault occurs.
 */
void microej_segfault_handler_init(void);

/**
 * @brief Initializes the handler that executes a MicroEJ Core Engine dump when SIGUSR1 signal is received by the current process.
 */
void microej_usr1_signal_handler_init(void);

#ifdef __cplusplus
	}
#endif

#endif // SIGHANDLER_H

