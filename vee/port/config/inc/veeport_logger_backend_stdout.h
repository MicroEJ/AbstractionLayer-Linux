/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef VEEPORT_LOGGER_BACKEND_STDOUT_H
#define VEEPORT_LOGGER_BACKEND_STDOUT_H

/**
 * @file
 * @brief Standard output backend of the VEE Port logger.
 * @author MicroEJ Developer Team
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Registers the standard output backend and initializes the VEE Port logger.
 *
 * @details It must be called once, before any abstraction layer logs a message. The messages logged
 * before this call are dropped.
 */
void VEEPORT_LOGGER_BACKEND_STDOUT_init(void);

#ifdef __cplusplus
}
#endif

#endif // VEEPORT_LOGGER_BACKEND_STDOUT_H
