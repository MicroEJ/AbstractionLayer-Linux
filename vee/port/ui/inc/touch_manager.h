/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef _TOUCH_MANAGER
#define _TOUCH_MANAGER

/* Includes ------------------------------------------------------------------*/

#include <stdint.h>

#include "veeport_logger.h"

/* Defines -------------------------------------------------------------------*/

/**
 * @brief Name of the log module of the touchscreen manager.
 *
 * Each source file that logs registers the module with VEEPORT_LOGGER_DEFINE_MODULE().
 */
#define LLTOUCH_LOG_MODULE_NAME "touch"

/**
 * @brief Verbosity of the touchscreen manager.
 *
 * Override it in veeport_configuration.h with one of VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF
 * or _DBG.
 */
#ifndef LLTOUCH_LOG_LEVEL
#define LLTOUCH_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

/* API -----------------------------------------------------------------------*/

void TOUCH_MANAGER_initialize(void);
void * TOUCH_MANAGER_work(void *p_args);

#endif // _TOUCH_MANAGER
