/*
 * C
 *
 * Copyright 2023-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef  EVENT_CONFIGURATION_H
#define  EVENT_CONFIGURATION_H

#include <stdlib.h>
#include <string.h>
#include "veeport_logger.h"
#include "veeport_errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Max number of events in the queue.
 */
#define EVENT_QUEUE_SIZE (100U)

/**
 * Event function succeeded.
 */
#define EVENT_OK         (0U)

/**
 * An error was detected during the method execution.
 */
#define EVENT_NOK (-1)

/**
 * @brief Name of the log module shared by every source file of the Event Queue Abstraction Layer.
 *
 * Each source file that logs registers the module with VEEPORT_LOGGER_DEFINE_MODULE().
 */
#define LLEVENT_LOG_MODULE_NAME "event-queue"

/**
 * @brief Verbosity of the Event Queue Abstraction Layer.
 *
 * Override it in veeport_configuration.h with one of VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF
 * or _DBG.
 */
#ifndef LLEVENT_LOG_LEVEL
#define LLEVENT_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

#ifdef __cplusplus
}
#endif

#endif // EVENT_CONFIGURATION_H
