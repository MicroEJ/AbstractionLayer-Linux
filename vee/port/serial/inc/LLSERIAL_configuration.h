/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLSERIAL_CONFIGURATION_H
#define LLSERIAL_CONFIGURATION_H

#include "veeport_logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Define the File Descriptor monitor instance to use.
 *
 * Default to the system wide instance
 */
#define LLSERIAL_FD_MONITOR                     (&fd_monitor_sys)

/**
 * @brief Name of the log module shared by every source file of the Serial Abstraction Layer.
 *
 * Each source file that logs registers the module with VEEPORT_LOGGER_DEFINE_MODULE().
 */
#define LLSERIAL_LOG_MODULE_NAME "serial"

/**
 * @brief Verbosity of the Serial Abstraction Layer.
 *
 * Override it in veeport_configuration.h with one of VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF
 * or _DBG.
 */
#ifndef LLSERIAL_LOG_LEVEL
#define LLSERIAL_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

#ifdef __cplusplus
}
#endif
#endif // LLSERIAL_CONFIGURATION_H
