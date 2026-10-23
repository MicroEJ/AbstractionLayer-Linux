/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#ifndef LLMJVM_CONFIGURATION_H
#define LLMJVM_CONFIGURATION_H

#if defined __has_include
#if __has_include("veeport_configuration.h")
#include "veeport_configuration.h"
#endif // __has_include("veeport_configuration.h")
#else
#include "veeport_configuration.h"
#endif // defined __has_include

#include "veeport_logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Name of the log module shared by every source file of the Core Abstraction Layer.
 *
 * Each source file that logs registers the module with VEEPORT_LOGGER_DEFINE_MODULE().
 */
#define LLMJVM_LOG_MODULE_NAME "core"

/**
 * @brief Verbosity of the Core Abstraction Layer.
 *
 * Override it in veeport_configuration.h with one of VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF
 * or _DBG.
 */
#ifndef LLMJVM_LOG_LEVEL
#define LLMJVM_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

#ifdef __cplusplus
}
#endif

#endif // LLMJVM_CONFIGURATION_H
