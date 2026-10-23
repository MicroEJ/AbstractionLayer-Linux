/*
 * C
 *
 * Copyright 2023-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLKERNEL RAM implementation.
 * @author MicroEJ Development Team
 * @version 3.0.1
 */

#ifndef  LLKERNEL_RAM_CONFIGURATION_H
#define  LLKERNEL_RAM_CONFIGURATION_H

#include <stdint.h>

#include "veeport_logger.h"

/**
 * @brief Verbosity of the KF Abstraction Layer.
 *
 * Override it in veeport_configuration.h with one of VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF
 * or _DBG.
 */
#ifndef LLKERNEL_LOG_LEVEL
#define LLKERNEL_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

/**
 * @brief Kernel RAM allocation mode:
 * - KERNEL_RAM_IMPL_MALLOC with malloc()/free(): recommended configuration on Linux systems.
 * - KERNEL_RAM_IMPL_BESTFIT with best fit allocator: recommended configuration on MCUs.
 *
 */
#ifndef KERNEL_RAM_IMPL_BESTFIT
#define KERNEL_RAM_IMPL_MALLOC
#endif
// #define KERNEL_RAM_IMPL_BESTFIT

/**
 * @brief Uncomment this macro to set {@link #LLKERNEL_MAX_NB_DYNAMIC_FEATURES}
 * value to a custom value.
 */
//#define LLKERNEL_MAX_NB_DYNAMIC_FEATURES	XX

#endif // LLKERNEL_RAM_CONFIGURATION_H
