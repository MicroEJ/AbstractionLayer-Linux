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

#ifndef LLKERNEL_RAM_H
#define LLKERNEL_RAM_H

#include "veeport_logger.h"
#include "LLKERNEL_RAM_configuration.h"

/**
 * @brief Name of the log module shared by every source file of the KF Abstraction Layer.
 *
 * Each source file that logs registers the module with VEEPORT_LOGGER_DEFINE_MODULE().
 */
#define LLKERNEL_LOG_MODULE_NAME "kf"

#ifdef KERNEL_RAM_IMPL_BESTFIT
#include <limits.h>
#include "BESTFIT_ALLOCATOR.h"

/**
 * @brief Bestfit allocator initialization, to be called before starting MicroEJ VEE.
 *
 * @param start_address the start address of the kernel buffer.
 * @param end_address the start address of the kernel buffer.
 */
void LLKERNEL_RAM_BESTFIT_initialize(int32_t start_address, int32_t end_address);

/**
 * @brief Check the size to be allocated before bestfit allocation.
 *
 * @param size the size of the memory to allocate.
 * @return void* the pointer to the allocated memory.
 */
void * BESTFIT_ALLOCATOR_allocate_with_check(int32_t size);
#endif // KERNEL_RAM_IMPL_BESTFIT

/**
 * @brief Kernel memory allocation macro.
 *
 */
#ifdef KERNEL_RAM_IMPL_MALLOC
#define KERNEL_MALLOC(size) malloc((size_t)(size))
#else
#ifdef KERNEL_RAM_IMPL_BESTFIT
#define KERNEL_MALLOC(size) BESTFIT_ALLOCATOR_allocate_with_check(size)
#endif // KERNEL_RAM_IMPL_BESTFIT
#endif // KERNEL_RAM_IMPL_MALLOC

/**
 * @brief Kernel memory free macro.
 *
 */
#ifdef KERNEL_RAM_IMPL_MALLOC
#define KERNEL_FREE(addr) free(addr)
#else
#ifdef KERNEL_RAM_IMPL_BESTFIT
#define KERNEL_FREE(addr) BESTFIT_ALLOCATOR_free(&bestfit_allocator_instance, addr)
#endif // KERNEL_RAM_IMPL_BESTFIT
#endif // KERNEL_RAM_IMPL_MALLOC

/**@brief Maximum number of Features that can be dynamically installed */
#ifndef LLKERNEL_MAX_NB_DYNAMIC_FEATURES
// set {@link #LLKERNEL_MAX_NB_DYNAMIC_FEATURES} value to the value of the MicroEJ
// Kernel maximum number of Features that can be dynamically installed.
// See
// https://docs.microej.com/en/latest/ApplicationDeveloperGuide/applicationOptions.html#option-maximum-number-of-dynamic-features
extern int32_t _java_max_nb_dynamic_features;
	#define LLKERNEL_MAX_NB_DYNAMIC_FEATURES ((int32_t)&_java_max_nb_dynamic_features)
#endif // LLKERNEL_MAX_NB_DYNAMIC_FEATURES

#endif // LLKERNEL_RAM_H
