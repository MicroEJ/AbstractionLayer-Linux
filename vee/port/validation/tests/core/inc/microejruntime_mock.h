/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef MICROEJRUNTIME_MOCK_H
#define MICROEJRUNTIME_MOCK_H

// -----------------------------------------------------------------------------
// Includes
// -----------------------------------------------------------------------------

// Include VEE Port User configuration file
#if defined __has_include
	#if __has_include("veeport_configuration.h")
		#include "veeport_configuration.h"
	#endif // __has_include("veeport_configuration.h")
#else
// Ensure 'veeport_configuration.h' exists in your project for custom configurations.
	#include "veeport_configuration.h"
#endif // defined __has_include

#if (MICROEJ_CORE_VEE_MOCK_VALIDATION == 1)

#include <stdint.h>
#include <stdio.h>

// Defines and function prototypes copied from LLMJVM_impl.h and LLMJVM.h because these header files
// have no include guard, so they cannot be included in 2 different files.
#define LLMJVM_schedule __icetea__virtual__com_is2t_microjvm_bsp_IGreenThreadMicroJvmScheduler___schedule
#define LLMJVM_dump __icetea__virtual__com_is2t_microjvm_IGreenThreadMicroJvm___dump
#define LLMJVM_IMPL_getCurrentTime LLMJVM_IMPL_getCurrentTime__Z
#define LLMJVM_IMPL_scheduleRequest LLMJVM_IMPL_scheduleRequest__J
#define LLMJVM_OK (0)
#define LLMJVM_INTERRUPTED (1)
#define LLMJVM_ERROR (-1)
int32_t LLMJVM_IMPL_initialize(void);
int32_t LLMJVM_IMPL_vmTaskStarted(void);
int32_t LLMJVM_IMPL_scheduleRequest(int64_t absoluteTime);
int32_t LLMJVM_IMPL_idleVM(void);
int32_t LLMJVM_IMPL_wakeupVM(void);
int32_t LLMJVM_IMPL_ackWakeup(void);
int32_t LLMJVM_IMPL_getCurrentTaskID(void);
int32_t LLMJVM_IMPL_shutdown(void);
void LLMJVM_IMPL_setApplicationTime(int64_t t);
int64_t LLMJVM_IMPL_getCurrentTime(uint8_t monotonic);
int64_t LLMJVM_IMPL_getTimeNanos(void);
int32_t LLMJVM_schedule(void);

/** Marks a variable as intentionally unused to suppress compiler warnings
 *  @param x The variable to be marked as unused
 */
#define VEE_MOCK_UNUSED(x)  ((void)(x))

#endif // (MICROEJ_CORE_VEE_MOCK_VALIDATION == 1)

#endif // MICROEJRUNTIME_MOCK_H

// -----------------------------------------------------------------------------
// End
// -----------------------------------------------------------------------------
