/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

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

#include <string.h>
#include "async_wakeup_vm.h"
#include "microejruntime_mock.h"

// -----------------------------------------------------------------------------
// Private Global Variables
// -----------------------------------------------------------------------------

/**
 * @brief Global variables variables that store the timings data used to compute
 * waiting and wake-up times.
 */
static uint32_t async_wakeup_vm_delay_ms;
static uint32_t async_wakeup_vm_start_time_ms;

/**
 * @brief Boolean to indicate if a wakeup action has been scheduled.
 */
static uint8_t async_wakeup_vm_scheduled;

/**
 * @brief Boolean to indicate if the VEE Mock has been stopped.
 */
static uint8_t async_wakeup_vm_stopped;

/**
 * @brief Global variables related to the MICROEJ VEE Mock Task.
 */
static OSAL_task_handle_t async_task_handle = NULL;
OSAL_task_stack_declare(async_task_stack_mem, 1024);

/**
 * @brief Mutex to protect the MICROEJ VEE Mock as a resource.
 */
static OSAL_mutex_handle_t mutex;

// -----------------------------------------------------------------------------
// Private function definitions
// -----------------------------------------------------------------------------

/**
 * @brief Background task responsible for executing scheduled async LLMJVM_IMPL_wakeupVM().
 */
static void * async_task(unsigned long args) {
	VEE_MOCK_UNUSED(args);

	while (!async_wakeup_vm_stopped) {
		OSAL_mutex_take(&mutex, OSAL_INFINITE_TIME);

		if (async_wakeup_vm_scheduled) {
			uint32_t now = LLMJVM_IMPL_getCurrentTime(1);
			uint32_t elapsed = now - async_wakeup_vm_start_time_ms;

			if (elapsed >= async_wakeup_vm_delay_ms) {
				async_wakeup_vm_scheduled = 0;
				OSAL_mutex_give(&mutex);
				LLMJVM_IMPL_wakeupVM();
				continue;
			}
		}

		OSAL_mutex_give(&mutex);

		// Implementation note:
		// Active polling has been chosen to limit the dependencies on OSAL
		// and avoid issues caused by an OSAL limitation.
		OSAL_sleep(1);
	}

	return NULL;
}

// -----------------------------------------------------------------------------
// Public function definitions
// -----------------------------------------------------------------------------

// Initializes the async_wakeup_vm library and starts the background task.
OSAL_status_t async_wakeup_vm_init(void) {
	OSAL_status_t status;

	async_wakeup_vm_stopped = 0;

	status = OSAL_mutex_create((uint8_t *)"async_mutex", &mutex);
	if (status != OSAL_OK) {
		return status;
	}

	status = OSAL_task_create(async_task, (uint8_t *)"async_task", async_task_stack_mem, 1, NULL, &async_task_handle);
	return status;
}

void async_wakeup_vm_stop(void) {
	async_wakeup_vm_stopped = 1;
}

// Schedules an LLMJVM_IMPL_wakeupVM() to be executed after a specified delay.
OSAL_status_t async_wakeup_vm(uint32_t delay_ms) {
	OSAL_status_t status = OSAL_OK;

	OSAL_mutex_take(&mutex, OSAL_INFINITE_TIME);

	if (async_wakeup_vm_scheduled) {
		status = OSAL_ERROR; // A call is already scheduled
	} else {
		async_wakeup_vm_delay_ms = delay_ms;
		async_wakeup_vm_start_time_ms = LLMJVM_IMPL_getCurrentTime(1);
		async_wakeup_vm_scheduled = 1;
	}

	OSAL_mutex_give(&mutex);
	return status;
}

// Cancels a previously scheduled LLMJVM_IMPL_wakeupVM().
OSAL_status_t async_wakeup_vm_cancel(void) {
	OSAL_status_t status = OSAL_ERROR;

	OSAL_mutex_take(&mutex, OSAL_INFINITE_TIME);

	if (async_wakeup_vm_scheduled) {
		async_wakeup_vm_scheduled = 0;
		status = OSAL_OK;
	}

	OSAL_mutex_give(&mutex);
	return status;
}

#endif // (MICROEJ_CORE_VEE_MOCK_VALIDATION == 1)

// -----------------------------------------------------------------------------
// End
// -----------------------------------------------------------------------------
