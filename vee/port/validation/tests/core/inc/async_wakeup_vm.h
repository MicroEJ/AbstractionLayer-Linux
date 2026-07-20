/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef ASYNC_WAKEUP_VM_H
#define ASYNC_WAKEUP_VM_H

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
#include "osal.h"

// -----------------------------------------------------------------------------
// Public function declaration
// -----------------------------------------------------------------------------

/**
 * @brief Initialize async wakeup feature. Must be called once before using async_wakeup_vm().
 *
 * @return OSAL_OK on success, or another OSAL_status_t error code.
 */
OSAL_status_t async_wakeup_vm_init(void);

/**
 * @brief Call LLMJVM_IMPL_wakeupVM in timeout_ms ms
 *
 * @return OSAL_OK on success, OSAL_ERROR if a call is already scheduled.
 */
OSAL_status_t  async_wakeup_vm(uint32_t timeout_ms);

/**
 * @brief Cancel the scheduled async wakeupVM.
 *
 * @return OSAL_OK if a call was canceled, OSAL_ERROR if there was nothing to cancel.
 */
OSAL_status_t  async_wakeup_vm_cancel(void);

/**
 * @brief Stop async wakeup feature.
 */
void async_wakeup_vm_stop(void);

#endif // (MICROEJ_CORE_VEE_MOCK_VALIDATION == 1)

#endif // ASYNC_WAKEUP_VM_H

// -----------------------------------------------------------------------------
// End
// -----------------------------------------------------------------------------
