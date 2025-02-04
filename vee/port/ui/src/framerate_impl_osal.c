/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/*
 * Implementation for OSAL
 */

#include <stddef.h>
#include "framerate_conf.h"
#ifdef FRAMERATE_ENABLED

/* Includes ------------------------------------------------------------------*/

#include "osal.h"
#include "framerate_impl.h"

/* Defines -------------------------------------------------------------------*/

#define FRAMERATE_STACK_SIZE ( 512 )
#define FRAMERATE_TASK_PRIORITY      ( 3 )
#define FRAMERATE_TASK_STACK_SIZE     FRAMERATE_STACK_SIZE/4
#define FRAMERATE_TASK_NAME "Framerate"

/* Private API ---------------------------------------------------------------*/

OSAL_task_stack_declare(framerate_task_stack, FRAMERATE_TASK_STACK_SIZE);

static OSAL_task_handle_t task_handle;

static void _framerate_task_entry_point(void * pvParameters)
{
	(void) pvParameters;
	// launch framerate job
	framerate_task_work();
	// job end, cleanup resources
	OSAL_task_delete(&task_handle);
}

/* API -----------------------------------------------------------------------*/

int32_t framerate_impl_start_task(void)
{
	OSAL_status_t status = OSAL_task_create((OSAL_task_entry_point_t) _framerate_task_entry_point, FRAMERATE_TASK_NAME, framerate_task_stack, FRAMERATE_TASK_PRIORITY, NULL, &task_handle);
	return (OSAL_OK == status) ? FRAMERATE_OK : FRAMERATE_ERROR;
}

void framerate_impl_sleep(uint32_t ms)
{
	OSAL_sleep(ms);
	return;
}

#endif

