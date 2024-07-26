/*
 * C
 *
 * Copyright 2013-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

/* Includes ------------------------------------------------------------------*/

#include <stdint.h>
#include <pthread.h>

#include "LLUI_INPUT_impl.h"
#include "microej.h"
#ifdef TOUCHMANAGER_ENABLED
#include "touch_manager.h"
#endif

/* Private variables ---------------------------------------------------------*/

static pthread_mutex_t input_mutex;


/* API -----------------------------------------------------------------------*/

void LLUI_INPUT_IMPL_initialize(void)
{
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&input_mutex, &attr);

#ifdef TOUCHMANAGER_ENABLED
	TOUCH_MANAGER_initialize();
#endif
}

int32_t LLUI_INPUT_IMPL_getInitialStateValue(int32_t stateMachinesID, int32_t stateID)
{
	// no state on this BSP
	return 0;
}

void LLUI_INPUT_IMPL_enterCriticalSection(void)
{
  pthread_mutex_lock(&input_mutex);
}

void LLUI_INPUT_IMPL_leaveCriticalSection(void)
{
  pthread_mutex_unlock(&input_mutex);
}
