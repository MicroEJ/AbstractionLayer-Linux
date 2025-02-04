/*
 * C
 *
 * Copyright 2015-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/* Includes ------------------------------------------------------------------*/

#include <stdint.h>
#include "framerate_impl.h"

/* Globals -------------------------------------------------------------------*/

#ifdef FRAMERATE_ENABLED
static uint32_t framerate_schedule_time = 0;	// means "not initialised"
static uint32_t framerate_counter = 0;
static uint32_t framerate_last = 0;
#endif

/* API -----------------------------------------------------------------------*/

int32_t framerate_init(int32_t schedule_time)
{
#ifdef FRAMERATE_ENABLED

	int32_t return_code = FRAMERATE_OK;

	if (framerate_schedule_time == (uint32_t)0)	// means "not initialized"
	{
		// fix globals
		framerate_schedule_time = schedule_time;
		framerate_counter = 0;
		framerate_last = 0;

		return_code = framerate_impl_start_task();
	}
	return return_code;

#else
	(void) schedule_time;
	return FRAMERATE_ERROR;
#endif
}

void framerate_increment(void)
{
#ifdef FRAMERATE_ENABLED
	framerate_counter++;
#endif
}

uint32_t framerate_get(void)
{
#ifdef FRAMERATE_ENABLED
	return framerate_last;
#else
	return 0;
#endif
}

void framerate_task_work(void)
{
#ifdef FRAMERATE_ENABLED
	while(1)
	{
		// sleep during n milliseconds
		framerate_impl_sleep(framerate_schedule_time);

		// update global counter
		// cppcheck-suppress [misra-c2012-10.8] Truncate float data.
		framerate_last = (int32_t)((float)framerate_counter * ((float)((float)1000 / (float)framerate_schedule_time)));

		// reset framerate counter
		framerate_counter = 0;
	}
#endif
}

/* Java API ------------------------------------------------------------------*/

int32_t javaFramerateInit(int32_t schedule_time)
{
	return framerate_init(schedule_time);
}

uint32_t javaFramerateGet(void)
{
	return framerate_get();
}
