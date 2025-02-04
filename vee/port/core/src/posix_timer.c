/*
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief POSIX timer implementation.
 * @author MicroEJ Developer Team
 * @version 1.1.1
 * @date 5 June 2024
 */

#include "posix_timer.h"
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

#include "microej.h"
#include "posix_time.h"

#ifdef __cplusplus
	extern "C" {
#endif

static uint8_t running;

static pthread_mutex_t timer_mutex;
static pthread_cond_t timer_condition;

/** Absolute Monotonic time (e.g. time since the startup of the system) */
static int64_t next_wakeup_time;

static void (*timerexpiredhandler)(void);

#define LONG_MAX_VALUE 9223372036854775807L

/*
 *********************************************************************************************************
 *                                             PUBLIC FUNCTIONS
 *********************************************************************************************************
 */

void posix_timer_initialize(void){
	next_wakeup_time = LONG_MAX_VALUE;
	running = MICROEJ_TRUE;

	pthread_mutexattr_t mutex_attributes;
	int32_t result = pthread_mutexattr_init(&mutex_attributes);
	assert(result==0);

	result = pthread_mutexattr_settype(&mutex_attributes, PTHREAD_MUTEX_DEFAULT);
	assert(result==0);

	result = pthread_mutex_init(&timer_mutex, &mutex_attributes);
	assert(result==0);
	result = pthread_mutexattr_destroy(&mutex_attributes);
	assert(result==0);

	// initialize the condition
	pthread_condattr_t condition_attributes;
	result = pthread_condattr_init(&condition_attributes);
	assert(result==0);
	#ifndef CONDITION_SETCLOCK_NO_SUPPORT
		// time used by the condition in pthread_cond_timedwait is monotonic
		result = pthread_condattr_setclock(&condition_attributes, CLOCK_MONOTONIC);
		assert(result==0);
	#endif
	result = pthread_cond_init(&timer_condition, &condition_attributes);
	assert(result==0);
	result = pthread_condattr_destroy(&condition_attributes);
	assert(result==0);
}

void posix_timer_settimerexpiredhandler(void (*handler) (void)){
	timerexpiredhandler = handler;
}

void * posix_timer_run(void* args){
	(void)args;
	int32_t result;

	while((uint8_t) MICROEJ_TRUE == running){
		result = pthread_mutex_lock(&timer_mutex);
		assert(result==0);

		if((next_wakeup_time > 0) && (next_wakeup_time!=LONG_MAX_VALUE)){ // timer launch scheduled
			if(next_wakeup_time > posix_time_getcurrenttime(MICROEJ_TRUE)){

				int64_t tmp_next_wakeup_time = next_wakeup_time;
				#ifdef CONDITION_SETCLOCK_NO_SUPPORT
					//If there is no support to configure the condition on monotonic clock,
					//then the absolute time given to timedwait must come from realtime clock.
					tmp_next_wakeup_time = posix_time_getrealtimefrommonotonictime(tmp_next_wakeup_time);
				#endif

				struct timespec ts;
				ts.tv_sec = (int32_t)(tmp_next_wakeup_time / 1000);
				ts.tv_nsec = (int32_t)(tmp_next_wakeup_time % 1000) * 1000000;

				result = pthread_cond_timedwait(&timer_condition, &timer_mutex, &ts);
				if(result == ETIMEDOUT){
					// timeout occurred, timer expired
					timerexpiredhandler();
					next_wakeup_time = LONG_MAX_VALUE;//not schedule anymore
				}
			}else{
				timerexpiredhandler();// timer could be launch now
				next_wakeup_time = LONG_MAX_VALUE;//not schedule anymore
			}
		}
		else{
			result = pthread_cond_wait(&timer_condition, &timer_mutex);
		}

		result = pthread_mutex_unlock(&timer_mutex);
		assert(result==0);
	}
	return NULL;
}

void posix_timer_schedule_timer(int64_t schedule_time_ms){
	assert(schedule_time_ms>0);
	int32_t result = pthread_mutex_lock(&timer_mutex);
	assert(result==0);

	if(schedule_time_ms < next_wakeup_time){
		// register new wake up time
		next_wakeup_time = schedule_time_ms;

		// notify thread that new schedule is requested
		result = pthread_cond_signal(&timer_condition);
		assert(result==0);
	}

	result = pthread_mutex_unlock(&timer_mutex);
	assert(result==0);
}

void posix_timer_stop(void){
	// stop timer
	running = MICROEJ_FALSE;
	// unlock timer thread
	int32_t result = pthread_cond_broadcast(&timer_condition);
	assert(result==0);
}

void posix_timer_dispose(void){
	int32_t result = 0;
	// destroy underlying handles
	result = pthread_cond_destroy(&timer_condition);
	assert(result==0);
	result = pthread_mutex_destroy(&timer_mutex);
	assert(result==0);
}

#ifdef __cplusplus
	}
#endif
