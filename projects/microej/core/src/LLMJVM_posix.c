/*
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLMJVM implementation over POSIX.
 * @author MicroEJ Developer Team
 * @version 1.1.1
 * @date 5 June 2024
 */

#include <stdint.h>
#include <limits.h>
#include <pthread.h>
#include <assert.h>

#include "LLMJVM_impl.h"
#include "microej.h"

#include "posix_timer.h"
#include "posix_time.h"

#ifdef __cplusplus
	extern "C" {
#endif


static pthread_mutex_t 	mutex;
static pthread_cond_t 	condition;
static pthread_t		thread_ref;

/** True if the VM has been waken up */
static uint8_t 			wokeup;


static void LLMJVM_IMPL_timer_expired(void){
	int32_t result = LLMJVM_schedule();
	assert(result==LLMJVM_OK);
}


/*
 * Implementation of functions from LLMJVM_impl.h
 * and other helping functions.
 */

int32_t LLMJVM_IMPL_initialize(void)
{
	return LLMJVM_OK;
}

// Creates the timer used to callback the LLMJVM_schedule() function.
// After its creation, the timer is idle.
int32_t LLMJVM_IMPL_vmTaskStarted(void)
{
	int32_t res = LLMJVM_OK;

	// init timer
	posix_timer_initialize();

	int32_t result;
	pthread_mutexattr_t mutex_attributes;
	result = pthread_mutexattr_init(&mutex_attributes);
	assert(result==0);

	result = pthread_mutexattr_settype(&mutex_attributes, PTHREAD_MUTEX_DEFAULT);
	assert(result==0);

	result = pthread_mutex_init(&mutex, &mutex_attributes);
	assert(result==0);

	result = pthread_mutexattr_destroy(&mutex_attributes);
	assert(result==0);

	// initialize the condition
	pthread_condattr_t condition_attributes;
	result = pthread_condattr_init(&condition_attributes);
	assert(result==0);
	result = pthread_cond_init(&condition, &condition_attributes);
	assert(result==0);

	result = pthread_condattr_destroy(&condition_attributes);
	assert(result==0);

	// initialize and start timer thread
	pthread_attr_t attributes;
	result = pthread_attr_init(&attributes);
	assert(result==0);
	result = pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN);
	assert(result==0);
	// Initialize pthread such as its resource will be
	result = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_JOINABLE);
	assert(result==0);
	result = pthread_create(&thread_ref, &attributes, &posix_timer_run, NULL);

	result = pthread_attr_destroy(&attributes);
	assert(result==0);

	if(result != 0){
		// timer thread could not be created
		res = LLMJVM_ERROR;
	} else {
		// set MicroJvm timer handler
		posix_timer_settimerexpiredhandler(&LLMJVM_IMPL_timer_expired);
	}

	return res;
}


// Schedules requests from the VM
int32_t LLMJVM_IMPL_scheduleRequest(int64_t absolute_time)
{
	posix_timer_schedule_timer(absolute_time);
	return LLMJVM_OK;
}

// Suspends the VM task if the pending flag is not set
int32_t LLMJVM_IMPL_idleVM(void)
{
	int32_t result = pthread_mutex_lock(&mutex);
	assert(result==0);
	if(!wokeup){
		result = pthread_cond_wait(&condition, &mutex);
		assert(result==0);
	}
	result = pthread_mutex_unlock(&mutex);
	assert(result==0);
	return LLMJVM_OK;
}

// Wakes up the VM task and reset next wake up time
int32_t LLMJVM_IMPL_wakeupVM(void)
{
	// notify thread
	int32_t result = pthread_mutex_lock(&mutex);
	assert(result==0);

	wokeup = MICROEJ_TRUE;
	result = pthread_cond_signal(&condition);
	assert(result==0);

	result = pthread_mutex_unlock(&mutex);
	assert(result==0);
	return LLMJVM_OK;
}

// Clear the pending wake up flag
int32_t LLMJVM_IMPL_ackWakeup(void)
{
	wokeup = MICROEJ_FALSE;
	return LLMJVM_OK;
}

int32_t LLMJVM_IMPL_getCurrentTaskID(void)
{
	return pthread_self();
}

void LLMJVM_IMPL_setApplicationTime(int64_t t)
{
	posix_time_setapplicationtime(t);
}

// Gets the system or the application time in milliseconds
int64_t LLMJVM_IMPL_getCurrentTime(uint8_t is_platform_time)
{
	return posix_time_getcurrenttime(is_platform_time);
}

// Gets the current system time in nanoseconds
int64_t LLMJVM_IMPL_getTimeNanos(void){
	return posix_time_gettimenanos();
}

int32_t LLMJVM_IMPL_shutdown(void){
	// stop and dispose Timer thread
	posix_timer_stop();
	int32_t result = pthread_join(thread_ref, NULL);
	assert(result==0);
	posix_timer_dispose();
	// destroy underlying handles
	result = pthread_mutex_destroy(&mutex);
	assert(result==0);
	result = pthread_cond_destroy(&condition);
	assert(result==0);
	return LLMJVM_OK; // nothing to do here
}

#ifdef __cplusplus
	}
#endif
