/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
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
/* cppcheck-suppress misra-c2012-21.10 ; included only for the POSIX clock API (CLOCK_MONOTONIC, struct timespec); no
 * ISO C time and date function is used. */
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "LLMJVM_configuration.h"
#include "microej.h"
#include "posix_time.h"

#ifdef __cplusplus
extern "C" {
#endif

VEEPORT_LOGGER_DEFINE_MODULE(LLMJVM_LOG_MODULE_NAME, LLMJVM_LOG_LEVEL)

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

int32_t posix_timer_initialize(void) {
	next_wakeup_time = LONG_MAX_VALUE;
	running = MICROEJ_TRUE;

	int32_t result = pthread_mutex_init(&timer_mutex, NULL);
	if (0 != result) {
		VEEPORT_LOGGER_LOG_ERR("cannot initialize the timer mutex (%s)", strerror(result));
	} else {
		pthread_condattr_t condition_attributes;
		result = pthread_condattr_init(&condition_attributes);
		if (0 != result) {
			VEEPORT_LOGGER_LOG_ERR("cannot initialize the timer condition attributes (%s)", strerror(result));
		} else {
			#ifndef CONDITION_SETCLOCK_NO_SUPPORT
			// time used by the condition in pthread_cond_timedwait is monotonic
			result = pthread_condattr_setclock(&condition_attributes, CLOCK_MONOTONIC);
			if (0 != result) {
				VEEPORT_LOGGER_LOG_ERR("cannot set the timer condition clock (%s)", strerror(result));
			}
			#endif
			if (0 == result) {
				result = pthread_cond_init(&timer_condition, &condition_attributes);
				if (0 != result) {
					VEEPORT_LOGGER_LOG_ERR("cannot initialize the timer condition (%s)", strerror(result));
				}
			}

			int32_t destroy_result = pthread_condattr_destroy(&condition_attributes);
			if (0 != destroy_result) {
				VEEPORT_LOGGER_LOG_ERR("cannot destroy the timer condition attributes (%s)",
				                       strerror(destroy_result));
			}
		}
	}
	return result;
}

void posix_timer_settimerexpiredhandler(void (*handler) (void)) {
	timerexpiredhandler = handler;
}

void * posix_timer_run(void *args) {
	(void)args;

	while ((uint8_t)MICROEJ_TRUE == running) {
		int32_t result = pthread_mutex_lock(&timer_mutex);
		if (0 != result) {
			VEEPORT_LOGGER_LOG_ERR("cannot lock the timer mutex (%s)", strerror(result));
			/* cppcheck-suppress misra-c2012-21.8 ; the error cannot be recovered. A supervisor can restart a process
			 * that ends, but not a process that hangs. */
			exit(EXIT_FAILURE);
		}

		if ((next_wakeup_time > 0) && (next_wakeup_time != LONG_MAX_VALUE)) { // timer launch scheduled
			if (next_wakeup_time > posix_time_getcurrenttime(MICROEJ_TRUE)) {
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
				if (result == ETIMEDOUT) {
					// timeout occurred, timer expired
					timerexpiredhandler();
					next_wakeup_time = LONG_MAX_VALUE;//not schedule anymore
				} else if (0 != result) {
					VEEPORT_LOGGER_LOG_ERR("cannot wait for the timer condition (%s)", strerror(result));
				} else {
					// woken up by a new schedule, a reset or a stop
				}
			} else {
				timerexpiredhandler();// timer could be launch now
				next_wakeup_time = LONG_MAX_VALUE;//not schedule anymore
			}
		} else {
			result = pthread_cond_wait(&timer_condition, &timer_mutex);
			if (0 != result) {
				VEEPORT_LOGGER_LOG_ERR("cannot wait for the timer condition (%s)", strerror(result));
			}
		}

		result = pthread_mutex_unlock(&timer_mutex);
		if (0 != result) {
			VEEPORT_LOGGER_LOG_ERR("cannot unlock the timer mutex (%s)", strerror(result));
		}
	}
	return NULL;
}

void posix_timer_schedule_timer(int64_t schedule_time_ms) {
	assert(schedule_time_ms > 0);
	int32_t result = pthread_mutex_lock(&timer_mutex);
	if (0 != result) {
		VEEPORT_LOGGER_LOG_ERR("cannot lock the timer mutex (%s)", strerror(result));
		/* cppcheck-suppress misra-c2012-21.8 ; the error cannot be recovered. A supervisor can restart a process that
		 * ends, but not a process that hangs. */
		exit(EXIT_FAILURE);
	} else {
		if (schedule_time_ms < next_wakeup_time) {
			// register new wake up time
			next_wakeup_time = schedule_time_ms;

			// notify thread that new schedule is requested
			result = pthread_cond_signal(&timer_condition);
			if (0 != result) {
				VEEPORT_LOGGER_LOG_ERR("cannot signal the timer condition (%s)", strerror(result));
				/* cppcheck-suppress misra-c2012-21.8 ; the error cannot be recovered. A supervisor can restart a
				 * process that ends, but not a process that hangs. */
				exit(EXIT_FAILURE);
			}
		}

		result = pthread_mutex_unlock(&timer_mutex);
		if (0 != result) {
			VEEPORT_LOGGER_LOG_ERR("cannot unlock the timer mutex (%s)", strerror(result));
		}
	}
}

void posix_timer_reset(void) {
	// reset next wakeup
	next_wakeup_time = LONG_MAX_VALUE;
	// unlock timer thread
	int32_t result = pthread_cond_broadcast(&timer_condition);
	if (0 != result) {
		VEEPORT_LOGGER_LOG_ERR("cannot broadcast the timer condition (%s)", strerror(result));
	}
}

void posix_timer_stop(void) {
	// stop timer
	running = MICROEJ_FALSE;
	// unlock timer thread
	int32_t result = pthread_cond_broadcast(&timer_condition);
	if (0 != result) {
		VEEPORT_LOGGER_LOG_ERR("cannot broadcast the timer condition (%s)", strerror(result));
	}
}

void posix_timer_dispose(void) {
	int32_t result = pthread_cond_destroy(&timer_condition);
	if (0 != result) {
		VEEPORT_LOGGER_LOG_ERR("cannot destroy the timer condition (%s)", strerror(result));
	}
	result = pthread_mutex_destroy(&timer_mutex);
	if (0 != result) {
		VEEPORT_LOGGER_LOG_ERR("cannot destroy the timer mutex (%s)", strerror(result));
	}
}

#ifdef __cplusplus
}
#endif
