/*
 * C
 *
 * Copyright 2017-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

/**
 * @file
 * @brief OS Abstraction Layer empty implementation
 * @author MicroEJ Developer Team
 * @version 1.1.0
 * @date 6 July 2022
 */

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "osal.h"

#define NANOSECONDS_IN_SECONDS 1000000000
#define NANOSECONDS_IN_MILLISECONDS 1000000
#define MILLISECONDS_IN_SECONDS 1000

static OSAL_status_t OSAL_posix_current_time(struct timespec *time);
static OSAL_status_t OSAL_posix_time_add(struct timespec t1, struct timespec t2, struct timespec *time);
static OSAL_status_t OSAL_milliseconds_to_posix_time(struct timespec *time, uint32_t ms);
static OSAL_status_t OSAL_add_milliseconds_to_posix_current_time(uint32_t ms, struct timespec *time);

/**
 * @brief Create an OS task and start it.
 *
 * @param[in] entry_point function called at task startup
 * @param[in] name the task name
 * @param[in] stack task stack declared using OSAL_task_stack_declare() macro
 * @param[in] priority task priority
 * @param[in] parameters task entry parameters. NULL if no entry parameters
 * @param[in,out] handle pointer on a task handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_task_create(OSAL_task_entry_point_t entry_point, uint8_t *name, OSAL_task_stack_t stack,
                               int32_t priority, void *parameters, OSAL_task_handle_t *handle) {
	OSAL_status_t result = OSAL_ERROR;
	int32_t pthread_result = 0;
	pthread_attr_t attr;

	int32_t stack_size = (int)stack;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		pthread_result = pthread_attr_init(&attr);
		if (0 == pthread_result) {
			if (stack_size > 0) {
				pthread_attr_setstacksize(&attr, stack_size);
			}

			int32_t create_result = pthread_create((pthread_t *)handle, &attr, entry_point, parameters);
			if (0 == create_result) {
				//Do not check pthread_setname_np return code since this function may result in error <code>EBUSY</code>
				//if the application is run from a debugger (see pthread_setname_np API documentation).
				pthread_setname_np((pthread_t)*handle, (const char *)name);
				result = OSAL_OK;
			}
		}
	}

	return result;
}

/**
 * @brief Delete an OS task and start it.
 *
 * @param[in] handle pointer on the task handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_task_delete(OSAL_task_handle_t *handle) {
	// nothing to do
	return OSAL_OK;
}

/**
 * @brief Create an OS queue with a predefined queue size.
 *
 * @param[in] name queue name
 * @param[in,out] handle pointer on a queue handle
 * @param[in] queue structure containing address and size declared using OSAL_queue_declare() macro
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_queue_create(uint8_t *name, OSAL_queue_handle_t *handle, OSAL_queue_t queue) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		uint8_t *name_local = malloc(strlen((const char *)name) + 1);
		if (NULL == name_local) {
			result = OSAL_NOMEM;
		} else {
			strcpy((char *)name_local, (const char *)name);
			handle->name = name_local;
			handle->size = queue.size;
			handle->message_queue = queue.addr;
			handle->first_message_index = 0;
			handle->last_message_index = 0;
			handle->count = 0;

			if (0 == pthread_mutex_init(&(handle->mutex), NULL)) {
				result = OSAL_OK;
			}

			if ((result == OSAL_OK) && (0 != pthread_cond_init(&(handle->condition), NULL))) {
				result = OSAL_ERROR;
			}
		}
	}

	return result;
}

/**
 * @brief Delete an OS queue.
 *
 * @param[in] handle pointer on the queue handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_queue_delete(OSAL_queue_handle_t *handle) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		// free queue mutex and condition
		if (0 == pthread_mutex_destroy(&(handle->mutex))) {
			result = OSAL_OK;
		}

		if ((result == OSAL_OK) && (0 != pthread_cond_destroy(&(handle->condition)))) {
			result = OSAL_ERROR;
		}

		free(handle->name);
	}

	return result;
}

static void* OSAL_queue_pop(OSAL_queue_handle_t *handle) {
	void *msg = ((void **)handle->message_queue)[handle->first_message_index];
	handle->first_message_index = (handle->first_message_index + 1) % handle->size;
	handle->count--;

	return msg;
}

static void OSAL_queue_push(OSAL_queue_handle_t *handle, void *msg) {
	((void **)handle->message_queue)[handle->last_message_index] = msg;
	handle->last_message_index = (handle->last_message_index + 1) % handle->size;
	handle->count++;
}

static OSAL_status_t OSAL_queue_wait(OSAL_queue_handle_t *handle, uint32_t timeout) {
	OSAL_status_t result = OSAL_ERROR;

	struct timespec absolute_time_result;
	if (OSAL_OK == OSAL_add_milliseconds_to_posix_current_time(timeout, &absolute_time_result)) {
		if (0 == pthread_cond_timedwait(&(handle->condition), &(handle->mutex), &absolute_time_result)) {
			result = OSAL_OK;
		}
	}
	return result;
}

/**
 * @brief Post a message in an OS queue.
 *
 * @param[in] handle pointer on the queue handle
 * @param[in] msg message to post in the message queue
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_queue_post(OSAL_queue_handle_t *handle, void *msg) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	}

	if (0 != pthread_mutex_lock(&(handle->mutex))) {
		return OSAL_ERROR;
	}

	if (handle->count < handle->size) {
		OSAL_queue_push(handle, msg);
		result = OSAL_OK;
	} else {
		// no space available to add the message
		result = OSAL_NOMEM;
	}

	if (0 != pthread_cond_signal(&(handle->condition))) {
		return OSAL_ERROR;
	}

	if (0 != pthread_mutex_unlock(&(handle->mutex))) {
		return OSAL_ERROR;
	}

	return result;
}

/**
 * @brief Fetch a message from an OS queue. Blocks until a message arrived or a timeout occurred.
 *
 * @param[in] handle pointer on the queue handle
 * @param[in,out] msg message fetched in the OS queue
 * @param[in] timeout maximum time to wait for message arrival
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_queue_fetch(OSAL_queue_handle_t *handle, void **msg, uint32_t timeout) {
	OSAL_status_t result = OSAL_ERROR;

	if ((NULL == handle) || (NULL == msg)) {
		return OSAL_WRONG_ARGS;
	}

	if (0 != pthread_mutex_lock(&(handle->mutex))) {
		return OSAL_ERROR;
	}

	if(handle->count > 0 || OSAL_OK == OSAL_queue_wait(handle, timeout)) {
		*msg = OSAL_queue_pop(handle);
		result = OSAL_OK;
	}

	if (0 != pthread_mutex_unlock(&(handle->mutex))) {
		return OSAL_ERROR;
	}

	return result;
}

/**
 * @brief Create an OS counter semaphore with a semaphore count initial value.
 *
 * @param[in] name counter semaphore name
 * @param[in] initial_count counter semaphore initial count value
 * @param[in] max_count counter semaphore maximum count value
 * @param[in,out] handle pointer on a counter semaphore handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_counter_semaphore_create(uint8_t *name, uint32_t initial_count, uint32_t max_count,
                                            OSAL_counter_semaphore_handle_t *handle) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (-1 != sem_init(handle, 0, initial_count)) {
			result = OSAL_OK;
		}
	}

	return result;
}

/**
 * @brief Delete an OS counter semaphore.
 *
 * @param[in] handle pointer on the counter semaphore handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_counter_semaphore_delete(OSAL_counter_semaphore_handle_t *handle) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (-1 != sem_destroy(handle)) {
			result = OSAL_OK;
		}
	}

	return result;
}

/**
 * @brief Take operation on OS counter semaphore. Block the current task until counter semaphore
 * become available or timeout occurred. Decrease the counter semaphore count value by 1 and
 * block the current task if count value equals to 0.
 *
 * @param[in] handle pointer on the counter semaphore handle
 * @param[in] timeout maximum time to wait until the counter semaphore become available
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_counter_semaphore_take(OSAL_counter_semaphore_handle_t *handle, uint32_t timeout) {
	OSAL_status_t result = OSAL_ERROR;
	struct timespec ts;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		result = OSAL_add_milliseconds_to_posix_current_time(timeout, &ts);
		if (OSAL_OK == result) {
			if (-1 == sem_timedwait(handle, &ts)) {
				printf("[ERROR] failed to take semaphore (%s) with timeout %ld\n", strerror(errno), ts.tv_nsec);
				if (ETIMEDOUT == errno) {
					result = OSAL_TIMEOUT;
				} else {
					result = OSAL_ERROR;
				}
			}
		}
	}

	return result;
}

/**
 * @brief Give operation on OS counter semaphore. Increase the counter semaphore count value by 1 and unblock the
 * current task if count value equals to 0.
 *
 * @param[in] handle pointer on the counter semaphore handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_counter_semaphore_give(OSAL_counter_semaphore_handle_t *handle) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (-1 != sem_post(handle)) {
			result = OSAL_OK;
		}
	}

	return result;
}

/**
 * @brief Create an OS binary semaphore with a semaphore count initial value (0 or 1).
 *
 * @param[in] name counter semaphore name
 * @param[in] initial_count counter semaphore initial count value
 * @param[in,out] handle pointer on a binary semaphore handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_binary_semaphore_create(uint8_t *name, uint32_t initial_count,
                                           OSAL_binary_semaphore_handle_t *handle) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (-1 != sem_init(handle, 0, (0 == initial_count) ? 0 : 1)) {
			result = OSAL_OK;
		}
	}

	return result;
}

/**
 * @brief Delete an OS binary semaphore.
 *
 * @param[in] handle pointer on the binary semaphore handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_binary_semaphore_delete(OSAL_binary_semaphore_handle_t *handle) {
	return OSAL_counter_semaphore_delete(handle);
}

/**
 * @brief Take operation on OS binary semaphore. Block the current task until binary semaphore
 * become available or timeout occurred. Decrease the binary semaphore count value by 1 and
 * block the current task if count value equals to 0.
 *
 * @param[in] handle pointer on the binary semaphore handle
 * @param[in] timeout maximum time to wait until the binary semaphore become available
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_binary_semaphore_take(OSAL_binary_semaphore_handle_t *handle, uint32_t timeout) {
	return OSAL_counter_semaphore_take(handle, timeout);
}

/**
 * @brief Give operation on OS binary semaphore. Increase the binary semaphore count value by 1 and unblock the current
 * task if count value.
 * equals to 0.
 *
 * @param[in] handle pointer on the binary semaphore handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_binary_semaphore_give(OSAL_binary_semaphore_handle_t *handle) {
	return OSAL_counter_semaphore_give(handle);
}

/**
 * @brief Create an OS mutex.
 *
 * @param[in] name mutex name
 * @param[in,out] handle pointer on a mutex handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_mutex_create(uint8_t *name, OSAL_mutex_handle_t *handle) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (0 == pthread_mutex_init(handle, NULL)) {
			result = OSAL_OK;
		}
	}

	return result;
}

/**
 * @brief Delete an OS mutex.
 *
 * @param[in] handle pointer on the mutex handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_mutex_delete(OSAL_mutex_handle_t *handle) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (0 == pthread_mutex_destroy(handle)) {
			result = OSAL_OK;
		}
	}

	return result;
}

/**
 * @brief Take operation on OS mutex.
 *
 * @param[in] handle pointer on the mutex handle
 * @param[in] timeout maximum time to wait until the mutex become available
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_mutex_take(OSAL_mutex_handle_t *handle, uint32_t timeout) {
	OSAL_status_t result = OSAL_ERROR;
	struct timespec ts;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (-1 != timeout) {
			if (-1 != clock_gettime(CLOCK_REALTIME, &ts)) {
				ts.tv_nsec += timeout * 1000 * 1000;
				if (0 == pthread_mutex_timedlock(handle, &ts)) {
					result = OSAL_OK;
				}
			}
		} else {
			// Infinite timeout
			if (0 == pthread_mutex_lock(handle)) {
				result = OSAL_OK;
			}
		}
	}

	return result;
}

/**
 * @brief Give operation on OS mutex.
 *
 * @param[in] handle pointer on the mutex handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_mutex_give(OSAL_mutex_handle_t *handle) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == handle) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (0 == pthread_mutex_unlock(handle)) {
			result = OSAL_OK;
		}
	}

	return result;
}

/**
 * @brief Disable the OS scheduler context switching. Prevent the OS from
 * scheduling the current thread calling #OSAL_disable_context_switching while
 * the OS scheduling is already disable has an undefined behavior. This method
 * may be called from an interrupt.
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_disable_context_switching(void) {
	// TODO
	return OSAL_OK;
}

/**
 * @brief Reenable the OS scheduling that was disabled by #OSAL_disable_context_switching.
 * This method may be called from an interrupt.
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_enable_context_switching(void) {
	// TODO
	return OSAL_OK;
}

/**
 * @brief Asleep the current task during specified number of milliseconds.
 *
 * @param[in] milliseconds number of milliseconds
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_sleep(uint32_t milliseconds) {
	OSAL_status_t result = OSAL_ERROR;
	struct timespec time_to_wait;

	if (OSAL_OK == OSAL_milliseconds_to_posix_time(&time_to_wait, milliseconds)) {
		if (0 == nanosleep(&time_to_wait, NULL)) {
			result = OSAL_OK;
		}
	}

	return result;
}

static OSAL_status_t OSAL_posix_current_time(struct timespec *time) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == time) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (-1 != clock_gettime(CLOCK_REALTIME, time)) {
			result = OSAL_OK;
		}
	}

	return result;
}

static OSAL_status_t OSAL_posix_time_add(struct timespec t1, struct timespec t2, struct timespec *time) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == time) {
		result = OSAL_WRONG_ARGS;
	} else {
		long sec = t2.tv_sec + t1.tv_sec;
		long nsec = t2.tv_nsec + t1.tv_nsec;
		if (nsec >= NANOSECONDS_IN_SECONDS) {
			nsec -= NANOSECONDS_IN_SECONDS;
			sec++;
		}

		time->tv_sec = sec;
		time->tv_nsec = nsec;
		result = OSAL_OK;
	}

	return result;
}

static OSAL_status_t OSAL_milliseconds_to_posix_time(struct timespec *time, uint32_t ms) {
	OSAL_status_t result = OSAL_ERROR;

	if (NULL == time) {
		result = OSAL_WRONG_ARGS;
	} else {
		time->tv_sec = ms / MILLISECONDS_IN_SECONDS;
		time->tv_nsec = (ms % MILLISECONDS_IN_SECONDS) * NANOSECONDS_IN_MILLISECONDS;
		result = OSAL_OK;
	}

	return result;
}

static OSAL_status_t OSAL_add_milliseconds_to_posix_current_time(uint32_t ms, struct timespec *time) {
	struct timespec current_posix_time;
	struct timespec timeout_to_posix_time;

	OSAL_status_t result = OSAL_ERROR;

	if (NULL == time) {
		result = OSAL_WRONG_ARGS;
	} else {
		if (OSAL_OK == OSAL_posix_current_time(&current_posix_time) &&
		    (OSAL_OK == OSAL_milliseconds_to_posix_time(&timeout_to_posix_time, ms))) {
			if (OSAL_OK == OSAL_posix_time_add(current_posix_time, timeout_to_posix_time, time)) {
				result = OSAL_OK;
			}
		}
	}

	return result;
}
