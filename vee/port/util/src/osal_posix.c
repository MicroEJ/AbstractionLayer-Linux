/*
 * C
 *
 * Copyright 2017-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief OS Abstraction Layer empty implementation
 * @author MicroEJ Developer Team
 * @version 0.1.0
 * @date 11 April 2018
 */

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
//#include <unistd.h>
//#include <mqueue.h>
//#include <fcntl.h>
#include <semaphore.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "osal.h"

typedef struct
{
	pthread_cond_t  condition;
	pthread_mutex_t mutex;
	int value;
} osal_binary_semaphore_t;

typedef struct osal_linked_list_node {
	void* data;
	struct osal_linked_list_node* next;
} osal_linked_list_node_t;

typedef struct {
	int32_t size;
	osal_linked_list_node_t* node;
} osal_linked_list_t;

typedef struct
{
	pthread_cond_t  condition;
	pthread_mutex_t mutex;
	uint8_t* name;
	int32_t size;
	osal_linked_list_t waiting_msg;
} osal_queue_t;


static OSAL_status_t OSAL_linked_list_initialize(osal_linked_list_t* linked_list);
static OSAL_status_t OSAL_linked_list_add(osal_linked_list_t* linked_list, void* data);
static OSAL_status_t OSAL_linked_list_get(osal_linked_list_t* linked_list, void** data);
static OSAL_status_t OSAL_linked_list_size(osal_linked_list_t* linked_list, int32_t* size);

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
OSAL_status_t OSAL_task_create(OSAL_task_entry_point_t entry_point, uint8_t* name, OSAL_task_stack_t stack, int32_t priority, void* parameters, OSAL_task_handle_t* handle)
{
	OSAL_status_t result = OSAL_ERROR;
	int32_t pthread_result = 0;
	pthread_attr_t attr;

	int32_t stack_size = (int)stack;

    if(NULL == handle)
    {
    	result = OSAL_WRONG_ARGS;
    }
    else{
		pthread_result = pthread_attr_init(&attr);
		if(0 == pthread_result)
		{
			if (stack_size > 0)
			{
				pthread_attr_setstacksize(&attr, stack_size);
			}

			int32_t create_result = pthread_create((pthread_t*)handle, &attr, entry_point, parameters);
			if(0 == create_result)
			{
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
OSAL_status_t OSAL_task_delete(OSAL_task_handle_t* handle)
{
	// nothing to do
	return OSAL_OK;
}

/**
 * @brief Create an OS queue with a predefined queue size.
 *
 * @param[in,out] handle pointer on a queue handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_queue_create(uint8_t* name, uint32_t size, OSAL_queue_handle_t* handle)
{
//	OSAL_status_t result = OSAL_ERROR;
//	mqd_t queue_open_result;
//	struct mq_attr attr;
//	int32_t errno_val = 0;
//
//	if(NULL == handle)
//	{
//		result = OSAL_WRONG_ARGS;
//	}
//	else{
//		do {
//			queue_open_result = mq_open((const char *)name, O_RDWR | O_CREAT);
//			errno_val = errno;
//			if(EACCES == errno_val)
//			{
//				if(-1 == mq_unlink((const char *)name))
//				{
//					printf("[ERROR] %d\n", errno_val);
//				} else {
//					printf("[INFO] unlink success\n");
//				}
//			} else {
//				printf("[ERROR] %d\n", errno_val);
//			}
//		} while(-1 == queue_open_result);
//
//		if(-1 != queue_open_result)
//		{
//			*handle = (OSAL_queue_handle_t)queue_open_result;
//
//			attr.mq_maxmsg = size;
//			attr.mq_msgsize = sizeof(void*);
//			attr.mq_flags = 0;
//
//			if(-1 != mq_setattr(queue_open_result, &attr, NULL)){
//				result = OSAL_OK;
//			}
//		} else {
////			printf("[ERROR] %s\n", strerror(errno));
//			printf("[ERROR] %d\n", errno);
//		}
//	}
//
//	return result;

	OSAL_status_t result = OSAL_ERROR;
	int32_t errnum;

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		osal_queue_t * queue_tmp = malloc(sizeof(osal_queue_t));
		if(NULL == queue_tmp)
		{
			errnum = errno;
			if(ENOMEM == errnum){
				printf("[ERROR] OSAL queue memory allocation failed\n");
				result = OSAL_NOMEM;
			}
		} else {
			uint8_t* name_local = malloc(strlen((const char*)name) +1);
			if(NULL == name_local) {
				errnum = errno;
				if(ENOMEM == errnum){
					printf("[ERROR] OSAL queue name memory allocation failed\n");
					free(queue_tmp);
					result = OSAL_NOMEM;
				}
			} else {
				strcpy((char*)name_local, (const char*)name);
				queue_tmp->name = name_local;
				queue_tmp->size = size;
				result = OSAL_linked_list_initialize(&(queue_tmp->waiting_msg));

				if((result == OSAL_OK) && (0 == pthread_mutex_init((pthread_mutex_t *)&(queue_tmp->mutex), NULL)))
				{
					result = OSAL_OK;
				}

				if((result == OSAL_OK) && (0 != pthread_cond_init((pthread_cond_t *)&(queue_tmp->condition), NULL)))
				{
					result = OSAL_ERROR;
				} else {
					*handle = (OSAL_queue_handle_t)queue_tmp;
				}
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
OSAL_status_t OSAL_queue_delete(OSAL_queue_handle_t* handle)
{
//	OSAL_status_t result = OSAL_ERROR;
//
//	if(NULL == handle)
//	{
//		result = OSAL_WRONG_ARGS;
//	}
//	else{
//		if(-1 != mq_close((mqd_t)*handle))
//		{
//			// TODO unlink the queue to free it (need the queue name)
////			if(-1 != mq_unlink((const char *)QUEUE_NAME){}
//
//			return OSAL_OK;
//		}
//	}

	OSAL_status_t result = OSAL_ERROR;

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		// free queue mutex and condition
		if(0 == pthread_mutex_destroy(&((osal_queue_t *)*handle)->mutex))
		{
			result = OSAL_OK;
		}

		if((result == OSAL_OK) && (0 != pthread_cond_destroy(&((osal_queue_t *)*handle)->condition)))
		{
			result = OSAL_ERROR;
		}

		// free the queue linked list
		if(result == OSAL_OK)
		{
			osal_linked_list_node_t *linked_list_node_tmp_current = (((osal_queue_t *)*handle)->waiting_msg).node;
			osal_linked_list_node_t *linked_list_node_tmp_next = NULL;
			while(NULL != linked_list_node_tmp_current)
			{
				linked_list_node_tmp_next = linked_list_node_tmp_current->next;
				free(linked_list_node_tmp_current);
				linked_list_node_tmp_current = linked_list_node_tmp_next;
			}
		}

		free(((osal_queue_t *)*handle)->name);
		free(((osal_queue_t *)*handle));
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
OSAL_status_t OSAL_queue_post(OSAL_queue_handle_t* handle, void* msg)
{
//	OSAL_status_t result = OSAL_ERROR;
//
//	if(NULL == handle)
//	{
//		result = OSAL_WRONG_ARGS;
//	}
//	else{
//		if(-1 != mq_send((mqd_t)*handle, msg, sizeof(msg), 0))
//		{
//			result = OSAL_OK;
//		}
//	}
//	return result;

	OSAL_status_t result = OSAL_ERROR;

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		osal_queue_t * queue_tmp = (osal_queue_t *)*handle;
		pthread_mutex_lock(&((queue_tmp->mutex)));

		result = OSAL_linked_list_add(&(queue_tmp->waiting_msg), msg);

		pthread_cond_signal(&(queue_tmp->condition));
		pthread_mutex_unlock(&(queue_tmp->mutex));
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
OSAL_status_t OSAL_queue_fetch(OSAL_queue_handle_t* handle, void** msg, uint32_t timeout)
{
//	OSAL_status_t result = OSAL_ERROR;
//
//	if((NULL == handle) || (NULL == msg))
//	{
//		result = OSAL_WRONG_ARGS;
//	}
//	else{
//		if(-1 != mq_receive((mqd_t)*handle, (char *)msg, sizeof(msg), NULL))
//		{
//			result = OSAL_OK;
//		}
//	}
//	return result;


	OSAL_status_t result = OSAL_ERROR;

	if((NULL == handle) || (NULL == msg))
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		osal_queue_t * queue_tmp = (osal_queue_t *)*handle;
		pthread_mutex_lock(&(queue_tmp->mutex));
		int32_t queue_size = 0;

		result = OSAL_linked_list_size(&queue_tmp->waiting_msg, &queue_size);
		if((OSAL_OK == result) && (queue_size > 0))
		{
			result = OSAL_linked_list_get(&queue_tmp->waiting_msg, msg);
			if(NULL == msg)
			{
				printf("[ERROR]\n");
			}
		}
		else
		{
			struct timespec absolute_time_result;

			if (OSAL_OK == OSAL_add_milliseconds_to_posix_current_time(timeout, &absolute_time_result))
			{
				int32_t cond_wait_result = 0;
				if (0 == (cond_wait_result = pthread_cond_timedwait(&(queue_tmp->condition), &(queue_tmp->mutex), &absolute_time_result)))
				{
					result = OSAL_linked_list_size(&queue_tmp->waiting_msg, &queue_size);
					if((OSAL_OK == result) && (queue_size > 0))
					{
						result = OSAL_linked_list_get(&queue_tmp->waiting_msg, msg);
						result = OSAL_OK;
					}
				}
			}
		}
		pthread_mutex_unlock(&(queue_tmp->mutex));
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
OSAL_status_t OSAL_counter_semaphore_create(uint8_t* name, uint32_t initial_count, uint32_t max_count, OSAL_counter_semaphore_handle_t* handle)
{
	OSAL_status_t result = OSAL_ERROR;
	sem_t* mutex_sem = malloc(sizeof(sem_t));

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		if (-1 != sem_init(mutex_sem, 0, initial_count))
		{
			*handle = mutex_sem;
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
OSAL_status_t OSAL_counter_semaphore_delete(OSAL_counter_semaphore_handle_t* handle)
{
	OSAL_status_t result = OSAL_ERROR;

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		if(-1 != sem_destroy(*handle))
		{
			result = OSAL_OK;
		}
		free(*handle);
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
OSAL_status_t OSAL_counter_semaphore_take(OSAL_counter_semaphore_handle_t* handle, uint32_t timeout)
{
	OSAL_status_t result = OSAL_ERROR;
	struct timespec ts;

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		if (-1 != clock_gettime(CLOCK_REALTIME, &ts))
		{
			ts.tv_nsec += timeout * 1000 * 1000;
			if (-1 != sem_timedwait(*handle, &ts))
			{
				result = OSAL_OK;
			}
		}
	}
	return result;
}

/**
 * @brief Give operation on OS counter semaphore. Increase the counter semaphore count value by 1 and unblock the current task if count value.
 * equals to 0.
 *
 * @param[in] handle pointer on the counter semaphore handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_counter_semaphore_give(OSAL_counter_semaphore_handle_t* handle)
{
	OSAL_status_t result = OSAL_ERROR;

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		if (-1 != sem_post(*handle))
		{
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
OSAL_status_t OSAL_binary_semaphore_create(uint8_t* name, uint32_t initial_count, OSAL_binary_semaphore_handle_t* handle)
{
	OSAL_status_t result = OSAL_ERROR;
	sem_t* mutex_sem = malloc(sizeof(sem_t));

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		if (-1 != sem_init(mutex_sem, 0, (0 == initial_count) ? 0 : 1))
		{
			*handle = mutex_sem;
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
OSAL_status_t OSAL_binary_semaphore_delete(OSAL_binary_semaphore_handle_t* handle)
{
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
OSAL_status_t OSAL_binary_semaphore_take(OSAL_binary_semaphore_handle_t* handle, uint32_t timeout)
{
	return OSAL_counter_semaphore_take(handle, timeout);
}

/**
 * @brief Give operation on OS binary semaphore. Increase the binary semaphore count value by 1 and unblock the current task if count value.
 * equals to 0.
 *
 * @param[in] handle pointer on the binary semaphore handle
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_binary_semaphore_give(OSAL_binary_semaphore_handle_t* handle)
{
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
OSAL_status_t OSAL_mutex_create(uint8_t* name, OSAL_mutex_handle_t* handle)
{
	OSAL_status_t result = OSAL_ERROR;
	pthread_mutex_t* mutex = malloc(sizeof(pthread_mutex_t));

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		if(0 == pthread_mutex_init(mutex, NULL))
		{
			*handle = mutex;
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
OSAL_status_t OSAL_mutex_delete(OSAL_mutex_handle_t* handle)
{
	OSAL_status_t result = OSAL_ERROR;

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		pthread_mutex_t * pthread_mutex = (pthread_mutex_t *)*handle;
		if(0 == pthread_mutex_destroy(pthread_mutex))
		{
			result = OSAL_OK;
		}
		free(*handle);
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
OSAL_status_t OSAL_mutex_take(OSAL_mutex_handle_t* handle, uint32_t timeout)
{
	OSAL_status_t result = OSAL_ERROR;
	struct timespec ts;

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		pthread_mutex_t * pthread_mutex = (pthread_mutex_t *)*handle;
		if(-1 != timeout){
			if (-1 != clock_gettime(CLOCK_REALTIME, &ts))
			{
				ts.tv_nsec += timeout * 1000 * 1000;
				if(0 == pthread_mutex_timedlock(pthread_mutex, &ts))
				{
					result = OSAL_OK;
				}
			}
		}
		else {
			// Infinite timeout
			if(0 == pthread_mutex_lock(pthread_mutex))
			{
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
OSAL_status_t OSAL_mutex_give(OSAL_mutex_handle_t* handle)
{
	OSAL_status_t result = OSAL_ERROR;

	if(NULL == handle)
	{
		result = OSAL_WRONG_ARGS;
	}
	else{
		pthread_mutex_t * pthread_mutex = (pthread_mutex_t *)*handle;
		if(0 == pthread_mutex_unlock(pthread_mutex))
		{
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
OSAL_status_t OSAL_disable_context_switching(void)
{
	// TODO
	return OSAL_OK;
}

/**
 * @brief Reenable the OS scheduling that was disabled by #OSAL_disable_context_switching.
 * This method may be called from an interrupt.
 *
 * @return operation status (@see OSAL_status_t)
 */
OSAL_status_t OSAL_enable_context_switching(void)
{
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
OSAL_status_t OSAL_sleep(uint32_t milliseconds)
{
	OSAL_status_t result = OSAL_ERROR;
	struct timespec time_to_wait;

	if(OSAL_OK == OSAL_milliseconds_to_posix_time(&time_to_wait, milliseconds))
	{
		if(0 == nanosleep(&time_to_wait, NULL))
		{
			result = OSAL_OK;
		}
	}

	return result;
}

static OSAL_status_t OSAL_linked_list_initialize(osal_linked_list_t* linked_list)
{
	OSAL_status_t result = OSAL_ERROR;

	if(NULL == linked_list)
	{
		result = OSAL_WRONG_ARGS;
	} else {
		linked_list->size = 0;
		linked_list->node = NULL;
		result = OSAL_OK;
	}

	return result;
}

static OSAL_status_t OSAL_linked_list_add(osal_linked_list_t* linked_list, void* data)
{
	OSAL_status_t result = OSAL_ERROR;

	if(NULL == linked_list)
	{
		result = OSAL_WRONG_ARGS;
	} else {
		osal_linked_list_node_t* linked_list_node = malloc(sizeof(osal_linked_list_node_t));
		if(NULL == linked_list_node)
		{
			int32_t errnum = errno;
			if(ENOMEM == errnum)
			{
				result = OSAL_NOMEM;
			}
			printf("[ERROR] linked list add failed (%s)\n", strerror(errnum));
		} else {
			// initialize the new linked list node
			linked_list_node->data = data;
			linked_list_node->next = NULL;

			if(NULL == linked_list->node)
			{
				linked_list->node = linked_list_node;
			} else {
				osal_linked_list_node_t* linked_list_node_tmp = linked_list->node;
				// add the new node in the linked list
				while(NULL != linked_list_node_tmp->next)
				{
					linked_list_node_tmp = linked_list_node_tmp->next;
				}
				linked_list_node_tmp->next = linked_list_node;
			}

			// new data added, increase linked list size
			++linked_list->size;

			result = OSAL_OK;
		}
	}

	return result;
}

static OSAL_status_t OSAL_linked_list_get(osal_linked_list_t* linked_list, void** data)
{
	OSAL_status_t result = OSAL_ERROR;

	if((NULL == linked_list) || (NULL == data))
	{
		result = OSAL_WRONG_ARGS;
	} else {
		osal_linked_list_node_t* linked_list_node_tmp = linked_list->node;
		if(NULL != linked_list_node_tmp)
		{
			*data = linked_list_node_tmp->data;
			linked_list->node = (linked_list->node)->next;
			free(linked_list_node_tmp);
			--linked_list->size;
			result = OSAL_OK;
		}
	}

	return result;
}

static OSAL_status_t OSAL_linked_list_size(osal_linked_list_t* linked_list, int32_t* size)
{
	OSAL_status_t result = OSAL_ERROR;

	if((NULL == linked_list) || (NULL == size))
	{
		result = OSAL_WRONG_ARGS;
	} else if (linked_list->size > 0) {
		*size = linked_list->size;
		result = OSAL_OK;
	}

	return result;
}

static OSAL_status_t OSAL_posix_current_time(struct timespec *time)
{
	OSAL_status_t result = OSAL_ERROR;

	if(NULL == time)
	{
		result = OSAL_WRONG_ARGS;
	} else {
		if (-1 != clock_gettime(CLOCK_REALTIME, time))
		{
			result = OSAL_OK;
		}
	}

	return result;
}

static OSAL_status_t OSAL_posix_time_add(struct timespec t1, struct timespec t2, struct timespec *time)
{
	OSAL_status_t result = OSAL_ERROR;

	if(NULL == time)
	{
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

static OSAL_status_t OSAL_milliseconds_to_posix_time(struct timespec *time, uint32_t ms)
{
	OSAL_status_t result = OSAL_ERROR;

	if(NULL == time)
	{
		result = OSAL_WRONG_ARGS;
	} else {
		time->tv_sec = ms / MILLISECONDS_IN_SECONDS;
		time->tv_nsec = (ms % MILLISECONDS_IN_SECONDS) * NANOSECONDS_IN_MILLISECONDS;
		result = OSAL_OK;
	}

	return result;
}

static OSAL_status_t OSAL_add_milliseconds_to_posix_current_time(uint32_t ms, struct timespec *time)
{
	struct timespec current_posix_time;
	struct timespec timeout_to_posix_time;

	OSAL_status_t result = OSAL_ERROR;

	if(NULL == time)
	{
		result = OSAL_WRONG_ARGS;
	} else {
		if (OSAL_OK == OSAL_posix_current_time(&current_posix_time) && (OSAL_OK == OSAL_milliseconds_to_posix_time(&timeout_to_posix_time, ms)))
		{
			if(OSAL_OK == OSAL_posix_time_add(current_posix_time, timeout_to_posix_time, time))
			{
				result = OSAL_OK;
			}
		}
	}

	return result;
}
