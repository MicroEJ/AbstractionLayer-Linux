/*
 * C
 *
 * Copyright 2018-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef OSAL_PORTMACRO_H
#define OSAL_PORTMACRO_H

/**
 * @file
 * @brief OS Abstraction Layer POSIX port macro
 * @author MicroEJ Developer Team
 * @version 1.1.0
 * @date 6 July 2022
 */
#include <stdint.h>
#include <pthread.h>
#include <semaphore.h>

/** @brief Custom OS type definitions */
#define OSAL_CUSTOM_TYPEDEF

/** @brief task function entry point */
typedef void *(*OSAL_task_entry_point_t)(void *);

/** @brief OS task handle */
typedef pthread_t OSAL_task_handle_t;

/** @brief OS queue handle */
typedef struct {
	pthread_cond_t condition;
	pthread_mutex_t mutex;
	uint8_t *name;
	int32_t size;
	void *message_queue;
	int32_t first_message_index; // Index of the first message (for reading)
	int32_t last_message_index; // Index of the last message (for writing)
	int32_t count;
} OSAL_queue_handle_t;

/** @brief OS counter semaphore handle */
typedef sem_t OSAL_counter_semaphore_handle_t;

/** @brief OS binary semaphore handle */
typedef sem_t OSAL_binary_semaphore_handle_t;

/** @brief OS mutex handle */
typedef pthread_mutex_t OSAL_mutex_handle_t;

/** @brief OS task stack */
typedef int32_t OSAL_task_stack_t;

/** @brief OS queue */
typedef struct _OSAL_queue_t {
	int32_t size;
	void *addr;
} OSAL_queue_t;

/*
 * @brief Declare a task stack.
 *
 * @param[in] _name name of the variable that defines the stack.
 * @param[in] _size size of the stack in bytes. _size must be compile time constant value.
 */
#define OSAL_task_stack_declare(_name, _size) OSAL_task_stack_t _name = _size

/*
 * @brief Declare a queue.
 *
 * @param[in] _name name of the variable that defines the queue address.
 * @param[in] _size number of items that can be stored in the queue. _size must be compile time constant value.
 */
#define OSAL_queue_declare(_name, _size) void *_name ## _buffer[_size]; \
		OSAL_queue_t _name = { .size = _size, .addr = _name ## _buffer }

#endif // OSAL_PORTMACRO_H
