/*
 * C
 *
 * Copyright 2018-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef OSAL_PORTMACRO_H
#define OSAL_PORTMACRO_H

/**
 * @file
 * @brief OS Abstraction Layer POSIX port macro
 * @author MicroEJ Developer Team
 * @version 0.1.0
 * @date 11 April 2018
 */
#include <stdint.h>

/** @brief OS task stack */
typedef int32_t OSAL_task_stack_t;

/*
 * @brief Declare a task stack.
 *
 * @param[in] _name name of the variable that defines the stack.
 * @param[in] _size size of the stack in bytes. _size must be compile time constant value.
 */
#define OSAL_task_stack_declare(_name, _size) OSAL_task_stack_t _name = _size


#endif // OSAL_PORTMACRO_H
