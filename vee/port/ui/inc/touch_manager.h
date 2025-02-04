/*
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef _TOUCH_MANAGER
#define _TOUCH_MANAGER

/* Includes ------------------------------------------------------------------*/

#include <stdint.h>

/* API -----------------------------------------------------------------------*/

void TOUCH_MANAGER_initialize(void);
void* TOUCH_MANAGER_work(void* p_args);

#endif // _TOUCH_MANAGER
