/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#ifndef POSIX_TIMER_H
#define POSIX_TIMER_H

/**
 * @file
 * @brief POSIX timer API.
 * @author MicroEJ Developer Team
 * @version 1.1.1
 * @date 5 June 2024
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initializes the mutex and the condition of the timer.
 *
 * @return 0 on success, else the error number of the pthread function that failed.
 */
int32_t posix_timer_initialize(void);
void * posix_timer_run(void *args);
void posix_timer_schedule_timer(int64_t schedule_time_ms);
void posix_timer_stop(void);
void posix_timer_dispose(void);
void posix_timer_settimerexpiredhandler(void (*handler) (void));
void posix_timer_reset(void);

#ifdef __cplusplus
}
#endif

#endif // POSIX_TIMER_H
