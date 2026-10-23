/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief Critical section of VEE Port Essentials, mapped onto a mutex.
 * @author MicroEJ Developer Team
 */

#include <pthread.h>

#include "veeport_configuration.h"
#include "veeport_logger.h"

VEEPORT_LOGGER_DEFINE_MODULE("veeport_critical_section", VEEPORT_LOGGER_LEVEL_WRN)

/**
 * @brief The mutex behind the critical section.
 *
 * @details The section of the error helpers spans a call to SNI_throwNativeException(), so it must be
 * a lock a thread can hold across that call. A mutex is one. Masking the signals or the scheduler is
 * not.
 */
static pthread_mutex_t critical_section_mutex = PTHREAD_MUTEX_INITIALIZER;

void VEEPORT_CRITICAL_SECTION_enter(void) {
	int32_t status = pthread_mutex_lock(&critical_section_mutex);
	if (0 != status) {
		VEEPORT_LOGGER_LOG_ERR("pthread_mutex_lock failed (%d)", status);
	}
}

void VEEPORT_CRITICAL_SECTION_exit(void) {
	int32_t status = pthread_mutex_unlock(&critical_section_mutex);
	if (0 != status) {
		VEEPORT_LOGGER_LOG_ERR("pthread_mutex_unlock failed (%d)", status);
	}
}
