/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include "posix_time.h"
#include <errno.h>
/* cppcheck-suppress misra-c2012-21.10 ; included only for the POSIX clock API (clock_gettime, CLOCK_MONOTONIC, struct
 * timespec); no ISO C time and date function is used. */
#include <time.h>

/**
 * @file
 * @brief POSIX time implementation.
 * @author MicroEJ Developer Team
 * @version 1.1.1
 * @date 5 June 2024
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "microej.h"

/*
 *********************************************************************************************************
 *                                             DEFINES
 *********************************************************************************************************
 */

#define NANO_TO_MILLIS      1000000
#define MILLIS_TO_SECONDS   (int32_t)1000

/*
 *********************************************************************************************************
 * 	                                      PUBLIC FUNCTIONS
 *********************************************************************************************************
 */

int64_t posix_time_getcurrenttime(uint8_t is_platform_time) {
	// is_platform_time == true when ej.bon.Util.platformTimeMillis
	// is_platform_time == false when java.lang.System.currentTimeMillis
	// Posix MONOTONIC is equivalent to B-ON Platform time
	// Posix REALTIME is equivalent to B-ON Application time and Java System time

	struct timespec ts;

	if (clock_gettime(is_platform_time ? CLOCK_MONOTONIC : CLOCK_REALTIME, &ts) != 0) {
		// TODO error handling
	}
	int64_t milliseconds = ((int64_t)ts.tv_sec * MILLIS_TO_SECONDS);
	milliseconds += ((int64_t)ts.tv_nsec / NANO_TO_MILLIS);
	return milliseconds;
}

int64_t posix_time_gettimenanos(void) {
	struct timespec ts;
	// can only be called by ej.bon.Util.platformTimeNanos, so platform time (i.e. MONOTONIC)
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		// TODO error handling
	}
	int64_t nanoseconds = ((int64_t)ts.tv_sec * MILLIS_TO_SECONDS * NANO_TO_MILLIS);
	nanoseconds += (int64_t)ts.tv_nsec;
	return nanoseconds;
}

int32_t posix_time_setapplicationtime(int64_t time_millis) {
	struct timespec ts;
	int32_t error_code = 0;

	// TimeSpec represents a time as an amount of seconds + an amount of nano seconds
	int64_t tv_sec = time_millis / MILLIS_TO_SECONDS;
	int64_t tv_millisec = time_millis - (tv_sec * MILLIS_TO_SECONDS);
	int32_t tv_nanosec = (int32_t)tv_millisec * NANO_TO_MILLIS;

	ts.tv_sec = (int32_t)tv_sec;
	ts.tv_nsec = tv_nanosec;

	// can only be called by ej.bon.Util.setCurrentTimeMillis, so Java system/application time (i.e. REALTIME)
	if (clock_settime(CLOCK_REALTIME, &ts) != 0) {
		error_code = errno;
	}

	return error_code;
}

/**	Compute absolute realtime from absolute monotonic time */
int64_t posix_time_getrealtimefrommonotonictime(int64_t monotonic) {
	int64_t relative = monotonic - posix_time_getcurrenttime(MICROEJ_TRUE);
	return posix_time_getcurrenttime(MICROEJ_FALSE) + relative;
}

#ifdef __cplusplus
}
#endif
