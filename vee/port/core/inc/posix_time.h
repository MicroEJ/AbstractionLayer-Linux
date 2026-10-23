/*
 * C
 *
 * Copyright 2013-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef POSIX_TIME_H
#define POSIX_TIME_H

/**
 * @file
 * @brief POSIX time API.
 * @author MicroEJ Developer Team
 * @version 1.1.1
 * @date 5 June 2024
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int64_t posix_time_getcurrenttime(uint8_t is_platform_time);
int64_t posix_time_gettimenanos(void);
/**
 * @brief Sets the application time.
 *
 * @param[in] t the application time to set, in milliseconds since midnight, January 1, 1970 UTC.
 *
 * @return 0 on success, otherwise the <code>errno</code> the underlying call failed with. Setting the clock is a
 * privileged operation, so a port running unprivileged gets <code>EPERM</code> here on every call.
 */
int32_t posix_time_setapplicationtime(int64_t t);
int64_t posix_time_getrealtimefrommonotonictime(int64_t monotonic);

#ifdef __cplusplus
}
#endif

#endif // POSIX_TIME_H
