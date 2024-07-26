/*
 * C
 *
 * Copyright 2020-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

#ifndef  FS_HELPER_POSIX_CONFIGURATION_H
#define  FS_HELPER_POSIX_CONFIGURATION_H

/**
 * @file
 * @brief LLFS configuration.
 * @author MicroEJ Developer Team
 * @version 3.0.3
 * @date 21 July 2023
 */

#ifdef __cplusplus
	extern "C" {
#endif

/**
 * @brief Compatibility sanity check value.
 * This define value is checked in the implementation to validate that the version of this configuration
 * is compatible with the implementation.
 *
 * This value must not be changed by the user of the CCO.
 * This value must be incremented by the implementor of the CCO when a configuration define is added, deleted or modified.
 */
#define FS_HELPER_POSIX_CONFIGURATION_H_VERSION (1)


/**
 * @brief Enable or disable the buffering mode for fread/fwrite operations.
 * Set to 0 to disable the buffering mode. Keep the value to 1 for full buffering.
 */
#define FS_BUFFERING_ENABLED (1)

/**
 * @brief Define the IO Buffer Size when FS_BUFFERING_ENABLED is enabled (equal to 1).
 * The value of this buffer is platform dependent and need to be adjusted to get optimal performance.
 * Theoretically the bigger the buffer is, the better are the performances.
 */
#if defined(__QNXNTO__)
	#define FS_BUFFER_SIZE (16 * 1024)
#else
	#define FS_BUFFER_SIZE (1024)
#endif


#ifdef __cplusplus
	}
#endif

#endif // FS_HELPER_POSIX_CONFIGURATION_H
