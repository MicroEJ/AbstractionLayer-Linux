/*
 * C
 *
 * Copyright 2015-2022 MicroEJ Corp. All rights reserved.
 * This library is provided in source code for use, modification and test, subject to license terms.
 * Any modification of the source code will break MicroEJ Corp. warranties on the whole library.
 */

/* Includes ------------------------------------------------------------------*/

#ifndef LLDEVICE_IMPL
#define LLDEVICE_IMPL

/**
 * @file
 * @brief MicroEJ Device low level API
 * @author MicroEJ Developer Team
 * @version 2.1.0
 * @date 7 September 2022
 */

#include <sni.h>
#include <intern/LLDEVICE_impl.h>

#ifdef __cplusplus
	extern "C" {
#endif

/**
 * Fills the given buffer with the name of the architecture. The buffer is filled with a null-terminated string.
 * @param buffer the buffer to fill with the name of the architecture.
 * @param length the size of the buffer.
 * @return 1 on success or 0 on error.
 */
uint8_t LLDEVICE_IMPL_getArchitecture(uint8_t* buffer, int32_t length);

/**
 * Fills the given buffer with the ID of the device.
 * @param buffer the buffer to fill with the ID.
 * @param length the size of the buffer.
 * @return the number of bytes filled or 0 on error.
 */
uint32_t LLDEVICE_IMPL_getId(uint8_t* buffer, int32_t length);

/**
 * Fills the given buffer with the Version of the device as
 * a null-terminated string.
 *
 * @param buffer the buffer to fill with the Version.
 */
void LLDEVICE_IMPL_getVersion(uint8_t* buffer);

/**
 * Reboots the device.
 */
void LLDEVICE_IMPL_reboot(void);

/**
 * Shutdowns the device.
 */
void LLDEVICE_IMPL_shutdown(void);

#ifdef __cplusplus
	}
#endif

#endif

