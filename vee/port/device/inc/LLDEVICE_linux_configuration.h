/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

#ifndef LLDEVICE_LINUX_CONFIGURATION_H
#define LLDEVICE_LINUX_CONFIGURATION_H

/**
 * @file
 * @brief LLDEVICE API port for Linux configuration.
 * @author MicroEJ Developer Team
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The platform architecture name.
 */
#ifndef LLDEVICE_ARCHITECTURE
#define LLDEVICE_ARCHITECTURE   "Linux"
#endif

/**
 * @brief The device tree file that holds the serial number.
 */
#ifndef LLDEVICE_SERIAL_NUMBER_FILE
#define LLDEVICE_SERIAL_NUMBER_FILE   "/proc/device-tree/serial-number"
#endif

/**
 * @brief The file that holds the machine ID.
 */
#ifndef LLDEVICE_MACHINE_ID_FILE
#define LLDEVICE_MACHINE_ID_FILE   "/etc/machine-id"
#endif

#ifdef __cplusplus
}
#endif

#endif // LLDEVICE_LINUX_CONFIGURATION_H
