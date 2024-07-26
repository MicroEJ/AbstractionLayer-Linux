/*
 * C
 *
 * Copyright 2018-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief Linux Platform implementation specific macro.
 * @author MicroEJ Developer Team
 * @version 2.0.3
 * @date 27 November 2020
 */

#ifndef  LLNET_LINUX_CONFIGURATION_H
#define  LLNET_LINUX_CONFIGURATION_H


/**
 * @brief Compatibility sanity check value.
 * This define value is checked in the implementation to validate that the version of this configuration
 * is compatible with the implementation.
 *
 * This value must not be changed by the user of the CCO.
 * This value must be incremented by the implementor of the CCO when a configuration define is added, deleted or modified.
 */
#define LLNET_LINUX_CONFIGURATION_VERSION (1)

/**
 * Maximum length plus one for the interface name string.
 * Used in LLNET_NETWORKINTERFACE_IMPL_getVMInterfaceAddressesCount()
 */
#define IFADDRNAMEMAX (10)

#endif // LLNET_LINUX_CONFIGURATION_H
