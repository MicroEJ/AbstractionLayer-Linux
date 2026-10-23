/**
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 **/
/**
 * @file veeport_configuration.h
 *
 * @brief Configures the C modules integrated for this port of MICROEJ VEE.
 *
 * This header file contains all the custom C modules configurations of the VEE Port.
 * Use this file to override the C module configurations in the VEE Port.
 * Please refer to the C module configuration files to learn about the available configurations.
 * This file should also be used to define VEE Port specific configurations.
 *
 * ***** HOW TO INTEGRATE THIS FILE WITH C MODULES *****
 *
 * This section explains how to integrate this file with C module configuration files.
 *
 * The configuration file of each C module (i.e. '[C MODULE NAME]_configuration.h') should include this
 * file as followed:
 *
 *  // Include VEE Port User configuration file
 *  #if defined __has_include
 *  	#if __has_include("veeport_configuration.h")
 *  		#include "veeport_configuration.h"
 *  	#endif // __has_include("veeport_configuration.h")
 *  #else
 *  // Ensure 'veeport_configuration.h' exists in your project for custom configurations.
 *  	#include "veeport_configuration.h"
 *  #endif // defined __has_include
 *
 * Then, in the '[C MODULE NAME]_configuration.h' file, default values for each parameter should be provided
 * as followed:
 *
 * #ifndef MY_CONFIGURATION
 * #define MY_CONFIGURATION (MY_CONFIGURATION_DEFAULT_VALUE)
 * #endif
 *
 */

#ifndef VEEPORT_CONFIGURATION_H
#define VEEPORT_CONFIGURATION_H

#ifdef __cplusplus
extern "C" {
#endif

// ----------------------------------------------------------------------------
// Includes
// ----------------------------------------------------------------------------

// ############################################################################
//                        VEE Port Logger Configuration
// ############################################################################

/**
 * @brief Adds the function name and the line number to every message.
 *
 * The abstraction layer logs need to print the function name, especially on entry and exit.
 * Turning this feature off makes them unreadable.
 */
#define VEEPORT_LOGGER_VERBOSE (1)

/**
 * @brief Log level of each abstraction layer.
 *
 * Each layer declares its own default in its configuration header. Uncomment a line below to
 * override it with one of VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF or _DBG.
 */
//#define LLAUDIO_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLCRYPTO_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLDISPLAY_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLDISPLAY_MINIFB_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLECOM_NETWORK_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLEVENT_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLFS_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLKERNEL_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLMJVM_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLNET_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLNET_SSL_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLRIO_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLSERIAL_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define LLTOUCH_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)
//#define OSAL_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_DBG)

/**
 * @brief Prevent truncation of log messages.
 *
 */
#define VEEPORT_LOGGER_MSG_SIZE (1024)

// ############################################################################
//                   VEE Port Essentials Critical Section
// ############################################################################

/**
 * @brief Enters the critical section that protects the shared state of VEE Port Essentials.
 *
 * The error helpers format their message in one shared buffer, and the abstraction layers log and
 * throw from the VM thread and from their worker threads. Both functions map the section onto a
 * mutex of the C library, see veeport_critical_section.c.
 */
void VEEPORT_CRITICAL_SECTION_enter(void);

/**
 * @brief Leaves the critical section entered by VEEPORT_CRITICAL_SECTION_enter().
 */
void VEEPORT_CRITICAL_SECTION_exit(void);

#define VEEPORT_ENTER_CRITICAL() VEEPORT_CRITICAL_SECTION_enter()
#define VEEPORT_EXIT_CRITICAL()  VEEPORT_CRITICAL_SECTION_exit()

// ############################################################################
//                        Core Engine Configuration
// ############################################################################

// Example of a Core Engine configuration,
//
// /**
//  * @brief Sets this define to 1 to run the memory and Coremark benchmarks, disabled by default.
//  */
// #define MICROEJ_CORE_VALIDATION (0)

// Uncomment the following to run core tests.
//#define MICROEJ_CORE_VEE_MOCK_VALIDATION (1)

// ############################################################################
//                        KF Configuration
// ############################################################################

// ############################################################################
//                        Event Queue Configuration
// ############################################################################

// ############################################################################
//                        FS Configuration
// ############################################################################

// ############################################################################
//                        NET Configuration
// ############################################################################

// ############################################################################
//                        UI Configuration
// ############################################################################

// Enable the MicroUI events logger (LLUI_INPUT_dump()).
#define UI_FEATURE_EVENT_DECODER (1)

// Use the "single" buffer refresh strategy (one MCU buffer, one display-side buffer).
#define UI_FEATURE_BRS (UI_FEATURE_BRS_SINGLE)

// One drawing buffer.
#define UI_FEATURE_BRS_DRAWING_BUFFER_COUNT (1u)

// Flush a single rectangle that encapsulates all dirty regions.
#define UI_FEATURE_BRS_FLUSH_SINGLE_RECTANGLE (1)

// ############################################################################
//                        VG Configuration
// ############################################################################

// ----------------------------------------------------------------------------
// End
// ----------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif // VEEPORT_CONFIGURATION_H
