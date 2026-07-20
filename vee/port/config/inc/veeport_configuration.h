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
