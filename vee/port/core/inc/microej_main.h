/*
 * C
 *
 *  Copyright 2020-2024 MicroEJ Corp. All rights reserved.
 *  Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

/**
 * @file
 * @brief MicroEJ startup.
 * @author MicroEJ Developer Team
 * @version 3.0.0
 * @date 7 December 2023
 */

#ifndef MICROEJ_MAIN_H_
#define MICROEJ_MAIN_H_

#ifdef __cplusplus
    extern "C" {
#endif

/**
 * @brief Creates and starts a MicroEJ instance. This function returns when the MicroEJ execution ends.
 * @param argc arguments count
 * @param argv arguments vector
 * @param app_exit_code_ptr pointer where this function stores the application exit code or 0 in case of error in the MicroEJ Core Engine. May be null.
 * @return the MicroEJ Core Engine error code in case of error, or 0 if the execution ends without error.
 */
int microej_main(int argc, char **argv, int* app_exit_code_ptr);

#ifdef __cplusplus
    }
#endif

#endif /* MICROEJ_MAIN_H_ */
