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

#include <stdio.h>
#include "microej_main.h"
#include "LLMJVM.h"
#include "sni.h"

#ifdef __cplusplus
    extern "C" {
#endif

int microej_main(int argc, char **argv, int* app_exit_code_ptr) {
	void* vm;
	int core_engine_error_code = -1;
	int32_t app_exit_code = 0;
	// create Core Engine
	vm = SNI_createVM();

	if (vm == NULL) {
		printf("MicroEJ initialization error.\n");
	} else {
		printf("MicroEJ START\n");

		// Error codes documentation is available in LLMJVM.h
		core_engine_error_code = (int)SNI_startVM(vm, argc, argv);

		if (core_engine_error_code < 0) {
			// Error occurred
			if (core_engine_error_code == LLMJVM_E_EVAL_LIMIT) {
				printf("Evaluation limits reached.\n");
			} else {
				printf("MicroEJ execution error (err = %d).\n", (int) core_engine_error_code);
			}
		} else {
			// Core Engine execution ends normally
			app_exit_code = SNI_getExitCode(vm);
			printf("MicroEJ END (exit code = %d)\n", (int) app_exit_code);
		}

		// delete Core Engine
		SNI_destroyVM(vm);
	}

	if(app_exit_code_ptr != NULL){
		*app_exit_code_ptr = (int)app_exit_code;
	}

	return core_engine_error_code;
}

#ifdef __cplusplus
    }
#endif
