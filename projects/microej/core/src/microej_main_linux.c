/*
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief Linux MicroEJ main function.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 * @date 26 June 2023
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "microej_main.h"
#include "sighandler.h"
#ifdef LLKERNEL_VALIDATION
#include "t_llkernel_main.h"
#endif

#ifdef __cplusplus
	extern "C" {
#endif


/*
 * Generic Linux MicroEJ main function
 */
int main(int argc, char** argv){
	int app_exit_code = 0;
	int res;

	/* P0326IMX93EVK-16 workaround until we get a fix for M0090IDE-4679
       MEJ Application logs are not flushed instantly in the SDK console */
	if (setvbuf(stdout, NULL, _IONBF, 0) != 0){
		printf("setvbuf error: (err = %s).\n", strerror(errno));
	}

#ifdef LLKERNEL_VALIDATION
	/* Start the LLkernel tests */
	T_LLKERNEL_main();
	return 0;
#else

	microej_segfault_handler_init();
	microej_usr1_signal_handler_init();
	res = microej_main(argc-1, ++argv, &app_exit_code);
	if(res == 0){
		res = app_exit_code;
	}
	return res;
#endif
}

#ifdef __cplusplus
	}
#endif
