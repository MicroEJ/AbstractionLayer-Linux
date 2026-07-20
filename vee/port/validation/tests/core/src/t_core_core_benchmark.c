/*
 * C
 *
 * Copyright 2015-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include "embUnit.h"
#include "config.h"
#include "x_core_benchmark.h"
#include "u_time_base.h"

/** Private function definitions */
static void T_CORE_COREBENCH_setUp(void) {
	UTIL_TIME_BASE_initialize();
}

static void T_CORE_COREBENCH_tearDown(void) {
}

static void T_CORE_COREBENCH_check(void) {
	TEST_ASSERT_MESSAGE(X_CORE_BENCHMARK_run(),
	                    "\nNo core benchmark can be found.\nPlease install a core benchmark in your platform and implement X_CORE_BENCHMARK_run function.\n");
}

/* Public function definitions */

TestRef T_CORE_COREBENCH_tests(void) {
	EMB_UNIT_TESTFIXTURES(fixtures) {
		new_TestFixture("Run core benchmark", T_CORE_COREBENCH_check),
	};
	stdimpl_print("\nCoremark:\n");
	EMB_UNIT_TESTCALLER(corebenchTest, "Coremark", T_CORE_COREBENCH_setUp, T_CORE_COREBENCH_tearDown, fixtures);

	return (TestRef) & corebenchTest;
}
