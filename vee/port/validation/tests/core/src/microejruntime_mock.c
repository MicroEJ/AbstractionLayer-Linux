/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

// -----------------------------------------------------------------------------
// Includes
// -----------------------------------------------------------------------------

// Include VEE Port User configuration file
#if defined __has_include
	#if __has_include("veeport_configuration.h")
		#include "veeport_configuration.h"
	#endif // __has_include("veeport_configuration.h")
#else
// Ensure 'veeport_configuration.h' exists in your project for custom configurations.
	#include "veeport_configuration.h"
#endif // defined __has_include

#if (MICROEJ_CORE_VEE_MOCK_VALIDATION == 1)

#include <stdio.h>
#include "sni.h"
#include "u_print.h"
#include "async_wakeup_vm.h"
#include "microejruntime_mock.h"

// -----------------------------------------------------------------------------
// Macros and Defines
// -----------------------------------------------------------------------------

/**
 * @brief Mock of a VEE library (microejruntime.a) that tests the implementation of
 * the Core Engine abstraction layer implementation.
 */
#pragma message("MICROEJ VEE Mock enabled. Please remove from the build the files microejapp.o and microejruntime.a.")

/**
 * @brief Tolerance percentage used to check if tests are passed or failed. (the default value is 5%)
 */
#define ERROR_MARGIN_PERCENTAGE (5U)

/**
 * @brief Standard log output redirection macro, update UTIL_printf in u_print.h if necessary. (the default value is
 * printf)
 */
#define mock_printf UTIL_printf
#define test_assert_error(message)                           \
		do {                                                 \
			assertion_error_detected = true;                 \
			mock_printf("Assertion error: %s\n", (message)); \
		} while (0)

#define test_assert(condition, message)     \
		do {                                \
			if (!(condition)) {             \
				test_assert_error(message); \
			}                               \
		} while (0)

#define TARGET_500 (500)

// -----------------------------------------------------------------------------
// Private Global Variables
// -----------------------------------------------------------------------------

/**
 * @brief A variable returned when creating the VEE.
 */
static int vee;

/**
 * @brief Set to true when an assertion fails.
 */
static bool assertion_error_detected = false;

// -----------------------------------------------------------------------------
// List of the tests
// -----------------------------------------------------------------------------

static void test_idle(void);
static void test_schedule_request(void);
static void test_ackWakeup(void);
static void test_ackWakeup_cancel_schedule_request(void);
static void test_timer_schedule_request_after_ackWakeup_cancel(void);

// -----------------------------------------------------------------------------
// Private functions
// -----------------------------------------------------------------------------

/**
 * @brief Cleans the MICROEJ VEE Mock for the next tests.
 */
static void post_test_mock_cleanup(void) {
	async_wakeup_vm_cancel();
	LLMJVM_IMPL_ackWakeup();
}

/**
 * @brief Computes and returns the delta of the value according to the ERROR_MARGIN_PERCENTAGE.
 */
static int64_t delta_error_margin(int64_t value) {
	return ((value * ERROR_MARGIN_PERCENTAGE) / 100);
}

// -----------------------------------------------------------------------------
// MICROEJ VEE Mock function definitions
// -----------------------------------------------------------------------------

void * SNI_createVM(void) {
	int32_t res = LLMJVM_IMPL_initialize();
	test_assert(LLMJVM_OK == res, "LLMJVM_IMPL_initialize error");

	OSAL_status_t status = async_wakeup_vm_init();
	test_assert(OSAL_OK == status, "async_wakeup_vm_init error");

	return (void *)&vee;
}

int32_t SNI_startVM(void *vm, int32_t argc, char **argv) {
	VEE_MOCK_UNUSED(argc);
	VEE_MOCK_UNUSED(argv);

	if (vm != &vee) {
		test_assert_error("Wrong VEE passed to SNI_startVM");
		return SNI_ILLEGAL_ARGUMENT;
	}

	mock_printf("SNI_startVM\n");

	LLMJVM_IMPL_vmTaskStarted();

	// Execute the tests
	test_idle();
	test_schedule_request();
	test_ackWakeup();
	test_ackWakeup_cancel_schedule_request();
	test_timer_schedule_request_after_ackWakeup_cancel();

	LLMJVM_IMPL_shutdown();

	return 0;
}

void SNI_destroyVM(void *vm) {
	test_assert(vm == &vee, "Wrong VEE passed to SNI_destroyVM");

	async_wakeup_vm_stop();

	if (assertion_error_detected == true) {
		mock_printf("Tests FAILED\n");
	} else {
		mock_printf("Tests PASSED\n");
	}
}

int32_t SNI_getExitCode(void *vm) {
	test_assert(vm == &vee, "Wrong VEE passed to SNI_getExitCode");
	return 0;
}

void LLMJVM_dump(void) {
	mock_printf("LLMJVM_dump MOCK\n");
}

int32_t LLMJVM_schedule(void) {
	LLMJVM_IMPL_wakeupVM();
}

// -----------------------------------------------------------------------------
// Tests definition
// -----------------------------------------------------------------------------

/**
 * @brief Tests that LLMJVM_IMPL_idleVM() correctly blocks the execution and LLMJVM_IMPL_wakeupVM() unblocks it.
 */
static void test_idle(void) {
	mock_printf("%s \n", __func__);

	int64_t target = TARGET_500;

	// Start the MICROEJ VEE Mock to timeout after target ms.
	async_wakeup_vm(target);

	// Wait until the timeout occurs.
	volatile int64_t time_before_idle = LLMJVM_IMPL_getCurrentTime(1);
	LLMJVM_IMPL_idleVM();
	int64_t time_after_idle = LLMJVM_IMPL_getCurrentTime(1);
	volatile int64_t idle_time = time_after_idle - time_before_idle;

	// idle time expected to be equal to the VEE Mock timeout.
	test_assert((idle_time >= (target - delta_error_margin(target))), "LLMJVM_IMPL_idleVM() does not block.");

	post_test_mock_cleanup();
}

/**
 * @brief Tests that LLMJVM_IMPL_scheduleRequest() schedules a call to LLMJVM_schedule()
 */
static void test_schedule_request(void) {
	mock_printf("%s \n", __func__);

	int64_t target = TARGET_500;
	volatile int64_t request_time = LLMJVM_IMPL_getCurrentTime(1) + target;

	// Attempt to wake up the VEE before the timeout with "LLMJVM_IMPL_scheduleRequest".
	LLMJVM_IMPL_scheduleRequest(request_time);
	async_wakeup_vm(target * 2);

	volatile int64_t time_before_idle = LLMJVM_IMPL_getCurrentTime(1);
	LLMJVM_IMPL_idleVM();
	int64_t time_after_idle = LLMJVM_IMPL_getCurrentTime(1);

	volatile int64_t idle_time = time_after_idle - time_before_idle;

	// Expects to wake up the VEE after target ms.
	test_assert((idle_time > (target - delta_error_margin(target))),
	            "LLMJVM_IMPL_idleVM() does not block after LLMJVM_IMPL_scheduleRequest().");
	test_assert((idle_time < (target + delta_error_margin(target))),
	            "LLMJVM_IMPL_scheduleRequest() error.");

	post_test_mock_cleanup();
}

/**
 * @brief Tests that LLMJVM_IMPL_idleVM() blocks after calls to LLMJVM_IMPL_wakeupVM() and LLMJVM_IMPL_ackWakeup().
 */
static void test_ackWakeup(void) {
	mock_printf("%s \n", __func__);

	int64_t target = TARGET_500;

	async_wakeup_vm(target);

	// Allows the MICROEJ VEE execution to resume
	LLMJVM_IMPL_wakeupVM();

	// Acknowledge the wakeup to ensure that the next call of "LLMJVM_IMPL_idleVM" will be blocking.
	LLMJVM_IMPL_ackWakeup();

	// Wait until the MICROEJ VEE wakes up or timeout.
	volatile int64_t time_before_idle = LLMJVM_IMPL_getCurrentTime(1);
	LLMJVM_IMPL_idleVM();
	int64_t time_after_idle = LLMJVM_IMPL_getCurrentTime(1);
	volatile int64_t idle_time = time_after_idle - time_before_idle;

	// Timeout expected here because the call of "LLMJVM_IMPL_idleVM" must be blocking.
	test_assert((idle_time >= (target - delta_error_margin(target))),
	            "LLMJVM_IMPL_ackWakeup does not make next call to LLMJVM_IMPL_idleVM() blocking.");

	post_test_mock_cleanup();
}

/**
 * @brief Tests that LLMJVM_IMPL_ackWakeup() cancels any previous request scheduled with LLMJVM_IMPL_scheduleRequest()
 */
static void test_ackWakeup_cancel_schedule_request(void) {
	mock_printf("%s \n", __func__);

	int64_t target = TARGET_500;

	// Performs a schedule request to start in 'target' ms
	volatile int64_t request_time = LLMJVM_IMPL_getCurrentTime(1) + target;
	LLMJVM_IMPL_scheduleRequest(request_time);

	async_wakeup_vm(target * 2);

	// Cancels the current schedule request
	LLMJVM_IMPL_ackWakeup();
	volatile int64_t time_before_idle = LLMJVM_IMPL_getCurrentTime(1);

	// Waits until the schedule request occurs or timeout after target*2 ms.
	LLMJVM_IMPL_idleVM();
	int64_t time_after_idle = LLMJVM_IMPL_getCurrentTime(1);

	volatile int64_t idle_time = time_after_idle - time_before_idle;

	// Timeout expected to confirm that the "LLMJVM_IMPL_scheduleRequest" has been cancelled.
	test_assert((idle_time > ((target * 2) - delta_error_margin((target * 2)))),
	            "LLMJVM_IMPL_scheduleRequest() not cancelled.");

	post_test_mock_cleanup();
}

/**
 * @brief Tests that LLMJVM_IMPL_ackWakeup() allows to schedule correctly a timer with
 * LLMJVM_IMPL_scheduleRequest after the last one has been cancelled.
 */
static void test_timer_schedule_request_after_ackWakeup_cancel(void) {
	mock_printf("%s \n", __func__);

	int64_t target = TARGET_500;

	// Performs a schedule request to start in 'target' ms
	volatile int64_t request_time = LLMJVM_IMPL_getCurrentTime(1) + target;
	LLMJVM_IMPL_scheduleRequest(request_time);

	async_wakeup_vm((target * 2));

	// Cancels the current schedule request
	LLMJVM_IMPL_ackWakeup();

	// Requests again a schedule to start in 'target' ms
	LLMJVM_IMPL_scheduleRequest(request_time);

	// Waits until the schedule request occurs or timeout after target*2 ms.
	volatile int64_t time_before_idle = LLMJVM_IMPL_getCurrentTime(1);
	LLMJVM_IMPL_idleVM();
	int64_t time_after_idle = LLMJVM_IMPL_getCurrentTime(1);

	volatile int64_t idle_time = time_after_idle - time_before_idle;

	// Execution of the second LLMJVM_IMPL_scheduleRequest expected after the first cancelling.
	test_assert((idle_time > (target - delta_error_margin(target))),
	            "LLMJVM_IMPL_scheduleRequest() error.");
	test_assert((idle_time < (target + delta_error_margin(target))),
	            "LLMJVM_IMPL_scheduleRequest() could not schedule a timer after LLMJVM_IMPL_ackWakeup.");

	post_test_mock_cleanup();
}

// -----------------------------------------------------------------------------
// End
// -----------------------------------------------------------------------------

#endif // (MICROEJ_CORE_VEE_MOCK_VALIDATION == 1)
