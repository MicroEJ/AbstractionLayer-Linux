/*
 * C
 *
 * Copyright 2023-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdbool.h>
#include <stddef.h>

#include "LLEVENT.h"
#include "sni.h"
#include "osal.h"

/**
 * Priority of the RTOS task used to offer events from outside the MicroEJ Core Engine task
 * (see Java_ej_event_utils_TestCNatives_offerEventFromTask).
 *
 * It MUST be STRICTLY LOWER than the MicroEJ Core Engine task priority: resuming the Event Queue
 * Java thread from the offer task must immediately preempt the offer task, otherwise the
 * suspend/resume race window (lost wake-up) cannot be exercised and the related tests lose their
 * ability to detect the bug. The value is RTOS-specific (e.g. on ThreadX a LOWER priority is a
 * HIGHER number, on FreeRTOS it is the opposite), so it must be provided by the VEE Port
 * integrator.
 */
#if !defined(TESTEVENT_OFFER_TASK_PRIORITY)
#error \
	"Define TESTEVENT_OFFER_TASK_PRIORITY: the priority of the testsuite offer task. It must be strictly lower than the MicroEJ Core Engine task priority (mind the RTOS priority ordering)."
#endif

/**
 * Stack size in bytes of the RTOS task used to offer events from outside the MicroEJ Core Engine
 * task.
 */
#if !defined(TESTEVENT_OFFER_TASK_STACK_SIZE)
#define TESTEVENT_OFFER_TASK_STACK_SIZE (2048)
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct testOfferExtendedBoolean {
	jboolean a;
	jboolean b;
	jboolean c;
	jboolean d;
	jboolean e;
	jboolean f;
};

struct testOfferExtendedByte {
	jbyte a;
	jbyte b;
	jbyte c;
	jbyte d;
	jbyte e;
	jbyte f;
};

struct testOfferExtendedChar {
	jchar a;
	jchar b;
	jchar c;
};

struct testOfferExtendedDouble {
	jdouble a;
	jdouble b;
	jdouble c;
};

struct testOfferExtendedFloat {
	jfloat a;
	jfloat b;
	jfloat c;
};

struct testOfferExtendedInt {
	jint a;
	jint b;
	jint c;
	jint d;
};

struct testOfferExtendedLong {
	jlong a;
	jlong b;
	jlong c;
};

struct testOfferExtendedShort {
	jshort a;
	jshort b;
	jshort c;
};

struct testOfferExtendedUnsignedByte {
	jboolean a;
	jboolean b;
	jboolean c;
};

struct testOfferExtendedUnsignedShort {
	jchar a;
	jchar b;
	jchar c;
};

struct testOfferExtendedAlignment {
	jbyte a;
	jint b;
	jchar c;
	__attribute__((aligned(8))) jdouble d;
	jboolean e;
	jchar f;
	jfloat g;
	jboolean h;
	__attribute__((aligned(8))) jlong i;
};

struct testNotConsumeAllEventBytes {
	jbyte a;
	jbyte b;
	jbyte c;
	jbyte d;
	jbyte e;
	jbyte f;
	jbyte g;
	jbyte h;
	jbyte i;
};

/*
 * State of the RTOS task used to offer events from outside the MicroEJ Core Engine task.
 *
 * A single request slot is enough: the offer-from-task natives are only called by tests that wait
 * for the previous event to be delivered before posting the next request, so at most one request
 * is pending at any time.
 */
OSAL_task_stack_declare(offer_task_stack, TESTEVENT_OFFER_TASK_STACK_SIZE);
// The POSIX OSAL handles are a pthread_t and a sem_t, which cannot be initialized with NULL.
static OSAL_task_handle_t offer_task_handle = { 0 };
static OSAL_binary_semaphore_handle_t offer_request_semaphore = { 0 };
static bool offer_task_started = false;
static int32_t offer_request_type = 0;
static int32_t offer_request_data = 0;
static bool offer_request_is_extended = false;
// Debugger-visible status of the last offer performed by the offer task (0 on success).
static volatile int32_t last_offer_status = 0;

/**
 * Entry point of the offer task. Waits for a request posted by the offer-from-task natives and
 * performs the offer from this task, outside the MicroEJ Core Engine task, so that it can race
 * the suspend/resume of the Event Queue receiving thread.
 */
static void * offer_task_entry_point(void *args) {
	(void)args;
	while (1) {
		OSAL_status_t take_status = OSAL_binary_semaphore_take(&offer_request_semaphore, OSAL_INFINITE_TIME);
		if (OSAL_OK != take_status) {
			// Semaphore failure: leave the task, the Java tests will detect it by timeout.
			break;
		}
		if (true == offer_request_is_extended) {
			struct testOfferExtendedByte pt;
			pt.a = 1;
			pt.b = 2;
			pt.c = 3;
			pt.d = 4;
			pt.e = 5;
			pt.f = -6;
			last_offer_status = LLEVENT_offerExtendedEvent(offer_request_type, (void *)&pt, sizeof(pt));
		} else {
			last_offer_status = LLEVENT_offerEvent((uint32_t)offer_request_type, offer_request_data);
		}
	} /* end forever */
	return NULL;
}

/**
 * Creates and starts the offer task and its request semaphore on first use. Throws an SNI native
 * exception if the OS resources cannot be created.
 */
static void start_offer_task(void) {
	if (!offer_task_started) {
		OSAL_status_t task_status = OSAL_ERROR;
		OSAL_status_t semaphore_status = OSAL_binary_semaphore_create((uint8_t *)"TestEventOfferSem", 0,
		                                                              &offer_request_semaphore);
		if (OSAL_OK == semaphore_status) {
			task_status = OSAL_task_create(offer_task_entry_point, (uint8_t *)"TestEventOffer", offer_task_stack,
			                               TESTEVENT_OFFER_TASK_PRIORITY, NULL, &offer_task_handle);
		}
		if ((OSAL_OK == semaphore_status) && (OSAL_OK == task_status)) {
			offer_task_started = true;
		} else {
			SNI_throwNativeException(SNI_ERROR, "Cannot create the testsuite offer task");
		}
	}
}

int32_t Java_ej_event_utils_TestCNatives_offerEventCApi(uint32_t type, int32_t data) {
	return LLEVENT_offerEvent(type, data);
}

int32_t Java_ej_event_utils_TestCNatives_offerExtendedEventCApi(int32_t type, int8_t *data, uint32_t data_length) {
	return LLEVENT_offerExtendedEvent(type, data, data_length);
}

void Java_ej_event_utils_TestCNatives_offerExtendedBoolean(int32_t type) {
	struct testOfferExtendedBoolean pt;
	pt.a = JTRUE;
	pt.b = JFALSE;
	pt.c = JTRUE;
	pt.d = JTRUE;
	pt.e = JFALSE;
	pt.f = JTRUE;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_offerExtendedByte(int32_t type) {
	struct testOfferExtendedByte pt;
	pt.a = 1;
	pt.b = 2;
	pt.c = 3;
	pt.d = 4;
	pt.e = 5;
	pt.f = -6;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_offerExtendedChar(int32_t type) {
	struct testOfferExtendedChar pt;
	pt.a = 'a';
	pt.b = 'b';
	pt.c = 'c';
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_offerExtendedDouble(int32_t type) {
	struct testOfferExtendedDouble pt;
	pt.a = 1.54;
	pt.b = 3.2;
	pt.c = -7.35;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_offerExtendedFloat(int32_t type) {
	struct testOfferExtendedFloat pt;
	pt.a = 1.54f;
	pt.b = 3.2f;
	pt.c = -7.35f;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_offerExtendedInt(int32_t type) {
	struct testOfferExtendedInt pt;
	pt.a = 1;
	pt.b = 2;
	pt.c = 3;
	pt.d = -6;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_offerExtendedLong(int32_t type) {
	struct testOfferExtendedLong pt;
	pt.a = 0x100000000;
	pt.b = 0x200000000;
	pt.c = -0x300000000;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_offerExtendedShort(int32_t type) {
	struct testOfferExtendedShort pt;
	pt.a = 1;
	pt.b = 2;
	pt.c = -6;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_offerExtendedUnsignedByte(int32_t type) {
	struct testOfferExtendedUnsignedByte pt;
	pt.a = 128;
	pt.b = 129;
	pt.c = 130;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_offerExtendedUnsignedShort(int32_t type) {
	struct testOfferExtendedUnsignedShort pt;
	pt.a = 32768;
	pt.b = 32769;
	pt.c = 32770;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_testAlignment(int32_t type) {
	struct testOfferExtendedAlignment pt;
	pt.a = 1;
	pt.b = 42;
	pt.c = 'e';
	pt.d = 4.45;
	pt.e = JTRUE;
	pt.f = 32769;
	pt.g = 5.42f;
	pt.h = 130;
	pt.i = 0x300000000;
	LLEVENT_offerExtendedEvent(type, (void *)&pt, sizeof(pt));
}

void Java_ej_event_utils_TestCNatives_testNotConsumeAllEventBytes(int32_t type) {
	struct testNotConsumeAllEventBytes pt1;
	pt1.a = 4;
	pt1.b = 5;
	pt1.c = 6;
	pt1.d = 7;
	pt1.e = 8;
	pt1.f = 9;
	pt1.g = 10;
	pt1.h = 11;
	pt1.i = 12;
	LLEVENT_offerExtendedEvent(type, (void *)&pt1, sizeof(pt1));
	struct testOfferExtendedByte pt2;
	pt2.a = 1;
	pt2.b = 2;
	pt2.c = 3;
	pt2.d = 4;
	pt2.e = 5;
	pt2.f = -6;
	LLEVENT_offerExtendedEvent(type, (void *)&pt2, sizeof(pt2));
}

void Java_ej_event_utils_TestCNatives_offerEventFromTask(int32_t type, int32_t data) {
	start_offer_task();
	if (offer_task_started) {
		offer_request_type = type;
		offer_request_data = data;
		offer_request_is_extended = false;
		OSAL_binary_semaphore_give(&offer_request_semaphore);
	}
}

void Java_ej_event_utils_TestCNatives_offerExtendedByteFromTask(int32_t type) {
	start_offer_task();
	if (offer_task_started) {
		offer_request_type = type;
		offer_request_data = 0;
		offer_request_is_extended = true;
		OSAL_binary_semaphore_give(&offer_request_semaphore);
	}
}

#ifdef __cplusplus
}
#endif
