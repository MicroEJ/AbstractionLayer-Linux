/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

#include <tslib.h>

#include "touch_manager.h"
#include "posix_time.h"
#include "touch_helper.h"

#include "microui_constants.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLTOUCH_LOG_MODULE_NAME, LLTOUCH_LOG_LEVEL)

static volatile int pressed;

#define TSDEVICE_RETRY_TIMEOUT_SEC 1
#define TSDEVICE_RETRY_TIMEOUT_NB 10
/** Touchscreen device path. Project-specific; set at build time from
 *  project_options.cmake via -DLLTOUCH_TSDEVICE="...". */
#ifndef LLTOUCH_TSDEVICE
#define LLTOUCH_TSDEVICE "/dev/input/touchscreen0"
#endif

#ifdef TOUCH_POLLING
static int64_t touch_poll_delay = 20;
#endif // TOUCH_POLLING

struct tsdev *TOUCH_MANAGER_ts_init() {
	struct tsdev *ts = NULL;
	const char *tsdevice = LLTOUCH_TSDEVICE;
	int retries = TSDEVICE_RETRY_TIMEOUT_NB;

	/* retry in case the device is not ready yet */
	while (retries > 0) {
		ts = ts_open(tsdevice, 0);
		if (NULL != ts) {
			break;
		}
		VEEPORT_LOGGER_LOG_WRN("touch initialization failed, retry in %d seconds (ts_open error %d: %m)",
		                       TSDEVICE_RETRY_TIMEOUT_SEC, errno);
		retries--;
		sleep(TSDEVICE_RETRY_TIMEOUT_SEC);
	}

	if (NULL == ts) {
		VEEPORT_LOGGER_LOG_ERR("touch initialization failed (ts_open error)");
	}

	if ((NULL != ts) && (0 != ts_config(ts))) {
		VEEPORT_LOGGER_LOG_ERR("touch initialization failed (ts_config error)");
		ts_close(ts);
		ts = NULL;
	}
	return ts;
}

void * TOUCH_MANAGER_work(void *p_args) {
	(void)p_args;
	struct tsdev *ts = NULL;
	struct ts_sample samp;
	int ret;

	ts = TOUCH_MANAGER_ts_init();
	if (NULL == ts) {
		return NULL;
	}

#ifdef TOUCH_POLLING
	int64_t t0 = 0;
	int64_t t1 = 0;
#endif

	while (1) {
#ifdef TOUCH_POLLING
		if (t0 == 0l) {
//			VEEPORT_LOGGER_LOG_DBG("[TOUCH] init time");
			t0 = posix_time_getcurrenttime(1);
		}
#endif

		ret = ts_read(ts, &samp, 1);

		if (ret != 1) {
			VEEPORT_LOGGER_LOG_WRN("cannot read the touch event (ts_read error=%d)", ret);
			/* error during ts_read(), reopen the ts device, and exit if it fails again  */
			ts_close(ts);
			ts = TOUCH_MANAGER_ts_init();
			if (NULL == ts) {
				return NULL;
			} else {
				continue;
			}
		}

//		VEEPORT_LOGGER_LOG_DBG("%ld.%06ld: %6d %6d %6d", samp.tv.tv_sec, samp.tv.tv_usec, samp.x, samp.y,
// samp.pressure);
		if (samp.pressure > 0) {
			if (pressed == 0) {
				TOUCH_HELPER_pressed(samp.x, samp.y);
				pressed = 1;
			} else {
#ifdef TOUCH_POLLING
				t1 = posix_time_getcurrenttime(1) - t0;
//				VEEPORT_LOGGER_LOG_DBG("[TOUCH] t0=%l ms, t1=%l", t0, t1);
//				VEEPORT_LOGGER_LOG_DBG("[TOUCH] test (%l ms, ret=%d)", t1, ret);
				if (t1 < touch_poll_delay) {
//					VEEPORT_LOGGER_LOG_DBG("[TOUCH] continue (%l ms, ret=%d)", t1, ret);
					continue;
				} else {
//					VEEPORT_LOGGER_LOG_DBG("[TOUCH] reset (%l ms, ret=%d)", t1, ret);
					t0 = 0;
				}
//				VEEPORT_LOGGER_LOG_DBG("%ld.%06ld: %6d %6d %6d", samp.tv.tv_sec, samp.tv.tv_usec, samp.x, samp.y,
//				                       samp.pressure);
#endif
				TOUCH_HELPER_moved(samp.x, samp.y);
			}
		} else {
			if (pressed == 1) {
				//post the event
				TOUCH_HELPER_released();
				pressed = 0;
			}
		}
	}
}

void TOUCH_MANAGER_initialize(void) {
	pthread_t thread;
	pthread_attr_t attributes;
	int32_t result __attribute__((unused));

	result = pthread_attr_init(&attributes);
	assert(result == 0);
	result = pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN);
	assert(result == 0);
	result = pthread_create(&thread, &attributes, TOUCH_MANAGER_work, NULL);
	assert(result == 0);
	result = pthread_setname_np(thread, "MICROUI touch");
	assert(result == 0);
	result = pthread_attr_destroy(&attributes);
	assert(result == 0);
}
