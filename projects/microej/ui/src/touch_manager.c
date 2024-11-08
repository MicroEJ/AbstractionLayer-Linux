/*
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
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

//#define LLTOUCH_DEBUG

#ifdef LLTOUCH_DEBUG
#define LLTOUCH_LOG_DEBUG printf
#else // LLTOUCH_DEBUG
#define LLTOUCH_LOG_DEBUG(...) ((void) 0)
#endif
#define LLTOUCH_LOG_WARNING printf("[LLTOUCH][WARNING] ");printf

static volatile int pressed;

#define TSDEVICE_RETRY_TIMEOUT_SEC 1
#define TSDEVICE_RETRY_TIMEOUT_NB 10
#define TSDEVICE_DEFAULT_NAME "/dev/input/touchscreen0"

#ifdef TOUCH_POLLING
static int64_t touch_poll_delay = 20;
#endif // TOUCH_POLLING

struct tsdev *TOUCH_MANAGER_ts_init() {
	struct tsdev *ts = NULL;
	char *tsdevice = NULL;
	int retries = TSDEVICE_RETRY_TIMEOUT_NB;

	tsdevice = getenv("TSLIB_TSDEVICE");
	if (NULL == tsdevice) {
		tsdevice = TSDEVICE_DEFAULT_NAME;
	}

	/* retry in case the device is not ready yet */
	while (retries > 0) {
		ts = ts_open(tsdevice, 0);
		if (NULL != ts) {
			break;
		}
		LLTOUCH_LOG_DEBUG("Touch initialization failed. retry in %d seconds (ts_open error %d: %m)\n", TSDEVICE_RETRY_TIMEOUT_SEC, errno);
		retries--;
		sleep(TSDEVICE_RETRY_TIMEOUT_SEC);
	}

	if (NULL == ts) {
		LLTOUCH_LOG_WARNING("Touch initialization failed... (ts_open error)\n");
	}

	if ((NULL != ts) && (0 != ts_config(ts))) {
		LLTOUCH_LOG_WARNING("Touch initialization failed... (ts_config error)\n");
		ts_close(ts);
		ts = NULL;
	}
	return ts;
}

void* TOUCH_MANAGER_work(void* p_args) {
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
		if(t0 == 0l) {
//			LLTOUCH_LOG_DEBUG("[TOUCH] init time \n");
			t0 = posix_time_getcurrenttime(1);
		}
#endif

		ret = ts_read(ts, &samp, 1);

		if (ret != 1) {
			LLTOUCH_LOG_DEBUG("Fail to Read touch event (ts_read error=%d)\n", ret);
			/* error during ts_read(), reopen the ts device, and exit if it fails again  */
			ts_close(ts);
			ts = TOUCH_MANAGER_ts_init();
			if (NULL == ts) {
				return NULL;
			} else {
				continue;
			}
		}

//		LLTOUCH_LOG_DEBUG("%ld.%06ld: %6d %6d %6d\n", samp.tv.tv_sec, samp.tv.tv_usec, samp.x, samp.y, samp.pressure);
		if(samp.pressure > 0) {

			if(pressed == 0) {
				TOUCH_HELPER_pressed(samp.x,samp.y);
				pressed = 1;
			} else {
#ifdef TOUCH_POLLING
				t1 = posix_time_getcurrenttime(1) - t0;
//				LLTOUCH_LOG_DEBUG("[TOUCH] t0=%l ms, t1=%l \n", t0, t1);
//				LLTOUCH_LOG_DEBUG("[TOUCH] test (%l ms, ret=%d)\n", t1, ret);
				if(t1 < touch_poll_delay){
//					LLTOUCH_LOG_DEBUG("[TOUCH] continue (%l ms, ret=%d)\n", t1, ret);
					continue;
				}else{
//					LLTOUCH_LOG_DEBUG("[TOUCH] reset (%l ms, ret=%d)\n", t1, ret);
					t0 = 0;
				}
//				LLTOUCH_LOG_DEBUG("%ld.%06ld: %6d %6d %6d\n", samp.tv.tv_sec, samp.tv.tv_usec, samp.x, samp.y, samp.pressure);
#endif
				TOUCH_HELPER_moved(samp.x, samp.y);
			}
		} else {
			if(pressed == 1) {
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
	int32_t result;

	result = pthread_attr_init(&attributes);
	assert(result==0);
	result = pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN);
	assert(result==0);
	result = pthread_create(&thread, &attributes, TOUCH_MANAGER_work, NULL);
	assert(result==0);
	result = pthread_attr_destroy(&attributes);
	assert(result==0);
}
