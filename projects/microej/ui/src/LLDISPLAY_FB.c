/*
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */



#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdlib.h>
#include "posix_time.h"
#include "microej.h"
#include "framerate.h"
#include <assert.h>
#include <limits.h>
#include <pthread.h>

#include "LLUI_DISPLAY_impl.h"
#include "LLDISPLAY_FB.h"
#include "LLDISPLAY_FB_fbdev.h"
#include "LLDISPLAY_FB_drm.h"

//#define DEBUG_SYNC

static uint8_t* lldisplay_buf = NULL;
static int32_t lldisplay_xmin = 0;
static int32_t lldisplay_xmax = 0;
static int32_t lldisplay_ymin = 0;
static int32_t lldisplay_ymax = 0;

static int fd = -1;	/* file descriptor for the framebuffer device */
static char * fb_base;	/* base address of the video-memory */

static struct lldisplay_screeninfo_t display_screeninfo;
static int8_t display_use_vsync = 0;
static int8_t display_is_available = 0;

//cppcheck-suppress [misra-c2012-8.7] need to be defined to avoid link issue
int32_t com_ist_allocator_SimpleAllocator_MallocPtr = 0;

typedef struct binary_semaphore_t {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool free;
}binary_semaphore_t;

void lldisplay_binary_semaphore_init(binary_semaphore_t* sem);
void lldisplay_binary_semaphore_take(binary_semaphore_t* sem);
void lldisplay_binary_semaphore_give(binary_semaphore_t* sem);
void lldisplay_mutex_init(pthread_mutex_t* mutex);
void lldisplay_cond_init(pthread_cond_t* condition);

static binary_semaphore_t copy_semaphore;
//cppcheck-suppress [misra-c2012-8.9] address is used via LLUI_DISPLAY_SInitData
static binary_semaphore_t binary_semaphore_0;
//cppcheck-suppress [misra-c2012-8.9] address is used via LLUI_DISPLAY_SInitData
static binary_semaphore_t binary_semaphore_1;

void lldisplay_binary_semaphore_init(binary_semaphore_t* sem){
	lldisplay_mutex_init(&(sem->mutex));
	lldisplay_cond_init(&(sem->cond));
	sem->free = true;
}

void lldisplay_binary_semaphore_take(binary_semaphore_t* sem)
{
    int32_t result = pthread_mutex_lock(&(sem->mutex));
	assert(result==0);
    while (!sem->free){
        result = pthread_cond_wait(&(sem->cond), &(sem->mutex));
		assert(result==0);
    }
    sem->free = false;
    result = pthread_mutex_unlock(&(sem->mutex));
	assert(result==0);
}

void lldisplay_binary_semaphore_give(binary_semaphore_t* sem)
{
	int32_t result = pthread_mutex_lock(&(sem->mutex));
	assert(result==0);
	sem->free = true;
	result = pthread_cond_signal(&(sem->cond));
	assert(result==0);
	result = pthread_mutex_unlock(&(sem->mutex));
	assert(result==0);
}

void lldisplay_mutex_init(pthread_mutex_t* mutex){
	pthread_mutexattr_t mutexAttributes;
	int32_t result = pthread_mutexattr_init(&mutexAttributes);
	assert(result==0);

	result = pthread_mutexattr_settype(&mutexAttributes, PTHREAD_MUTEX_DEFAULT);
	assert(result==0);

	result = pthread_mutex_init(mutex, &mutexAttributes);
	assert(result==0);
	result = pthread_mutexattr_destroy(&mutexAttributes);
	assert(result==0);
}

void lldisplay_cond_init(pthread_cond_t* condition){
	// initialize the condition
	pthread_condattr_t conditionAttributes;
	int32_t result = pthread_condattr_init(&conditionAttributes);
	assert(result==0);
#ifndef CONDITION_SETCLOCK_NO_SUPPORT
	// time used by the condition in pthread_cond_timedwait is monotonic
	result = pthread_condattr_setclock(&conditionAttributes, CLOCK_MONOTONIC);
	assert(result==0);
#endif
	result = pthread_cond_init(condition, &conditionAttributes);
	assert(result==0);
	result = pthread_condattr_destroy(&conditionAttributes);
	assert(result==0);
}

static void vsync(void)
{
	if(display_use_vsync == 1){
#ifdef LLDISPLAY_FBDEV
		lldisplay_fb_fbdev_waitforvsync(fd);
#endif
#ifdef LLDISPLAY_FBDRM
		lldisplay_fb_drm_waitforvsync(fd);
#endif
	}
}

static void* lldisplay_copy_task(void* p_args){
	(void)p_args;
	while(1){
#ifdef DEBUG_SYNC
		LLDISPLAY_LOG_DEBUG("[TASK] wait copy signal\n");
#endif
		lldisplay_binary_semaphore_take(&copy_semaphore);
#ifdef DEBUG_SYNC
		LLDISPLAY_LOG_DEBUG("[TASK] copy signal got\n");
#endif
#ifdef FRAMERATE_ENABLED
		framerate_increment();
#endif
		vsync();
		int32_t mul = (display_screeninfo.bpp/8);
		(void)memcpy((void*)(fb_base+(display_screeninfo.width*lldisplay_ymin*mul)), (void*)(lldisplay_buf+(display_screeninfo.width*lldisplay_ymin*mul)), display_screeninfo.width*(lldisplay_ymax-lldisplay_ymin+1)*mul);

#ifdef DEBUG_SYNC
		LLDISPLAY_LOG_DEBUG("[TASK] give done signal\n");
#endif
		LLUI_DISPLAY_flushDone(false);
#ifdef DEBUG_SYNC
		LLDISPLAY_LOG_DEBUG("[TASK] done signal given\n");
#endif
	}
}

void LLUI_DISPLAY_IMPL_initialize(LLUI_DISPLAY_SInitData* init_data) {
	uint8_t* back_buffer;
	const char *fb_name = NULL;
	int8_t display_convert_32_to_16_bpp = 0;
	const char *display_convert_32_to_16_bpp_str = NULL;
	const char *display_use_vsync_str = NULL;
	pthread_t lldisplay_copy_threadRef = -1;
	int screensize = 0;
	int ret;

	LLDISPLAY_LOG_DEBUG("Screen initialization...\n");

	fb_name = getenv("LLDISPLAY_FBDEVICE");
	if (fb_name != NULL) {
		/* open fb-device, map video-memory and more */
		fd = open(fb_name, O_RDWR);
	} else {
		/* try default driver names for each backend type */
#ifdef LLDISPLAY_FBDEV
		fd = open("/dev/fb0", O_RDWR);
		if (fd < 0) {
			fd = open("/dev/fb1", O_RDWR);
			if (fd < 0) {
				fd = open("/dev/fd", O_RDWR);
			}
		}
#endif
#ifdef LLDISPLAY_FBDRM
		fd = open("/dev/dri/card0", O_RDWR);
#endif
	}

	if (fd < 0) {
		LLDISPLAY_LOG_DEBUG("Screen initialization...	FAILED 1\n");
		LLDISPLAY_LOG_WARNING("Frame buffer not available, skipping display setup\n");
		return;
	}

#ifdef LLDISPLAY_FBDEV
	ret = lldisplay_fb_fbdev_getscreeninfo(fd, &display_screeninfo);
#endif
#ifdef LLDISPLAY_FBDRM
	ret = lldisplay_fb_drm_getscreeninfo(fd, &display_screeninfo);
#endif
	if (ret < 0) {
		LLDISPLAY_LOG_DEBUG("Screen initialization...	FAILED 2\n");
		return;
	}

	display_convert_32_to_16_bpp_str = getenv("LLDISPLAY_CONVERT_32_TO_16_BPP");
	if( display_convert_32_to_16_bpp_str != NULL ) {
		if(display_screeninfo.bpp != 16){
			LLDISPLAY_LOG_DEBUG("Wrong screen format (%dx%d - %d bpp) to make convertion of 32 bpp to 16 bpp\n", display_screeninfo.width, display_screeninfo.height, display_screeninfo.bpp);
			return;
		}
		display_convert_32_to_16_bpp = 1;
	}

	display_use_vsync_str = getenv("LLDISPLAY_USE_VSYNC");
	if( display_use_vsync_str != NULL ) {
		display_use_vsync = 1;
	}


	/* memory map the frame buffer */
	screensize = display_screeninfo.width * display_screeninfo.height * display_screeninfo.bpp / 8;
#ifdef LLDISPLAY_USE_FLIP
	screensize = screensize * 2;
#endif
#ifdef LLDISPLAY_FBDEV
	ret = lldisplay_fb_fbdev_create_fb(fd, screensize, &fb_base);
#endif
#ifdef LLDISPLAY_FBDRM
	ret =  lldisplay_fb_drm_create_fb(fd, screensize, display_screeninfo, &fb_base);
#endif
	if (ret != 0) {
		LLDISPLAY_LOG_DEBUG("Screen initialization...	FAILED 4\n");
		return;
	}

	/* back buffer allocation */
	if((display_screeninfo.bpp == 16) || (display_screeninfo.bpp == 32)){
		if(display_convert_32_to_16_bpp == 1){
			back_buffer = malloc(display_screeninfo.width * display_screeninfo.height * 32 / 8); // 32 bits per pixel stack
		}else{
			back_buffer = malloc(display_screeninfo.width * display_screeninfo.height * display_screeninfo.bpp / 8);
		}
	}else{
		LLDISPLAY_LOG_DEBUG("Screen format not handled (%dx%d - %d bpp)\n", display_screeninfo.width, display_screeninfo.height, display_screeninfo.bpp);
		return;
	}
	if(back_buffer == NULL){
		LLDISPLAY_LOG_DEBUG("An error occurred during back buffer allocation\n");
		return;
	}

#ifdef LLDISPLAY_USE_FLIP
#ifdef LLDISPLAY_FBDEV
	lldisplay_fb_fbdev_setdoublebuffer(fd);
#endif
#endif

#ifdef LLDISPLAY_FBDRM
	ret = lldisplay_fb_drm_set_crtc(fd);
	if (ret != 0) {
		LLDISPLAY_LOG_DEBUG("Screen initialization...	FAILED 5\n");
		return;
	}
#endif

	display_is_available = 1;

	// initialize copy task semaphore
	lldisplay_binary_semaphore_init(&copy_semaphore);
	//take the semaphore => next take should block
	lldisplay_binary_semaphore_take(&copy_semaphore);

	int32_t result ;
	pthread_attr_t attributes;
	result = pthread_attr_init(&attributes);
	assert(result==0);
	result = pthread_attr_setstacksize(&attributes, PTHREAD_STACK_MIN);
	assert(result==0);
	// Initialize pthread such as its resource will be
	result = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_JOINABLE);
	result = pthread_create(&lldisplay_copy_threadRef, &attributes, &lldisplay_copy_task, NULL);
	assert(result==0);

	lldisplay_binary_semaphore_init(&binary_semaphore_0);
	lldisplay_binary_semaphore_init(&binary_semaphore_1);
	init_data->binary_semaphore_0 = (void*)&binary_semaphore_0;
	init_data->binary_semaphore_1 = (void*)&binary_semaphore_1;
	init_data->lcd_width = display_screeninfo.width;
	init_data->lcd_height = display_screeninfo.height;
	init_data->back_buffer_address = (uint8_t*)back_buffer;
	LLDISPLAY_LOG_DEBUG("Screen initialization...	OK\n");
}

uint8_t* LLUI_DISPLAY_IMPL_flush(MICROUI_GraphicsContext* gc, uint8_t* addr, uint32_t xmin, uint32_t ymin, uint32_t xmax, uint32_t ymax)
{
	(void)gc;
	(void)xmin;
	(void)xmax;
	lldisplay_buf = addr;
	lldisplay_ymin = ymin;
	lldisplay_ymax = ymax;

	if (display_is_available == 1) {
#ifdef DEBUG_SYNC
		LLDISPLAY_LOG_DEBUG("[FLUSH] give copy signal\n");
#endif
	lldisplay_binary_semaphore_give(&copy_semaphore);
#ifdef DEBUG_SYNC
		LLDISPLAY_LOG_DEBUG("[FLUSH] copy signal given\n");
#endif

#ifdef FRAMERATE_ENABLED
//	framerate_increment();
#endif
	}
	return addr;
}

void LLUI_DISPLAY_IMPL_binarySemaphoreTake(void* sem)
{
	if (display_is_available == 1) {
		lldisplay_binary_semaphore_take((binary_semaphore_t*)sem);
	}
}

void LLUI_DISPLAY_IMPL_binarySemaphoreGive(void* sem, bool under_isr)
{
	(void)under_isr;
	if (display_is_available == 1) {
		lldisplay_binary_semaphore_give((binary_semaphore_t*)sem);
	}	
}