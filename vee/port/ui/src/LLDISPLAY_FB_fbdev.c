/*
 * C
 *
 * Copyright 2014-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

#include "LLUI_DISPLAY_impl.h"

#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/fb.h>

#include "LLUI_DISPLAY_impl.h"
#include "LLDISPLAY_FB.h"
#include "LLDISPLAY_FB_fbdev.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLDISPLAY_LOG_MODULE_NAME, LLDISPLAY_LOG_LEVEL)

int lldisplay_fb_fbdev_getscreeninfo(int fd, lldisplay_screeninfo_t *display_screeninfo) {
	struct fb_var_screeninfo vscreeninfo; /* copy of drivers var-struct */
	int ret = 0;

	/* get a copy of the current var-structure*/
	if (ioctl(fd, FBIOGET_VSCREENINFO, &vscreeninfo) >= 0) {
		display_screeninfo->width = vscreeninfo.xres;
		display_screeninfo->height = vscreeninfo.yres;
		display_screeninfo->bpp = vscreeninfo.bits_per_pixel;
	} else {
		VEEPORT_LOGGER_LOG_DBG("Screen initialization...	FAILED 2");
		ret = -1;
	}

	return ret;
}

int lldisplay_fb_fbdev_create_fb(int fd, int screensize, char **fb_base) {
	int ret = 0;
	*fb_base = mmap(0, screensize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	//cppcheck-suppress [misra-c2012-11.6] mmap returns (void *) -1
	if (*fb_base == MAP_FAILED) {
		VEEPORT_LOGGER_LOG_ERR("mmap failed for size %d: %s", screensize, strerror(errno));
		ret = -errno;
	}
	return ret;
}

void lldisplay_fb_fbdev_setdoublebuffer(int fd) {
	struct fb_var_screeninfo vscreeninfo; /* copy of drivers var-struct */

	/* get a copy of the current var-structure*/
	if (ioctl(fd, FBIOGET_VSCREENINFO, &vscreeninfo) < 0) {
		VEEPORT_LOGGER_LOG_ERR("Wrong ioctl (FBIOGET_VSCREENINFO: %s)", strerror(errno));
		return;
	}
	vscreeninfo.yres_virtual = vscreeninfo.yres * (uint32_t)2;
	if (ioctl(fd, FBIOPUT_VSCREENINFO, &vscreeninfo) < 0) {
		VEEPORT_LOGGER_LOG_ERR("Wrong ioctl (FBIOPUT_VSCREENINFO: %s)", strerror(errno));
	}

	vscreeninfo.xoffset = 0;
	vscreeninfo.yoffset = 0;
	if (ioctl(fd, FBIOPAN_DISPLAY, &vscreeninfo) < 0) {
		VEEPORT_LOGGER_LOG_ERR("Wrong ioctl (FBIOPAN_DISPLAY: %s)", strerror(errno));
	}
}

void lldisplay_fb_fbdev_waitforvsync(int fd) {
	int args = 1;
	if (ioctl(fd, FBIO_WAITFORVSYNC, &args) < 0) {
		VEEPORT_LOGGER_LOG_ERR("Framebuffer error during vsync (%s)", strerror(errno));
	}
}
