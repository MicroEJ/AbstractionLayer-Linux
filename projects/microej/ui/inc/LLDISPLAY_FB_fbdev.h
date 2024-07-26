/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLDISPLAY_FB_FBDEV_H
#define LLDISPLAY_FB_FBDEV_H

/* Includes ------------------------------------------------------------------*/

#include "LLDISPLAY_FB.h"

/* Defines -------------------------------------------------------------------*/

/* API -----------------------------------------------------------------------*/

/*
 * Wait for vertical sync
 */

int lldisplay_fb_fbdev_getscreeninfo(int fd, lldisplay_screeninfo_t* display_screeninfo);
int lldisplay_fb_fbdev_create_fb(int fd, int screensize, char** fb_base);
void lldisplay_fb_fbdev_setdoublebuffer(int fd);
void lldisplay_fb_fbdev_waitforvsync(int fd);

#endif	// LLDISPLAY_FB_FBDEV_H