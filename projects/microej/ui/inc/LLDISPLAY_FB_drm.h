/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLDISPLAY_FB_DRM_H
#define LLDISPLAY_FB_DRM_H

/* Includes ------------------------------------------------------------------*/

#include "LLDISPLAY_FB.h"

/* Defines -------------------------------------------------------------------*/

/* API -----------------------------------------------------------------------*/

int lldisplay_fb_drm_getscreeninfo(int fb, lldisplay_screeninfo_t* display_screeninfo);
int lldisplay_fb_drm_create_fb(int fd, int screensize, lldisplay_screeninfo_t display_screeninfo, char** fb_base);
int lldisplay_fb_drm_set_crtc(int fd);
void lldisplay_fb_drm_setdoublebuffer(int fb);
void lldisplay_fb_drm_waitforvsync(int fb);

#endif	// LLDISPLAY_FB_DRM_H