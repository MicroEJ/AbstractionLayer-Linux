/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLDISPLAY_FB_H
#define LLDISPLAY_FB_H

/* Includes ------------------------------------------------------------------*/

/* Defines -------------------------------------------------------------------*/

// #define LLDISPLAY_DEBUG

// #define LLDISPLAY_USE_FLIP

#if !defined(LLDISPLAY_FBDEV) && !defined(LLDISPLAY_FBDRM)
#error "Select a framebuffer backend: enable either LLDISPLAY_FBDEV or LLDISPLAY_FBDRM"
#endif

#if defined(LLDISPLAY_FBDEV) && defined(LLDISPLAY_FBDRM)
#error "Select only one framebuffer backend: enable either LLDISPLAY_FBDEV or LLDISPLAY_FBDRM"
#endif

/* API -----------------------------------------------------------------------*/

typedef struct lldisplay_screeninfo_t {
    int32_t width;
    int32_t height;
    int32_t bpp;
} lldisplay_screeninfo_t;

/*
 * DEBUG logs
 */
#ifdef LLDISPLAY_DEBUG
#define LLDISPLAY_LOG_DEBUG printf
#else // LLDISPLAY_DEBUG
#define LLDISPLAY_LOG_DEBUG(...) ((void) 0)
#endif
#define LLDISPLAY_LOG_WARNING printf("[LLDISPLAY][WARNING] ");printf

#endif	// LLDISPLAY_FB_H