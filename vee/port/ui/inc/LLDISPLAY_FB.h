/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#ifndef LLDISPLAY_FB_H
#define LLDISPLAY_FB_H

/* Includes ------------------------------------------------------------------*/

#include "veeport_logger.h"

/* Defines -------------------------------------------------------------------*/

/**
 * @brief Name of the log module shared by every source file of the framebuffer display driver.
 *
 * Each source file that logs registers the module with VEEPORT_LOGGER_DEFINE_MODULE().
 */
#define LLDISPLAY_LOG_MODULE_NAME "display"

/**
 * @brief Verbosity of the framebuffer display driver.
 *
 * Override it in veeport_configuration.h with one of VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF
 * or _DBG.
 */
#ifndef LLDISPLAY_LOG_LEVEL
#define LLDISPLAY_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

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

#endif // LLDISPLAY_FB_H
