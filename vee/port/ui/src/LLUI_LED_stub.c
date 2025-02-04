/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include "LLUI_LED_impl.h"

int32_t LLUI_LED_IMPL_initialize(void) {
	return 0; // 0 LEDs
}

int32_t LLUI_LED_IMPL_getIntensity(int32_t ledID) {
	return LLUI_LED_MIN_INTENSITY;
}

void LLUI_LED_IMPL_setIntensity(int32_t ledID, int32_t intensity) {
	// nothing to do
}
