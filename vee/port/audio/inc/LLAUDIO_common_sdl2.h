/*
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef LLAUDIO_COMMON_SDL2_H
#define LLAUDIO_COMMON_SDL2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <SDL2/SDL.h>

#include <stdint.h>
#include <stdbool.h>

#include "LLAUDIO_defines.h"

_Static_assert(sizeof(uintptr_t) <= sizeof(uint32_t),
               "A uint32_t must be able to hold a uintptr_t.");
_Static_assert(sizeof(void *) <= sizeof(uint32_t),
               "A uint32_t must be able to hold a void*.");

// --------------------------
// Audio device configuration
// --------------------------

#define AUDIO_PLAYBACK_DESIRED_DEVICE_FREQUENCY 44100
#define AUDIO_PLAYBACK_DESIRED_DEVICE_FORMAT AUDIO_S16SYS
#define AUDIO_PLAYBACK_DESIRED_DEVICE_SAMPLES 4096u
#define AUDIO_PLAYBACK_DESIRED_DEVICE_CHANNELS 2u

#define AUDIO_CAPTURE_DESIRED_DEVICE_FREQUENCY 44100
#define AUDIO_CAPTURE_DESIRED_DEVICE_FORMAT AUDIO_S16SYS
#define AUDIO_CAPTURE_DESIRED_DEVICE_SAMPLES 4096u
#define AUDIO_CAPTURE_DESIRED_DEVICE_CHANNELS 1u

// -----------
// Error codes
// -----------

#define LLAUDIO_ERROR_TRACK_ALREADY_OPEN 1
#define LLAUDIO_ERROR_INVALID_FORMAT_PARAMETERS 2
#define LLAUDIO_ERROR_FAILED_CREATING_ENCODER_STREAM 3
#define LLAUDIO_ERROR_FAILED_CREATING_DECODER_STREAM 4
#define LLAUDIO_ERROR_HEAP_FULL_ALLOCATING_TRACK 5
#define LLAUDIO_ERROR_FAILED_INITIALIZING_MUTEX 6
#define LLAUDIO_ERROR_FAILED_INITIALIZING_CONDITION 7
#define LLAUDIO_ERROR_HEAP_FULL_ALLOCATING_RING_BUFFER 8
#define LLAUDIO_ERROR_FORMAT_NOT_SUPPORTED 9

// ----------------
// Common functions
// ----------------

void AUDIO_init();
SDL_AudioFormat AUDIO_get_pcm_format(const LLAUDIO_pcm_format_parameters_t *format_parameters);
void * AUDIO_malloc(size_t size);
void AUDIO_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* ifndef LLAUDIO_COMMON_SDL2_H */
