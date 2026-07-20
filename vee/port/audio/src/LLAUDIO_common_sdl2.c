/*
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include "LLAUDIO_common_sdl2.h"

#include "sni.h"
#include "BESTFIT_ALLOCATOR.h"

#include <stdio.h>
#include <pthread.h>

extern void const _audio_heap_start;
extern void const _audio_heap_end;

BESTFIT_ALLOCATOR audio_heap_allocator;

static void _init_audio_routine() {
	if (SDL_Init(SDL_INIT_AUDIO) < 0) {
		fprintf(stderr, "Could not initialize the SDL audio subsystem: %s\n", SDL_GetError());
		exit(1);
	}

	BESTFIT_ALLOCATOR_new(&audio_heap_allocator);
	BESTFIT_ALLOCATOR_initialize(&audio_heap_allocator, (uintptr_t)&_audio_heap_start, (uintptr_t)&_audio_heap_end);
}

void AUDIO_init() {
	static pthread_once_t initialization_control = PTHREAD_ONCE_INIT;
	pthread_once(&initialization_control, _init_audio_routine);
}

SDL_AudioFormat AUDIO_get_pcm_format(const LLAUDIO_pcm_format_parameters_t *format_parameters) {
	SDL_AudioFormat result = 0u;

	switch (format_parameters->bit_depth) {
	case 8:
		result = (format_parameters->is_signed != 0) ? AUDIO_S8 : AUDIO_U8;
		break;

	case 16:
		if (format_parameters->byte_order) {
			result = (format_parameters->is_signed != 0) ? AUDIO_S16MSB : AUDIO_U16MSB;
		} else {
			result = (format_parameters->is_signed != 0) ? AUDIO_S16LSB : AUDIO_U16LSB;
		}
		break;

	case 32:
		if (format_parameters->is_signed == 0) {
			fprintf(stderr, "32-bit unsigned audio format is not supported\n");
			break;
		} else {
			result = (format_parameters->byte_order != 0) ? AUDIO_S32MSB : AUDIO_S32LSB;
		}
		break;

	default:
		fprintf(stderr, "Invalid audio bit depth: %d\n", format_parameters->bit_depth);
		break;
	}

	return result;
}

void * AUDIO_malloc(size_t size) {
	void *result = BESTFIT_ALLOCATOR_allocate(&audio_heap_allocator, size);
	if (result == NULL) {
		fprintf(stderr, "%s: Failed allocating %u bytes\n", __FUNCTION__, size);
	}
	return result;
}

void AUDIO_free(void *ptr) {
	BESTFIT_ALLOCATOR_free(&audio_heap_allocator, ptr);
}
