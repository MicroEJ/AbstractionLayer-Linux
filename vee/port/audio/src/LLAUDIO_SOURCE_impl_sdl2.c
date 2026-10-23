/*
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include "LLAUDIO_SOURCE_impl.h"

#include "LLAUDIO_common_sdl2.h"
#include "sni.h"
#include "ring_buffer.h"

#include <assert.h>
#include <string.h>
#include <pthread.h>

VEEPORT_LOGGER_DEFINE_MODULE(LLAUDIO_LOG_MODULE_NAME, LLAUDIO_LOG_LEVEL)

// -------------
// Private types
// -------------

struct audio_track {
	SDL_AudioStream *encoder_stream;
	struct ring_buffer output_buffer;
	pthread_mutex_t mutex;
	pthread_cond_t condition;
};

// -----------------
// Private variables
// -----------------

static SDL_AudioDeviceID audio_device_id = 0;
static SDL_AudioSpec capture_spec = { 0 };

static struct audio_track *audio_track = NULL;

// -----------------
// Private functions
// -----------------

static void _audio_device_callback(void *userdata, Uint8 *stream, int len) {
	(void)userdata;
	static const size_t tmp_buffer_size = 512;

	if (audio_track == NULL) {
		return;
	}

	if (SDL_AudioStreamPut(audio_track->encoder_stream, stream, len) != 0) {
		VEEPORT_LOGGER_LOG_ERR("cannot write into the audio stream: %s", SDL_GetError());
	}

	while (true) {
		char tmp[tmp_buffer_size];
		SDL_AudioStreamFlush(audio_track->encoder_stream);
		int read = SDL_AudioStreamGet(audio_track->encoder_stream, tmp, tmp_buffer_size);
		if (read < 0) {
			VEEPORT_LOGGER_LOG_ERR("cannot read from the audio stream: %s", SDL_GetError());
		} else if (read == 0) {
			break;
		}
		pthread_mutex_lock(&audio_track->mutex);
		if (RING_put(&audio_track->output_buffer, tmp, read) == 0) {
			VEEPORT_LOGGER_LOG_ERR("cannot write into the output buffer");
		} else {
			pthread_cond_broadcast(&audio_track->condition);
		}
		pthread_mutex_unlock(&audio_track->mutex);
	}
}

static void _init_audio_routine() {
	AUDIO_init();

	const SDL_AudioSpec desired = {
		.freq = AUDIO_CAPTURE_DESIRED_DEVICE_FREQUENCY,
		.format = AUDIO_CAPTURE_DESIRED_DEVICE_FORMAT,
		.samples = AUDIO_CAPTURE_DESIRED_DEVICE_SAMPLES,
		.callback = _audio_device_callback,
		.userdata = NULL,
		.channels = AUDIO_CAPTURE_DESIRED_DEVICE_CHANNELS
	};

	audio_device_id = SDL_OpenAudioDevice(NULL, true, &desired, &capture_spec, 0);
	if (audio_device_id == 0) {
		VEEPORT_LOGGER_LOG_ERR("cannot initialize the capture device: %s", SDL_GetError());
		exit(1);
	}
}

static void _init_audio() {
	static pthread_once_t initialization_control = PTHREAD_ONCE_INIT;
	pthread_once(&initialization_control, _init_audio_routine);
}

// ----------------
// Public functions
// ----------------

uint32_t LLAUDIO_SOURCE_IMPL_open(const char *format_encoding, const int32_t *format_parameters_array,
                                  uint32_t buffer_size) {
	struct audio_track *result = NULL;

	const LLAUDIO_pcm_format_parameters_t *format_parameters =
		(const LLAUDIO_pcm_format_parameters_t *)format_parameters_array;

	_init_audio();

	SDL_LockAudioDevice(audio_device_id);

	if (audio_track != NULL) {
		VEEPORT_ERRORS_throw_caught_exception(LLAUDIO_ERROR_TRACK_ALREADY_OPEN);
		goto audio_track_already_open;
	}

	SDL_AudioStream *encoder_stream = NULL;

	if (strcmp(format_encoding, "PCM") == 0) {
		SDL_AudioFormat dst_format = AUDIO_get_pcm_format(format_parameters);
		if (SDL_AUDIO_BITSIZE(dst_format) == 0) {
			VEEPORT_ERRORS_throw_runtime_exception(LLAUDIO_ERROR_INVALID_FORMAT_PARAMETERS);
			goto invalid_format_parameters;
		}

		encoder_stream = SDL_NewAudioStream(capture_spec.format,
		                                    capture_spec.channels,
		                                    capture_spec.freq,
		                                    dst_format,
		                                    format_parameters->num_channels,
		                                    format_parameters->sample_rate);
		if (encoder_stream == NULL) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLAUDIO_ERROR_FAILED_CREATING_ENCODER_STREAM, "%s",
			                                              SDL_GetError());
			goto failed_creating_encoder_stream;
		}

		result = AUDIO_malloc(sizeof(struct audio_track));
		if (result == NULL) {
			VEEPORT_ERRORS_throw_caught_exception(LLAUDIO_ERROR_HEAP_FULL_ALLOCATING_TRACK);
			goto audio_heap_full_allocating_track;
		}

		result->encoder_stream = encoder_stream;
		if (pthread_mutex_init(&result->mutex, NULL) != 0) {
			VEEPORT_ERRORS_throw_runtime_exception(LLAUDIO_ERROR_FAILED_INITIALIZING_MUTEX);
			goto failed_initializing_mutex;
		}
		if (pthread_cond_init(&result->condition, NULL) != 0) {
			VEEPORT_ERRORS_throw_runtime_exception(LLAUDIO_ERROR_FAILED_INITIALIZING_CONDITION);
			goto failed_initializing_condition;
		}

		char *begin = AUDIO_malloc(buffer_size + 1); // We allocated buffer_size + 1 bytes as the ring buffer can only
		                                             // store one less byte than the allocated array.
		if (begin == NULL) {
			VEEPORT_ERRORS_throw_caught_exception(LLAUDIO_ERROR_HEAP_FULL_ALLOCATING_RING_BUFFER);
			goto audio_heap_full_allocating_ring_buffer;
		}
		char *end = begin + buffer_size + 1;
		RING_init(&result->output_buffer, begin, end);
		memset(begin, 0, end - begin);
	} else {
		VEEPORT_LOGGER_LOG_ERR("unsupported audio track format %.16s", format_encoding);
		VEEPORT_ERRORS_throw_caught_exception(LLAUDIO_ERROR_FORMAT_NOT_SUPPORTED);
		goto audio_format_not_supported;
	}

	audio_track = result;
	SDL_PauseAudioDevice(audio_device_id, false);

	goto end;

audio_heap_full_allocating_ring_buffer:
	pthread_cond_destroy(&result->condition);

failed_initializing_condition:
	pthread_mutex_destroy(&result->mutex);

failed_initializing_mutex:
	AUDIO_free(result);
	result = NULL;

audio_heap_full_allocating_track:
	SDL_FreeAudioStream(encoder_stream);

failed_creating_encoder_stream:
invalid_format_parameters:
audio_format_not_supported:
audio_track_already_open:

end:
	SDL_UnlockAudioDevice(audio_device_id);
	return (uint32_t)result;
}

void LLAUDIO_SOURCE_IMPL_close(uint32_t record_handle) {
	SDL_LockAudioDevice(audio_device_id);

	struct audio_track *track = (struct audio_track *)record_handle;
	assert(track == audio_track);
	if (track == NULL) {
		return;
	}

	SDL_PauseAudioDevice(audio_device_id, true);
	SDL_FreeAudioStream(track->encoder_stream);
	AUDIO_free(track->output_buffer.begin);
	pthread_cond_destroy(&track->condition);
	pthread_mutex_destroy(&track->mutex);
	AUDIO_free(track);
	audio_track = NULL;

	SDL_UnlockAudioDevice(audio_device_id);
}

int32_t LLAUDIO_SOURCE_IMPL_readBuffer(uint32_t record_handle, uint8_t *array, uint32_t offset, uint32_t size,
                                       uint32_t timeout) {
	(void)timeout; // TODO Honor the timeout

	struct audio_track *track = (struct audio_track *)record_handle;
	assert(track == audio_track);

	pthread_mutex_lock(&track->mutex);
	while (RING_available(&track->output_buffer) == 0u) {
		pthread_cond_wait(&track->condition, &track->mutex);
	}
	size_t read = RING_get(&track->output_buffer, array + offset, size);
	pthread_mutex_unlock(&track->mutex);

	return read;
}
