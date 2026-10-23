/*
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include "LLAUDIO_SINK_impl.h"

#include "LLAUDIO_common_sdl2.h"
#include "sni.h"
#include "ring_buffer.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

VEEPORT_LOGGER_DEFINE_MODULE(LLAUDIO_LOG_MODULE_NAME, LLAUDIO_LOG_LEVEL)

// -------------
// Private types
// -------------

struct audio_track {
	SDL_AudioStream *decoder_stream;
	struct ring_buffer input_buffer;
	pthread_mutex_t mutex;
	pthread_cond_t condition;
};

// -----------------
// Private variables
// -----------------

static SDL_AudioDeviceID audio_device_id = 0;
static SDL_AudioSpec playback_spec = { 0 };

static struct audio_track *audio_track = NULL;

// -----------------
// Private functions
// -----------------

static void _audio_device_callback(void *userdata, Uint8 *stream, int len) {
	(void)userdata;
	static const size_t tmp_buffer_size = 512;

	memset(stream, 0, len);
	if (audio_track == NULL) {
		return;
	}

	size_t available = SDL_AudioStreamAvailable(audio_track->decoder_stream);

	if (available < (size_t)len) {
		char tmp[tmp_buffer_size];
		pthread_mutex_lock(&audio_track->mutex);
		while (RING_available(&audio_track->input_buffer) > 0) {
			size_t read = RING_get(&audio_track->input_buffer, tmp, tmp_buffer_size);
			SDL_AudioStreamPut(audio_track->decoder_stream, tmp, read);
		}
		pthread_cond_broadcast(&audio_track->condition);
		pthread_mutex_unlock(&audio_track->mutex);
	}

	int read = SDL_AudioStreamGet(audio_track->decoder_stream, stream, len);
	if (read == -1) {
		VEEPORT_LOGGER_LOG_ERR("cannot read from the audio stream: %s", SDL_GetError());
	} else {
		SDL_PauseAudioDevice(audio_device_id, false);
		if (read < len) {
			VEEPORT_LOGGER_LOG_WRN("buffer underrun");
		}
	}
}

static void _init_audio_routine() {
	AUDIO_init();

	const SDL_AudioSpec desired = {
		.freq = AUDIO_PLAYBACK_DESIRED_DEVICE_FREQUENCY,
		.format = AUDIO_PLAYBACK_DESIRED_DEVICE_FORMAT,
		.samples = AUDIO_PLAYBACK_DESIRED_DEVICE_SAMPLES,
		.callback = _audio_device_callback,
		.userdata = NULL,
		.channels = AUDIO_PLAYBACK_DESIRED_DEVICE_CHANNELS
	};

	audio_device_id = SDL_OpenAudioDevice(NULL, false, &desired, &playback_spec, 0);
	if (audio_device_id == 0) {
		VEEPORT_LOGGER_LOG_ERR("cannot initialize the playback device: %s", SDL_GetError());
		exit(1);
	}
}

static void _init_audio() {
	static pthread_once_t initialization_control = PTHREAD_ONCE_INIT;
	pthread_once(&initialization_control, _init_audio_routine);
}

static bool _LLAUDIO_SINK_IMPL_waitForBufferFlushed_continuation(uint32_t track_handle, uint32_t timeout);

// ----------------
// Public functions
// ----------------

uint32_t LLAUDIO_SINK_IMPL_open(const char *format_encoding, const int32_t *format_parameters_array,
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

	SDL_AudioStream *decoder_stream = NULL;

	if (strcmp(format_encoding, "PCM") == 0) {
		SDL_AudioFormat src_format = AUDIO_get_pcm_format(format_parameters);
		if (SDL_AUDIO_BITSIZE(src_format) == 0) {
			VEEPORT_ERRORS_throw_runtime_exception(LLAUDIO_ERROR_INVALID_FORMAT_PARAMETERS);
			goto invalid_format_parameters;
		}

		decoder_stream = SDL_NewAudioStream(src_format,
		                                    format_parameters->num_channels,
		                                    format_parameters->sample_rate,
		                                    playback_spec.format,
		                                    playback_spec.channels,
		                                    playback_spec.freq);
		if (decoder_stream == NULL) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLAUDIO_ERROR_FAILED_CREATING_DECODER_STREAM, "%s",
			                                              SDL_GetError());
			goto failed_creating_audio_stream;
		}

		result = AUDIO_malloc(sizeof(struct audio_track));
		if (result == NULL) {
			VEEPORT_ERRORS_throw_caught_exception(LLAUDIO_ERROR_HEAP_FULL_ALLOCATING_TRACK);
			goto audio_heap_full_allocating_track;
		}

		result->decoder_stream = decoder_stream;
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
		RING_init(&result->input_buffer, begin, end);
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
	SDL_FreeAudioStream(decoder_stream);

failed_creating_audio_stream:
invalid_format_parameters:
audio_format_not_supported:
audio_track_already_open:

end:
	SDL_UnlockAudioDevice(audio_device_id);
	return (uint32_t)result;
}

void LLAUDIO_SINK_IMPL_close(uint32_t track_handle) {
	SDL_LockAudioDevice(audio_device_id);

	struct audio_track *track = (struct audio_track *)track_handle;
	assert(track == audio_track);
	if (track == NULL) {
		return;
	}

	SDL_PauseAudioDevice(audio_device_id, true);
	SDL_FreeAudioStream(track->decoder_stream);
	AUDIO_free(track->input_buffer.begin);
	pthread_cond_destroy(&track->condition);
	pthread_mutex_destroy(&track->mutex);
	AUDIO_free(track);
	audio_track = NULL;

	SDL_UnlockAudioDevice(audio_device_id);
}

void LLAUDIO_SINK_IMPL_setVolume(uint32_t track_handle, float gain) {
	(void)track_handle;
	(void)gain;
	/* Not implemented yet. The API for audio track controls is to be redesigned. */
}

int32_t LLAUDIO_SINK_IMPL_writeBuffer(uint32_t track_handle, const uint8_t *array, uint32_t offset, uint32_t size,
                                      uint32_t timeout) {
	(void)timeout; // TODO Honor the timeout

	struct audio_track *track = (struct audio_track *)track_handle;
	assert(track == audio_track);

	pthread_mutex_lock(&track->mutex);
	size_t written = 0u;
	while (written < size) {
		while (RING_free(&track->input_buffer) == 0u) {
			pthread_cond_wait(&track->condition, &track->mutex);
		}
		written += RING_put(&track->input_buffer, array + offset + written, size - written);
	}
	pthread_mutex_unlock(&track->mutex);

	return written;
}

bool LLAUDIO_SINK_IMPL_waitForBufferFlushed(uint32_t track_handle, uint32_t timeout) {
	struct audio_track *track = (struct audio_track *)track_handle;
	assert(track == audio_track);

	SDL_AudioStreamFlush(track->decoder_stream);

	pthread_mutex_lock(&track->mutex);
	bool available = RING_available(&track->input_buffer) > 0 || SDL_AudioStreamAvailable(track->decoder_stream) > 0;
	pthread_mutex_unlock(&track->mutex);

	if (available) {
		SNI_suspendCurrentJavaThreadWithCallback(timeout,
		                                         (SNI_callback)_LLAUDIO_SINK_IMPL_waitForBufferFlushed_continuation,
		                                         track);
	}

	return !available;
}

static bool _LLAUDIO_SINK_IMPL_waitForBufferFlushed_continuation(uint32_t track_handle, uint32_t timeout) {
	(void)track_handle;
	(void)timeout;
	struct audio_track *track = NULL;
	SNI_getCallbackArgs((void **)&track, NULL);
	assert(track != NULL);

	pthread_mutex_lock(&track->mutex);
	bool available = RING_available(&track->input_buffer) > 0 || SDL_AudioStreamAvailable(track->decoder_stream) > 0;
	pthread_mutex_unlock(&track->mutex);

	return !available;
}
