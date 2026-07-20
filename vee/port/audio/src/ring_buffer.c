/*
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include "ring_buffer.h"

#include <assert.h>
#include <string.h>

#include <stdio.h>

void RING_init(struct ring_buffer *buffer, void *begin, void *end) {
	*buffer = (struct ring_buffer) {
		.begin = begin,
		.end = end,
		.read = begin,
		.write = begin
	};
}

size_t RING_size(const struct ring_buffer *buffer) {
	return (char *)(buffer->end) - (char *)(buffer->begin) - 1u;
}

size_t RING_available(const struct ring_buffer *buffer) {
	if ((char *)(buffer->write) >= (char *)(buffer->read)) {
		return (char *)(buffer->write) - (char *)(buffer->read);
	} else {
		return RING_size(buffer) - ((char *)(buffer->read) - (char *)(buffer->write)) + 1u;
	}
}

size_t RING_free(struct ring_buffer *buffer) {
	return RING_size(buffer) - RING_available(buffer);
}

size_t RING_put(struct ring_buffer *buffer, const void * const data, const size_t size) {
	const size_t to_write = size <= RING_free(buffer) ? size : RING_free(buffer);
	assert(to_write <= RING_free(buffer));

	char *dst = (char *)buffer->write;
	size_t written = 0;

	while (dst + to_write - written >= (char *)(buffer->end)) {
		const size_t writing = (char *)(buffer->end) - dst;
		memcpy(dst, (const char *)data + written, writing);
		written += writing;
		dst = (char *)buffer->begin;
	}

	memcpy((void *)dst, (const char *)data + written, to_write - written);
	dst += to_write - written;
	written += to_write - written;

	buffer->write = (void *)dst;

	return written;
}

size_t RING_get(struct ring_buffer *buffer, void * const destination, const size_t size) {
	const size_t to_read = size <= RING_available(buffer) ? size : RING_available(buffer);
	assert(to_read <= RING_available(buffer));

	char *src = (char *)buffer->read;
	size_t read = 0u;

	while (src + to_read - read >= (char *)buffer->end) {
		const size_t reading = (char *)(buffer->end) - src;
		memcpy((char *)destination + read, src, reading);
		read += reading;
		src = buffer->begin;
	}

	memcpy((char *)destination + read, src, to_read - read);
	src += to_read - read;
	read += to_read - read;

	buffer->read = (void *)src;

	return read;
}
