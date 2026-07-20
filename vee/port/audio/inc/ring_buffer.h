/*
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/**
 * @brief Structure defining a single-producer, single-consumer, arbitrary data ring buffer.
 *
 * The variables in this structure should not be accessed directly. Use the functions defined in this header instead.
 *
 * This ring buffer is not thread-safe. The user must ensure proper synchronization calls are used when using this
 * structure.
 *
 * ### Implementation details:
 *
 * This ring buffer works by moving two pointers forward and wrapping over a provided memory array. One buffer (`write`)
 * will advance with each byte written in the array, while the other pointer (`read`), will advance with each byte
 * consumed.
 *
 * As a result, the actual data stored in the ring buffer ranges from `read` to one byte before `write` (wrapping over
 * the array if `write` is before `read`).
 *
 * Special cases:
 *
 *   - If `read == write`, then the buffer is empty.
 *
 *   - If `write == read - 1`, then the buffer is full. Note that due to this condition and to be able to distinguish
 *     with the previous case (when the buffer is empty), the buffer can only hold one less byte than the size of the
 *     underlying array.
 */
struct ring_buffer {
	/// @brief Pointer to the beginning of the ring buffer.
	void *begin;
	/// @brief Pointer one byte past the end of the ring buffer.
	void *end;
	/// @brief Pointer to the first byte that has not yet been consumed.
	void *read;
	/**
	 * @brief Pointer to the location where the first byte of the next write operation will be written.
	 *
	 * This is one byte past the end of the available bytes to be written.
	 */
	void *write;
};

/**
 * @brief Initializes `buffer` with the provided underlying array.
 *
 * The underlying array must not be deallocated while the ring buffer is alive.
 *
 * There is no matching destruction function. Once `buffer` is no longer needed, the caller may freely drop it from
 * memory. Afterwards, the underlying array may freely be deallocated.
 *
 * Note that due to implementation details, the ring buffer can only hold one less byte than the length of the
 * underlying array. The caller must adjust the array size in consequence if a specific amount of data needs to be
 * stored.
 *
 * @param buffer an unitialized ring buffer structure to be bound to the provided array
 * @param begin pointer to the first byte of the underlying array
 * @param end pointer to one byte past the end of the underlying array
 */
void RING_init(struct ring_buffer *buffer, void *begin, void *end);

/**
 * @brief Returns the maximum amount of bytes the buffer can hold.
 *
 * Note that due to implementation details, the ring buffer can only hold one less byte than the length of the
 * underlying array.
 *
 * @param buffer a ring buffer
 */
size_t RING_size(const struct ring_buffer *buffer);

/**
 * @brief Returns the total amount of bytes available to be read.
 *
 * @param buffer a ring buffer
 */
size_t RING_available(const struct ring_buffer *buffer);

/**
 * @brief Returns the maximum amount of bytes that can be written in this buffer.
 *
 * @param buffer a ring buffer
 */
size_t RING_free(struct ring_buffer *buffer);

/**
 * @brief Stores up to `size` bytes in the ring buffer.
 *
 * @param buffer the ring buffer that will receive the data
 * @param data pointer to the first byte of the data to copy
 * @param size the maximum amount of bytes to read
 * @return the actual amount of bytes written. Due to the size limit of the ring buffer, the number of bytes written may
 * be less than `size`.
 */
size_t RING_put(struct ring_buffer *buffer, const void *data, size_t size);

/**
 * @brief Consumes up to `size` bytes from the ring buffer.
 *
 * @param buffer the ring buffer from which the data will be consumed
 * @param data pointer to the first byte of the array in which the read data will be copied
 * @param size the maximum amount of bytes to consume
 * @return the actual number of bytes copied. This may be less than `size` if the amount of bytes available in the ring
 * buffer is less than the size of the output array.
 */
size_t RING_get(struct ring_buffer *buffer, void *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* ifndef RING_BUFFER_H */
