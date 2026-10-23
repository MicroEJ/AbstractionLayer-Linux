/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

#ifndef LLDEVICE_ID_UTIL_H
#define LLDEVICE_ID_UTIL_H

/**
 * @file
 * @brief Byte-buffer utilities used to build the device ID on Linux.
 * @author MicroEJ Developer Team
 */

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Reads the whole content of a file into a buffer.
 *
 * Reads at most @p buffer_size bytes, so a longer file is truncated. Retries an
 * interrupted read and a partial read, which the pseudo-files under /proc report.
 *
 * @param path the path of the file to read.
 * @param buffer the buffer to fill.
 * @param buffer_size the size of @p buffer in bytes, zero or more.
 * @return the number of bytes read, a negative value when the file cannot be opened or read.
 */
int32_t lldevice_id_util_read_file(const char *path, uint8_t *buffer, int32_t buffer_size);

/**
 * @brief Removes every NUL byte from a buffer, then removes its leading and trailing whitespace.
 *
 * Modifies @p buffer in place. The remaining bytes start at index zero.
 *
 * @param buffer the buffer to trim.
 * @param length the number of valid bytes in @p buffer, zero or more.
 * @return the number of bytes left in @p buffer.
 */
int32_t lldevice_id_util_trim(uint8_t *buffer, int32_t length);

/**
 * @brief Tells whether every byte of a buffer is zero.
 *
 * @param buffer the buffer to test.
 * @param length the number of bytes to test, zero or more.
 * @return true when every byte is zero or when @p length is zero, false otherwise.
 */
bool lldevice_id_util_is_all_zero(const uint8_t *buffer, int32_t length);

/**
 * @brief Parses a hexadecimal text into bytes.
 *
 * Accepts both letter cases. Writes nothing when @p text holds a character that is
 * not a hexadecimal digit, or when @p text_length is not twice @p destination_length.
 *
 * @param text the hexadecimal characters to parse.
 * @param text_length the number of characters in @p text.
 * @param destination the buffer to fill with the parsed bytes.
 * @param destination_length the exact number of bytes to parse.
 * @return true when every character was parsed, false otherwise.
 */
bool lldevice_id_util_parse_hex(const uint8_t *text, int32_t text_length, uint8_t *destination,
                                int32_t destination_length);

/**
 * @brief Derives an identifier from the machine ID of the host.
 *
 * Computes an HMAC-SHA256 keyed with @p machine_id over an application identifier private
 * to this abstraction layer, then keeps the first @p destination_length bytes. systemd asks
 * that the machine ID never be exposed as it is stored, so this derivation is what the
 * device ID carries.
 *
 * @param machine_id the machine ID bytes, used as the HMAC key.
 * @param machine_id_length the number of bytes in @p machine_id.
 * @param destination the buffer to fill with the derived identifier.
 * @param destination_length the number of bytes to derive, from 1 to 32.
 * @return true on success, false when @p destination_length is out of range or when the
 *         HMAC-SHA256 computation fails.
 */
bool lldevice_id_util_derive_id_from_machine_id(const uint8_t *machine_id, int32_t machine_id_length,
                                                uint8_t *destination, int32_t destination_length);

#ifdef __cplusplus
}
#endif

#endif // LLDEVICE_ID_UTIL_H
