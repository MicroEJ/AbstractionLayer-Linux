/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief Byte-buffer utilities used to build the device ID on Linux.
 * @author MicroEJ Developer Team
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "LLDEVICE_id_util.h"

#ifdef __cplusplus
extern "C" {
#endif

// Identifier keying the derivation of a device ID from the machine ID. Changing it changes the
// ID every host reports that has neither a device tree serial number nor a hardware address.
#define DEVICE_ID_APPLICATION_KEY       "com.microej.vee.device.getid"

#define HMAC_SHA256_SIZE                (32)
#define HEX_DIGITS_PER_BYTE             (2)
#define HEX_DIGIT_BITS                  (4)
#define HEX_LETTER_VALUE                (10)

#define ERROR_READ_FILE                 (-1)

static int32_t get_hex_digit_value(uint8_t character);

int32_t lldevice_id_util_read_file(const char *path, uint8_t *buffer, int32_t buffer_size) {
	int32_t result = ERROR_READ_FILE;

	int file = open(path, O_RDONLY);
	if (0 <= file) {
		int32_t read_total = 0;
		bool reading = true;
		while (reading && (read_total < buffer_size)) {
			ssize_t read_size = read(file, &buffer[read_total], (size_t)(buffer_size - read_total));
			if (0 > read_size) {
				if (EINTR != errno) {
					read_total = ERROR_READ_FILE;
					reading = false;
				}
			} else if (0 == read_size) {
				reading = false;
			} else {
				read_total += (int32_t)read_size;
			}
		}
		result = read_total;
		(void)close(file);
	}

	return result;
}

int32_t lldevice_id_util_trim(uint8_t *buffer, int32_t length) {
	int32_t compacted_length = 0;
	for (int32_t index = 0; index < length; ++index) {
		if ('\0' != buffer[index]) {
			buffer[compacted_length] = buffer[index];
			++compacted_length;
		}
	}

	int32_t start = 0;
	while ((start < compacted_length) && (0 != isspace((int)buffer[start]))) {
		++start;
	}

	int32_t end = compacted_length;
	while ((end > start) && (0 != isspace((int)buffer[end - 1]))) {
		--end;
	}

	int32_t trimmed_length = end - start;
	if (0 < start) {
		(void)memmove(buffer, &buffer[start], (size_t)trimmed_length);
	}

	return trimmed_length;
}

bool lldevice_id_util_is_all_zero(const uint8_t *buffer, int32_t length) {
	bool all_zero = true;

	for (int32_t index = 0; index < length; ++index) {
		if (0 != buffer[index]) {
			all_zero = false;
			break;
		}
	}

	return all_zero;
}

bool lldevice_id_util_parse_hex(const uint8_t *text, int32_t text_length, uint8_t *destination,
                                int32_t destination_length) {
	bool parsed = ((0 < destination_length) && (text_length == (destination_length * HEX_DIGITS_PER_BYTE)));

	for (int32_t index = 0; parsed && (index < destination_length); ++index) {
		int32_t high_digit = get_hex_digit_value(text[index * HEX_DIGITS_PER_BYTE]);
		int32_t low_digit = get_hex_digit_value(text[(index * HEX_DIGITS_PER_BYTE) + 1]);
		if ((0 > high_digit) || (0 > low_digit)) {
			parsed = false;
		} else {
			destination[index] = (uint8_t)(((uint32_t)high_digit << HEX_DIGIT_BITS) | (uint32_t)low_digit);
		}
	}

	return parsed;
}

bool lldevice_id_util_derive_id_from_machine_id(const uint8_t *machine_id, int32_t machine_id_length,
                                                uint8_t *destination, int32_t destination_length) {
	uint8_t digest[HMAC_SHA256_SIZE] = { 0 };
	unsigned int digest_length = 0;
	bool derived = false;

	if ((0 < destination_length) && (HMAC_SHA256_SIZE >= destination_length)) {
		const uint8_t *digest_result = HMAC(EVP_sha256(), machine_id, (int)machine_id_length,
		                                    (const uint8_t *)DEVICE_ID_APPLICATION_KEY,
		                                    sizeof(DEVICE_ID_APPLICATION_KEY) - 1U, digest, &digest_length);
		if ((NULL != digest_result) && (HMAC_SHA256_SIZE == digest_length)) {
			(void)memcpy(destination, digest, (size_t)destination_length);
			derived = true;
		}
	}

	OPENSSL_cleanse(digest, sizeof(digest));

	return derived;
}

/**
 * @brief Gives the value of a hexadecimal digit.
 *
 * @param character the character to convert.
 * @return the value of the digit, a negative value when the character is not a hexadecimal digit.
 */
static int32_t get_hex_digit_value(uint8_t character) {
	int32_t value = -1;

	if (('0' <= character) && ('9' >= character)) {
		value = (int32_t)character - (int32_t)'0';
	} else if (('a' <= character) && ('f' >= character)) {
		value = ((int32_t)character - (int32_t)'a') + HEX_LETTER_VALUE;
	} else if (('A' <= character) && ('F' >= character)) {
		value = ((int32_t)character - (int32_t)'A') + HEX_LETTER_VALUE;
	} else {
		value = -1;
	}

	return value;
}

#ifdef __cplusplus
}
#endif
