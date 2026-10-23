/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <LLCRYPTO_KEY_GENERATOR_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

#define BITS_PER_BYTE (8)

/* The AES key sizes of FIPS 197. No other symmetric algorithm is generated here. */
#define AES_KEY_SIZE_128_BITS (128)
#define AES_KEY_SIZE_192_BITS (192)
#define AES_KEY_SIZE_256_BITS (256)

/* The largest key this module produces, in bytes. */
#define MAX_KEY_LENGTH_BYTES (AES_KEY_SIZE_256_BITS / BITS_PER_BYTE)

/* RAND_bytes returns 1 on success, unlike most of OpenSSL. */
#define RAND_BYTES_SUCCESS (1)

typedef struct {
	char *name;
} LLCRYPTO_KEY_GENERATOR_algorithm;

int32_t LLCRYPTO_KEY_GENERATOR_IMPL_get_algorithm_id(uint8_t *algorithm_name) {
	/* Static so that its entries keep a stable address: an algorithm id is the address of the entry, which is the
	 * same contract the key pair generator uses. */
	static const LLCRYPTO_KEY_GENERATOR_algorithm available_algorithms[1] = {
		{ .name = "AES" }
	};

	VEEPORT_LOGGER_LOG_DBG("");

	int32_t return_code = LLCRYPTO_ERROR;
	size_t nb_algorithms = sizeof(available_algorithms) / sizeof(available_algorithms[0]);
	const LLCRYPTO_KEY_GENERATOR_algorithm *algorithm = &available_algorithms[0];

	for (size_t i = 0; i < nb_algorithms; i++) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			return_code = (int32_t)algorithm;
			break;
		}
		algorithm++;
	}

	return return_code;
}

uint8_t LLCRYPTO_KEY_GENERATOR_IMPL_is_key_size_supported(int32_t algorithm_id, int32_t key_size) {
	VEEPORT_LOGGER_LOG_DBG("key_size=%d", key_size);

	uint8_t is_supported = JFALSE;

	/* AES is the only algorithm this module answers for, so the size alone decides. */
	if (LLCRYPTO_ERROR != algorithm_id) {
		if ((AES_KEY_SIZE_128_BITS == key_size) || (AES_KEY_SIZE_192_BITS == key_size)
		    || (AES_KEY_SIZE_256_BITS == key_size)) {
			is_supported = JTRUE;
		}
	}

	return is_supported;
}

int32_t LLCRYPTO_KEY_GENERATOR_IMPL_generate_key(int32_t algorithm_id, int32_t key_size) {
	VEEPORT_LOGGER_LOG_DBG("key_size=%d", key_size);

	int32_t return_code = SNI_ERROR;
	uint8_t raw_key[MAX_KEY_LENGTH_BYTES] = { 0 };

	if ((uint8_t)JTRUE != LLCRYPTO_KEY_GENERATOR_IMPL_is_key_size_supported(algorithm_id, key_size)) {
		int32_t sni_rc = SNI_throwNativeException(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Unsupported key size");
		LLCRYPTO_ASSERT(SNI_OK == sni_rc);
	} else {
		const LLCRYPTO_KEY_GENERATOR_algorithm *algorithm =
			(const LLCRYPTO_KEY_GENERATOR_algorithm *)algorithm_id;
		int32_t key_length_bytes = key_size / BITS_PER_BYTE;

		int rc = RAND_bytes(raw_key, key_length_bytes);
		if (RAND_BYTES_SUCCESS != rc) {
			VEEPORT_LOGGER_LOG_ERR("RAND_bytes failed");
			int32_t sni_rc = SNI_throwNativeException(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                          "Cannot generate the key material");
			LLCRYPTO_ASSERT(SNI_OK == sni_rc);
		} else {
			struct llcrypto_key *key = llcrypto_key_from_secret_key(raw_key, (size_t)key_length_bytes,
			                                                        (const uint8_t *)algorithm->name);
			if (NULL == key) {
				int32_t sni_rc = SNI_throwNativeException(LLCRYPTO_OOM_EXCEPTION, "Cannot allocate the key structure");
				LLCRYPTO_ASSERT(SNI_OK == sni_rc);
			} else {
				return_code = (int32_t)key;
			}
		}

		/* The material has been copied into the key, so the stack copy is dead. Wipe it rather than leaving a
		 * second copy of a secret key in a frame that later calls reuse. */
		OPENSSL_cleanse(raw_key, sizeof(raw_key));
	}

	return return_code;
}
