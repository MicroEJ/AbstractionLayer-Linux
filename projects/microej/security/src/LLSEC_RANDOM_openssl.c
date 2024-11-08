/*
 * C
 *
 * Copyright 2019-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

/**
 * @file
 * @brief MicroEJ Security low level API implementation for OpenSSL Library
 * @author MicroEJ Developer Team
 * @version 3.0.0
 * @date 20 August 2024
 */

#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <LLSEC_RANDOM_impl.h>
#include <sni.h>

#define MICROEJ_LLSECU_RANDOM_SUCCESS 1
#define MICROEJ_LLSECU_RANDOM_ERROR   0

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file.
static bool random_seed_init = false;

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file.
static int32_t native_ids = 1;

int32_t LLSEC_RANDOM_IMPL_init() {
	int32_t return_code = MICROEJ_LLSECU_RANDOM_SUCCESS;
	int32_t native_id;
	if (false == random_seed_init) {
		// Seed with a poll
		(void)RAND_poll();
		random_seed_init = true;
	}
	native_id = native_ids;
	native_ids++;
	//The Java will register the returned native resource to be closed automatically when its associated SecureRandom Java object is garbage collected.
	//This requires the returned SecureRandom native id be registered as native resource, otherwise an IllegalArgumentException will be raised.
	//But in our case, as there is no SecureRandom native resource, we just register a fake resource id and return it to prevent the java from complaining
	// cppcheck-suppress misra-c2012-11.6 // Cast for matching SNI_registerResource function signature
	if (SNI_registerResource((void*)native_id, (SNI_closeFunction)LLSEC_RANDOM_IMPL_close, NULL) != SNI_OK) {
		(void)SNI_throwNativeException(SNI_ERROR, "can't register sni native resource");
		LLSEC_RANDOM_IMPL_close(native_id);
		return_code = MICROEJ_LLSECU_RANDOM_ERROR;
	}
	if (MICROEJ_LLSECU_RANDOM_SUCCESS == return_code) {
		return_code = native_id;
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

void LLSEC_RANDOM_IMPL_close(int32_t native_id) {
	//no-op
	(void)native_id;
}

int32_t LLSEC_RANDOM_IMPL_get_close_id() {
	return (int32_t)LLSEC_RANDOM_IMPL_close;
}

void LLSEC_RANDOM_IMPL_next_bytes(int32_t native_id, uint8_t* rnd, int32_t size) {
	(void)native_id;
	int rc = RAND_bytes(rnd, size);
	if (1 != rc) {
		(void)SNI_throwNativeException(rc, "RAND_bytes failed");
	}
}

// cppcheck-suppress constParameterPointer // SNI type conflict
void LLSEC_RANDOM_IMPL_set_seed(int32_t native_id, uint8_t* seed, int32_t size) {
	(void)native_id;
	// Redo seed
	RAND_seed(seed, size);
}

// cppcheck-suppress constParameterPointer // SNI type conflict
void LLSEC_RANDOM_IMPL_generate_seed(int32_t native_id, uint8_t* seed, int32_t size) {
	(void)native_id;
	int rc = RAND_bytes(seed, size);
	if (1 != rc) {
		(void)SNI_throwNativeException(rc, "RAND_bytes failed");
	}
}
