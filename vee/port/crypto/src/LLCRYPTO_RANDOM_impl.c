/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 *
 */

#include <stdint.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <LLCRYPTO_RANDOM_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"

#define MICROEJ_LLCRYPTO_RANDOM_SUCCESS 1
#define MICROEJ_LLCRYPTO_RANDOM_ERROR   0

// No per-instance native resource to release: the OpenSSL RNG is global state.
static void llcrypto_random_close(void *native_id) {
	LLCRYPTO_UNUSED_PARAM(native_id);
}

int32_t LLCRYPTO_RANDOM_IMPL_init() {
	static bool random_seed_init = false;

	int32_t return_code = MICROEJ_LLCRYPTO_RANDOM_SUCCESS;
	int32_t native_id = 0;
	if (!random_seed_init) {
		// Seed with a poll
		/* The flag stays clear when the poll fails, so the next call seeds again instead of
		 * handing out bytes from a generator that was never seeded. */
		if (1 != RAND_poll()) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Cannot seed the random generator");
			return_code = MICROEJ_LLCRYPTO_RANDOM_ERROR;
		} else {
			random_seed_init = true;
		}
	}
	if (MICROEJ_LLCRYPTO_RANDOM_SUCCESS == return_code) {
		static int32_t native_ids = 1;

		native_id = native_ids;
		native_ids++;
		//The Java will register the returned native resource to be closed automatically when its
		// associated SecureRandom Java object is garbage collected.
		//This requires the returned SecureRandom native id be registered as native resource,
		// otherwise an IllegalArgumentException will be raised.
		//But in our case, as there is no SecureRandom native resource, we just register a fake
		// resource id and return it to prevent the java from complaining
		/* cppcheck-suppress misra-c2012-11.6 ; native_id is a synthetic counter, not a pointer to an
		 * object. The OpenSSL RNG is global state, so there is no resource to point at, but SNI still
		 * requires a registered handle. There is no type to convert to. */
		if (SNI_OK != SNI_registerResource((void *)native_id, llcrypto_random_close, NULL)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Can't register SNI native resource");
			return_code = MICROEJ_LLCRYPTO_RANDOM_ERROR;
		}
	}
	if (MICROEJ_LLCRYPTO_RANDOM_SUCCESS == return_code) {
		return_code = native_id;
	} else {
		return_code = SNI_ERROR;
	}
	return return_code;
}

int32_t LLCRYPTO_RANDOM_IMPL_get_close_id() {
	return sni_close_id(llcrypto_random_close);
}

void LLCRYPTO_RANDOM_IMPL_next_bytes(int32_t native_id, uint8_t *rnd, int32_t size) {
	LLCRYPTO_UNUSED_PARAM(native_id);
	if (!sni_array_contains_range(rnd, 0, size)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		int rc = RAND_bytes(rnd, size);
		if (1 != rc) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "RAND_bytes failed");
		}
	}
}

void LLCRYPTO_RANDOM_IMPL_set_seed(int32_t native_id, uint8_t *seed, int32_t size) {
	LLCRYPTO_UNUSED_PARAM(native_id);
	if (!sni_array_contains_range(seed, 0, size)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		// Redo seed
		RAND_seed(seed, size);
	}
}

void LLCRYPTO_RANDOM_IMPL_generate_seed(int32_t native_id, uint8_t *seed, int32_t size) {
	LLCRYPTO_UNUSED_PARAM(native_id);
	if (!sni_array_contains_range(seed, 0, size)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		int rc = RAND_bytes(seed, size);
		if (1 != rc) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "RAND_bytes failed");
		}
	}
}
