/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stddef.h>
#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <LLCRYPTO_CONSTANTS.h>

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_utils.h"

struct curve_alias {
	const char *name;
	int nid;
};

void *llcrypto_calloc(size_t nmemb, size_t size) {
	/* cppcheck-suppress misra-c2012-21.3 ; The Java layer asks the module for crypto resources whose size is known
	 * only at run time, so the module cannot avoid dynamic allocation. OpenSSL allocates dynamically throughout, so
	 * replacing the standard allocator here would not remove the risks Directive 4.12 describes. */
	return calloc(nmemb, size);
}

void llcrypto_free(void *ptr) {
	/* cppcheck-suppress misra-c2012-21.3 ; Releases a block from llcrypto_calloc(), so it must be the deallocator
	 * that matches the allocator that produced it. */
	free(ptr);
}

void llcrypto_unregister_and_close(void *resource, SNI_closeFunction close_function) {
	if (SNI_OK != SNI_unregisterResource(resource, close_function)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Can't unregister SNI native resource");
	} else {
		close_function(resource);
	}
}

int llcrypto_curve_name_to_nid(const char *name) {
	/* Common Java curve name aliases that OBJ_txt2nid may not recognize. */
	static const struct curve_alias curve_aliases[] = {
		{ "secp256r1", NID_X9_62_prime256v1 },
		{ "prime256v1", NID_X9_62_prime256v1 },
		{ "P-256", NID_X9_62_prime256v1 },
		{ "secp384r1", NID_secp384r1 },
		{ "P-384", NID_secp384r1 },
		{ "secp521r1", NID_secp521r1 },
		{ "P-521", NID_secp521r1 },
	};

	int nid = OBJ_txt2nid(name);
	if (NID_undef == nid) {
		for (size_t i = 0; i < (sizeof(curve_aliases) / sizeof(curve_aliases[0])); i++) {
			if (0 == strcmp(name, curve_aliases[i].name)) {
				nid = curve_aliases[i].nid;
				break;
			}
		}
	}
	return nid;
}
