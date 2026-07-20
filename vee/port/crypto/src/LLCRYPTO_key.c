/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include "LLCRYPTO_key.h"
#include "LLCRYPTO_configuration.h"
#include <sni.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

// #define LLCRYPTO_KEY_DEBUG_TRACE

#ifdef LLCRYPTO_KEY_DEBUG_TRACE
#define LLCRYPTO_KEY_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_KEY_DEBUG_PRINTF(...) ((void)0)
#endif

static struct llcrypto_key *llcrypto_key_new(enum llcrypto_key_type type) {
	struct llcrypto_key *key = (struct llcrypto_key *)LLCRYPTO_calloc(1, sizeof(struct llcrypto_key));

	if (key != NULL) {
		key->type = type;
		key->alias = NULL;

		if (type == LLCRYPTO_KEY_TYPE_EVP_PKEY) {
			key->evp_key = NULL;
		} else {
			key->secret_key.buffer = NULL;
			key->secret_key.length = 0;
			key->secret_key.algorithm = NULL;
		}

		if (SNI_OK != SNI_registerResource(key, (SNI_closeFunction)llcrypto_key_free, NULL)) {
			LLCRYPTO_free(key);
			key = NULL;
		}
	}

	return key;
}

void llcrypto_key_free(struct llcrypto_key *key) {
	switch (key->type) {
	case LLCRYPTO_KEY_TYPE_EVP_PKEY:
		EVP_PKEY_free(key->evp_key);
		break;
	case LLCRYPTO_KEY_TYPE_SECRET_KEY:
		LLCRYPTO_free(key->secret_key.buffer);
		LLCRYPTO_free(key->secret_key.algorithm);
		break;
	default:
		LLCRYPTO_ASSERT(0);
		break;
	}

	LLCRYPTO_free(key->alias);

	if (SNI_unregisterResource(key, (SNI_closeFunction)llcrypto_key_free) != SNI_OK) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource\n");
	}
	LLCRYPTO_free(key);
}

int32_t llcrypto_key_get_encoded_max_size(const struct llcrypto_key *key) {
	int32_t max_size = 0;

	switch (key->type) {
	case LLCRYPTO_KEY_TYPE_SECRET_KEY:
		max_size = (int32_t)key->secret_key.length;
		break;
	default:
		break;
	}

	LLCRYPTO_KEY_DEBUG_PRINTF("%s max_size = %d\n", __func__, max_size);
	return max_size;
}

int32_t llcrypto_key_get_encoded(const struct llcrypto_key *key, uint8_t *output, int32_t output_length) {
	int32_t key_length = 0;

	switch (key->type) {
	case LLCRYPTO_KEY_TYPE_SECRET_KEY:
		if (key->secret_key.length <= (size_t)output_length) {
			(void)memcpy(output, key->secret_key.buffer, key->secret_key.length);
			key_length = (int32_t)key->secret_key.length;
		}
		break;
	default:
		break;
	}

	LLCRYPTO_KEY_DEBUG_PRINTF("%s key_length = %d\n", __func__, key_length);
	return key_length;
}

struct llcrypto_key *llcrypto_key_from_evp_pkey(EVP_PKEY *evp_key) {
	struct llcrypto_key *key = llcrypto_key_new(LLCRYPTO_KEY_TYPE_EVP_PKEY);

	if (key != NULL) {
		key->evp_key = evp_key;
	}

	return key;
}

struct llcrypto_key *llcrypto_key_from_x509_public_key(uint8_t *encoded, size_t len) {
	struct llcrypto_key *key = llcrypto_key_new(LLCRYPTO_KEY_TYPE_EVP_PKEY);

	if (key != NULL) {
		key->evp_key = d2i_PUBKEY(NULL, (const unsigned char **)&encoded, (long)len);
		if (key->evp_key == NULL) {
			llcrypto_key_free(key);
			key = NULL;
		}
	}

	return key;
}

struct llcrypto_key *llcrypto_key_from_pkcs8_private_key(uint8_t *encoded, size_t len) {
	struct llcrypto_key *key = llcrypto_key_new(LLCRYPTO_KEY_TYPE_EVP_PKEY);

	if (key != NULL) {
		key->evp_key = d2i_AutoPrivateKey(NULL, (const unsigned char **)&encoded, (long)len);
		if (key->evp_key == NULL) {
			llcrypto_key_free(key);
			key = NULL;
		}
	}

	return key;
}

struct llcrypto_key *llcrypto_key_from_secret_key(uint8_t *secret_key, size_t key_length, uint8_t *algorithm) {
	struct llcrypto_key *key = llcrypto_key_new(LLCRYPTO_KEY_TYPE_SECRET_KEY);

	if (key != NULL) {
		key->secret_key.buffer = (unsigned char *)LLCRYPTO_calloc(1, key_length);
		if (key->secret_key.buffer != NULL) {
			(void)memcpy(key->secret_key.buffer, secret_key, key_length);
			key->secret_key.length = key_length;
			key->secret_key.algorithm = (algorithm != NULL) ? LLCRYPTO_strdup((const char *)algorithm) : NULL;
		} else {
			llcrypto_key_free(key);
			key = NULL;
		}
	}

	return key;
}
