/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

static struct llcrypto_key *llcrypto_key_new(enum llcrypto_key_type type) {
	struct llcrypto_key *key = (struct llcrypto_key *)LLCRYPTO_calloc(1, sizeof(struct llcrypto_key));

	if (NULL != key) {
		key->type = type;
#if defined(LLCRYPTO_KEYSTORE_PKCS11)
		key->alias = NULL;
#endif

		if (LLCRYPTO_KEY_TYPE_EVP_PKEY == type) {
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
		if (NULL != key->secret_key.buffer) {
			OPENSSL_cleanse(key->secret_key.buffer, key->secret_key.length);
		}
		LLCRYPTO_free(key->secret_key.buffer);
		LLCRYPTO_free(key->secret_key.algorithm);
		break;
	default:
		LLCRYPTO_ASSERT(0);
		break;
	}

#if defined(LLCRYPTO_KEYSTORE_PKCS11)
	LLCRYPTO_free(key->alias);
#endif

	if (SNI_OK != SNI_unregisterResource(key, (SNI_closeFunction)llcrypto_key_free)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Can't unregister SNI native resource");
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

	VEEPORT_LOGGER_LOG_DBG("max_size = %d", max_size);
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

	VEEPORT_LOGGER_LOG_DBG("key_length = %d", key_length);
	return key_length;
}

struct llcrypto_key *llcrypto_key_from_evp_pkey(EVP_PKEY *evp_key) {
	struct llcrypto_key *key = llcrypto_key_new(LLCRYPTO_KEY_TYPE_EVP_PKEY);

	if (NULL != key) {
		key->evp_key = evp_key;
	}

	return key;
}

typedef EVP_PKEY *(*llcrypto_key_decoder)(EVP_PKEY **key, const unsigned char **der, long length);

/**
 * @brief Decodes key material into a new key.
 *
 * The material is decoded before the key is allocated, so that invalid material never registers a native resource.
 *
 * @param[in] decode       the OpenSSL decoder of the format.
 * @param[in] encoded_key  the DER-encoded key material.
 * @param[in] key_length   the length of the material in bytes.
 * @param[out] key_out     the new key on success, NULL on failure.
 *
 * @return `LLCRYPTO_SUCCESS`, `LLCRYPTO_ERROR_OOM`, or `LLCRYPTO_ERROR` when OpenSSL cannot decode the material.
 */
static int32_t llcrypto_key_from_der(llcrypto_key_decoder decode, const uint8_t *encoded_key, size_t key_length,
                                     struct llcrypto_key **key_out) {
	int32_t return_code = LLCRYPTO_ERROR;
	struct llcrypto_key *key = NULL;
	const unsigned char *der = (const unsigned char *)encoded_key;
	EVP_PKEY *evp_key = decode(NULL, &der, (long)key_length);

	if (NULL != evp_key) {
		key = llcrypto_key_from_evp_pkey(evp_key);
		if (NULL == key) {
			EVP_PKEY_free(evp_key);
			return_code = LLCRYPTO_ERROR_OOM;
		} else {
			return_code = LLCRYPTO_SUCCESS;
		}
	}

	*key_out = key;
	return return_code;
}

int32_t llcrypto_key_from_x509_public_key(const uint8_t *encoded_key, size_t key_length,
                                          struct llcrypto_key **key_out) {
	return llcrypto_key_from_der(d2i_PUBKEY, encoded_key, key_length, key_out);
}

int32_t llcrypto_key_from_pkcs8_private_key(const uint8_t *encoded_key, size_t key_length,
                                            struct llcrypto_key **key_out) {
	return llcrypto_key_from_der(d2i_AutoPrivateKey, encoded_key, key_length, key_out);
}

struct llcrypto_key *llcrypto_key_from_secret_key(const uint8_t *secret_key, size_t key_length,
                                                  const uint8_t *algorithm) {
	struct llcrypto_key *key = llcrypto_key_new(LLCRYPTO_KEY_TYPE_SECRET_KEY);

	if (NULL != key) {
		key->secret_key.buffer = (unsigned char *)LLCRYPTO_calloc(1, key_length);
		if (NULL != key->secret_key.buffer) {
			(void)memcpy(key->secret_key.buffer, secret_key, key_length);
			key->secret_key.length = key_length;
			key->secret_key.algorithm = (NULL != algorithm) ? LLCRYPTO_strdup((const char *)algorithm) : NULL;
		} else {
			llcrypto_key_free(key);
			key = NULL;
		}
	}

	return key;
}
