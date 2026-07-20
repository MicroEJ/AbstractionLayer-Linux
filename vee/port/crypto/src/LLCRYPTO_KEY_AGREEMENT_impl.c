/*
 * C
 *
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"
#include "LLCRYPTO_EXTERNAL_KEYSTORE_common.h"
#include "LLCRYPTO_KEY_AGREEMENT_impl.h"
#include <LLCRYPTO_CONSTANTS.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <sni.h>
#include <string.h>
#include <stdint.h>

// #define LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE

#ifdef LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE
#define LLCRYPTO_KEY_AGREEMENT_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_KEY_AGREEMENT_DEBUG_PRINTF(...) ((void)0)
#endif

/** Leading byte of a SEC1 uncompressed EC point (0x04 || X || Y). */
#define LLCRYPTO_EC_POINT_UNCOMPRESSED_TAG (0x04U)

typedef struct {
	char *name;
} LLCRYPTO_KEY_AGREEMENT_algorithm;

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file
static LLCRYPTO_KEY_AGREEMENT_algorithm available_algorithms[] = {
	{ .name = "ECDH" }
};

// cppcheck-suppress misra-c2012-8.7; external linkage is required as this function is part of the API
int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_get_algorithm_id(uint8_t *algorithm_name) {
	LLCRYPTO_KEY_AGREEMENT_DEBUG_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLCRYPTO_KEY_AGREEMENT_algorithm);
	LLCRYPTO_KEY_AGREEMENT_algorithm *algorithm = &available_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((const char *)algorithm_name, algorithm->name)) {
			break;
		}
		algorithm++;
	}

	if (nb_algorithms >= 0) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t)algorithm;
	} else {
		(void)SNI_throwNativeException(SNI_ERROR, "Unsupported key agreement algorithm");
	}

	return return_code;
}

// cppcheck-suppress misra-c2012-8.7; external linkage is required as this function is part of the API
int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_get_max_size(int32_t algorithm, int32_t local_private_key,
                                                 int32_t remote_public_key) {
	LLCRYPTO_KEY_AGREEMENT_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(algorithm);
	LLCRYPTO_UNUSED_PARAM(remote_public_key);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *priv_key = (const struct llcrypto_key *)local_private_key;

	/* For EC keys the shared secret length equals the key's field size in bytes */
	int32_t return_code = SNI_ERROR;
	int bits = EVP_PKEY_bits(priv_key->evp_key);
	if (bits <= 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	} else {
		return_code = (int32_t)((bits + 7) / 8);
	}

	return return_code;
}

/**
 * ECDH via OpenSSL EVP. Correct for in-memory keys (software keys and the
 * PKCS#12 backend). For a pkcs11-provider-backed key this would route through
 * the provider, so token-resident keys use key_agreement_pkcs11() instead.
 */
static int32_t key_agreement_evp(const struct llcrypto_key *priv_key, const struct llcrypto_key *pub_key,
                                 uint8_t *secret_buffer) {
	int32_t return_code = SNI_ERROR;
	size_t secret_len = 0;

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key->evp_key, NULL);
	if (NULL == ctx) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto end;
	}

	if (EVP_PKEY_derive_init(ctx) <= 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto cleanup;
	}

	if (EVP_PKEY_derive_set_peer(ctx, pub_key->evp_key) <= 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto cleanup;
	}

	/* First call: obtain required buffer length */
	if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto cleanup;
	}

	/* Second call: derive the shared secret */
	if (EVP_PKEY_derive(ctx, secret_buffer, &secret_len) <= 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
	} else {
		return_code = (int32_t)secret_len;
		LLCRYPTO_KEY_AGREEMENT_DEBUG_PRINTF("%s derived %d bytes\n", __func__, (int)secret_len);
	}

cleanup:
	EVP_PKEY_CTX_free(ctx);
end:
	return return_code;
}

#if defined(LLCRYPTO_KEYSTORE_PKCS11)
/**
 * ECDH for a PKCS#11 token-resident private key. Bypasses pkcs11-provider —
 * whose DER-wrapped ECDH peer point the OP-TEE TA mis-parses
 *  by calling C_DeriveKey directly with the raw
 * uncompressed peer point.
 */
static int32_t key_agreement_pkcs11(const struct llcrypto_key *priv_key, const struct llcrypto_key *pub_key,
                                    uint8_t *secret_buffer) {
	int32_t return_code = SNI_ERROR;
	unsigned char *peer_point = NULL;

	size_t peer_point_len = EVP_PKEY_get1_encoded_public_key(pub_key->evp_key, &peer_point);
	if ((0U == peer_point_len) || (NULL == peer_point)) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto end;
	}

	if (LLCRYPTO_EC_POINT_UNCOMPRESSED_TAG != peer_point[0]) {
		(void)SNI_throwNativeException(SNI_ERROR, "Peer EC point is not uncompressed");
		goto end;
	}

	/* The raw shared secret is the field size in bytes; that is also the buffer
	 * size the caller allocated from LLCRYPTO_KEY_AGREEMENT_IMPL_get_max_size. */
	size_t secret_len = (size_t)((EVP_PKEY_bits(priv_key->evp_key) + 7) / 8);
	if (llcrypto_eks_ecdh_derive(priv_key->alias, peer_point, peer_point_len, secret_buffer,
	                             &secret_len) == LLCRYPTO_SUCCESS) {
		return_code = (int32_t)secret_len;
		LLCRYPTO_KEY_AGREEMENT_DEBUG_PRINTF("%s derived %d bytes\n", __func__, (int)secret_len);
	}
	/* On failure llcrypto_eks_ecdh_derive has already thrown a native exception;
	 * leave return_code at SNI_ERROR. */

end:
	OPENSSL_free(peer_point);
	return return_code;
}

#endif /* LLCRYPTO_KEYSTORE_PKCS11 */

// cppcheck-suppress misra-c2012-8.7; external linkage is required as this function is part of the API
int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_generate_secret(int32_t algorithm, int32_t local_private_key,
                                                    int32_t remote_public_key, uint8_t *secret_buffer) {
	LLCRYPTO_KEY_AGREEMENT_DEBUG_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(algorithm);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *priv_key = (const struct llcrypto_key *)local_private_key;
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const struct llcrypto_key *pub_key = (const struct llcrypto_key *)remote_public_key;

	int32_t return_code = SNI_ERROR;

#if defined(LLCRYPTO_KEYSTORE_PKCS11)
	if (NULL != priv_key->alias) {
		return_code = key_agreement_pkcs11(priv_key, pub_key, secret_buffer);
	} else
#endif
	{
		return_code = key_agreement_evp(priv_key, pub_key, secret_buffer);
	}

	return return_code;
}
