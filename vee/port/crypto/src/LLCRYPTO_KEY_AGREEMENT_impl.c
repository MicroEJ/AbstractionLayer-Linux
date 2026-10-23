/*
 * C
 *
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdint.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <LLCRYPTO_KEY_AGREEMENT_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"
#if defined(LLCRYPTO_KEYSTORE_PKCS11)
#include "LLCRYPTO_EXTERNAL_KEYSTORE_pkcs11.h"
#endif

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

/** Leading byte of a SEC1 uncompressed EC point (0x04 || X || Y). */
#define LLCRYPTO_EC_POINT_UNCOMPRESSED_TAG (0x04U)

/** Buffer size for an EC group name, the longest being "brainpoolP512t1". */
#define LLCRYPTO_EC_GROUP_NAME_MAX (32)

typedef struct {
	char *name;
} LLCRYPTO_KEY_AGREEMENT_algorithm;

int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_get_algorithm_id(uint8_t *algorithm_name) {
	static const LLCRYPTO_KEY_AGREEMENT_algorithm available_algorithms[] = {
		{ .name = "ECDH" }
	};

	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = SNI_ERROR;
	size_t nb_algorithms = sizeof(available_algorithms) / sizeof(available_algorithms[0]);
	const LLCRYPTO_KEY_AGREEMENT_algorithm *algorithm = &available_algorithms[0];

	for (size_t i = 0; i < nb_algorithms; i++) {
		if (0 == strcmp((const char *)algorithm_name, algorithm->name)) {
			return_code = (int32_t)algorithm;
			break;
		}
		algorithm++;
	}

	if (SNI_ERROR == return_code) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Unsupported key agreement algorithm");
	}

	return return_code;
}

/**
 * The raw ECDH shared secret is as long as the private key's field size, so both the
 * advertised maximum and the length the token is asked to produce come from here.
 *
 * @return the field size in bytes, or LLCRYPTO_ERROR if the key reports no size.
 */
static int32_t ec_field_size_bytes(const struct llcrypto_key *key) {
	int32_t result = LLCRYPTO_ERROR;
	int bits = EVP_PKEY_bits(key->evp_key);
	if (bits > 0) {
		result = (int32_t)((bits + 7) / 8);
	}
	return result;
}

int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_get_max_size(int32_t algorithm, int32_t local_private_key,
                                                 int32_t remote_public_key) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(algorithm);
	LLCRYPTO_UNUSED_PARAM(remote_public_key);

	const struct llcrypto_key *priv_key = (const struct llcrypto_key *)local_private_key;

	int32_t return_code = ec_field_size_bytes(priv_key);
	if (LLCRYPTO_ERROR == return_code) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
	}

	return return_code;
}

/**
 * ECDH via OpenSSL EVP. Correct for in-memory keys (software keys and the
 * PKCS#12 backend). For a pkcs11-provider-backed key this would route through
 * the provider, so token-resident keys use key_agreement_pkcs11() instead.
 */
static int32_t key_agreement_evp(const struct llcrypto_key *priv_key, const struct llcrypto_key *pub_key,
                                 uint8_t *secret_buffer, int32_t secret_capacity) {
	int32_t return_code = SNI_ERROR;
	/* secret_capacity was bounded against the secret array by the caller, so it is
	 * non-negative and the conversions below are faithful. */
	size_t secret_len = 0;

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key->evp_key, NULL);
	if (NULL == ctx) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
		goto end;
	}

	if (EVP_PKEY_derive_init(ctx) <= 0) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
		goto cleanup;
	}

	if (EVP_PKEY_derive_set_peer(ctx, pub_key->evp_key) <= 0) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
		goto cleanup;
	}

	/* First call: obtain required buffer length */
	if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
		goto cleanup;
	}

	/* A short buffer is not an error to plain ECDH: it derives min(capacity, field size)
	 * bytes and reports success, so a caller with too small an array would silently get a
	 * truncated secret. Reject it here instead. */
	if ((size_t)secret_capacity < secret_len) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Secret buffer too small");
		goto cleanup;
	}

	/* Second call: derive the shared secret. The capacity is passed rather than the length
	 * reported above so the array bounds the write as well. */
	secret_len = (size_t)secret_capacity;
	if (EVP_PKEY_derive(ctx, secret_buffer, &secret_len) <= 0) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
	} else {
		return_code = (int32_t)secret_len;
		VEEPORT_LOGGER_LOG_DBG("derived %d bytes", (int)secret_len);
	}

cleanup:
	EVP_PKEY_CTX_free(ctx);
end:
	return return_code;
}

#if defined(LLCRYPTO_KEYSTORE_PKCS11)

/**
 * Check that the peer key is on the same curve as @p priv_key and that its
 * public point lies on that curve. EVP_PKEY_derive_set_peer() performs both for
 * the EVP path; the direct C_DeriveKey call below does not, and a peer point on
 * a weaker curve leaks the token-resident private scalar.
 *
 * @return LLCRYPTO_SUCCESS if the peer key is usable, LLCRYPTO_ERROR otherwise.
 */
static int32_t check_ecdh_peer_key(const struct llcrypto_key *priv_key, const struct llcrypto_key *pub_key) {
	int32_t return_code = LLCRYPTO_ERROR;
	char priv_group[LLCRYPTO_EC_GROUP_NAME_MAX];
	char peer_group[LLCRYPTO_EC_GROUP_NAME_MAX];

	/* Compare group names rather than EVP_PKEY_parameters_eq(): the private key
	 * is held by pkcs11-provider and the peer key by the default provider. */
	if ((1 != EVP_PKEY_get_utf8_string_param(priv_key->evp_key, OSSL_PKEY_PARAM_GROUP_NAME, priv_group,
	                                         sizeof(priv_group), NULL)) ||
	    (1 != EVP_PKEY_get_utf8_string_param(pub_key->evp_key, OSSL_PKEY_PARAM_GROUP_NAME, peer_group,
	                                         sizeof(peer_group), NULL)) ||
	    (0 != strcmp(priv_group, peer_group))) {
		goto end;
	}

	EVP_PKEY_CTX *check_ctx = EVP_PKEY_CTX_new(pub_key->evp_key, NULL);
	if (NULL == check_ctx) {
		goto end;
	}
	if (1 == EVP_PKEY_public_check(check_ctx)) {
		return_code = LLCRYPTO_SUCCESS;
	}
	EVP_PKEY_CTX_free(check_ctx);

end:
	return return_code;
}

/**
 * ECDH for a PKCS#11 token-resident private key: bypasses pkcs11-provider and
 * calls C_DeriveKey directly with the raw uncompressed peer point.
 *
 * Only the OP-TEE PKCS#11 TA strictly requires this bypass — it mis-parses the
 * DER-wrapped peer point pkcs11-provider sends. The bypass is nonetheless taken
 * for every PKCS#11 backend: the raw uncompressed form is the PKCS#11 v2.40
 * mandatory encoding every conformant token accepts, and one derivation path
 * shared by all tokens is cheaper to maintain and to test than a per-token
 * dispatch. It is deliberate, not an unscoped workaround.
 */
static int32_t key_agreement_pkcs11(const struct llcrypto_key *priv_key, const struct llcrypto_key *pub_key,
                                    uint8_t *secret_buffer, int32_t secret_capacity) {
	int32_t return_code = SNI_ERROR;
	unsigned char *peer_point = NULL;

	size_t peer_point_len = EVP_PKEY_get1_encoded_public_key(pub_key->evp_key, &peer_point);
	if ((0U == peer_point_len) || (NULL == peer_point)) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
		goto end;
	}

	if (LLCRYPTO_EC_POINT_UNCOMPRESSED_TAG != peer_point[0]) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Peer EC point is not uncompressed");
		goto end;
	}

	int32_t field_size = ec_field_size_bytes(priv_key);
	if (field_size <= 0) {
		int err = ERR_get_error();
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                               ERR_error_string(err, NULL));
		goto end;
	}
	size_t secret_len = (size_t)field_size;

	/* The secret is always exactly the field size, so a shorter array can never hold it.
	 * Reject rather than pass the array's capacity down: secret_len also becomes the
	 * CKA_VALUE_LEN the token derives to, which must stay the field size. */
	if ((size_t)secret_capacity < secret_len) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Secret buffer too small");
		goto end;
	}

	/* A truncated or padded X || Y must not reach C_DeriveKey. */
	if (((1U + (2U * secret_len)) != peer_point_len) ||
	    (LLCRYPTO_SUCCESS != check_ecdh_peer_key(priv_key, pub_key))) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Invalid peer EC public key");
		goto end;
	}

	if (llcrypto_eks_ecdh_derive(priv_key->alias, peer_point, peer_point_len, secret_buffer,
	                             &secret_len) == LLCRYPTO_SUCCESS) {
		return_code = (int32_t)secret_len;
		VEEPORT_LOGGER_LOG_DBG("derived %d bytes", (int)secret_len);
	}
	/* On failure llcrypto_eks_ecdh_derive has already thrown a native exception;
	 * leave return_code at SNI_ERROR. */

end:
	OPENSSL_free(peer_point);
	return return_code;
}

#endif /* LLCRYPTO_KEYSTORE_PKCS11 */

int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_generate_secret(int32_t algorithm, int32_t local_private_key,
                                                    int32_t remote_public_key, uint8_t *secret_buffer) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(algorithm);

	const struct llcrypto_key *priv_key = (const struct llcrypto_key *)local_private_key;
	const struct llcrypto_key *pub_key = (const struct llcrypto_key *)remote_public_key;

	int32_t return_code = SNI_ERROR;

	/* This native carries no length for secret_buffer, so its capacity can only come from
	 * the array itself. Read it before the backend choice below so both paths are covered
	 * and the read is compiled whichever keystore is built. */
	int32_t secret_capacity = sni_array_get_length(secret_buffer);
	if (secret_capacity < 0) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
#if defined(LLCRYPTO_KEYSTORE_PKCS11)
		if (NULL != priv_key->alias) {
			return_code = key_agreement_pkcs11(priv_key, pub_key, secret_buffer, secret_capacity);
		} else
#endif
		{
			return_code = key_agreement_evp(priv_key, pub_key, secret_buffer, secret_capacity);
		}
	}

	return return_code;
}
