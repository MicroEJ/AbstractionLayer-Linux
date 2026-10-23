/*
 * C
 *
 * Copyright 2021-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <string.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <LLCRYPTO_KEY_PAIR_GENERATOR_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"
#include "LLCRYPTO_utils.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

#define LLCRYPTO_KEY_PAIR_GENERATOR_SUCCESS 1
#define LLCRYPTO_KEY_PAIR_GENERATOR_ERROR   0

//RSA
static int32_t llcrypto_key_pair_generator_rsa_generate_key_pair(int32_t rsa_key_size,
                                                                 int32_t rsa_public_exponent);

//EC
static int32_t llcrypto_key_pair_generator_ec_generate_key_pair(const uint8_t *ec_curve_stdname);

typedef struct {
	char *name;
} LLCRYPTO_KEY_PAIR_GENERATOR_algorithm;

static int32_t llcrypto_key_pair_generator_rsa_generate_key_pair(int32_t rsa_key_size,
                                                                 int32_t rsa_public_exponent) {
	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = LLCRYPTO_KEY_PAIR_GENERATOR_ERROR;
	const char *error_message = NULL;
	int32_t error_code = LLCRYPTO_UNSPECIFIED_EXCEPTION;
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	BIGNUM *bn = NULL;
	struct llcrypto_key *key = NULL;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (NULL == ctx) {
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_new_id failed: %s", ERR_error_string(ERR_get_error(), NULL));
		error_message = "Cannot create the RSA key generation context";
		goto end;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_keygen_init failed: %s", ERR_error_string(ERR_get_error(), NULL));
		error_message = "Cannot initialize RSA key generation";
		goto cleanup;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)rsa_key_size) <= 0) {
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_set_rsa_keygen_bits failed: %s", ERR_error_string(ERR_get_error(), NULL));
		error_message = "Cannot set the RSA key size";
		error_code = LLCRYPTO_KEY_PAIR_GENERATOR_UNSUPPORTED_PARAMETER;
		goto cleanup;
	}

	bn = BN_new();
	if (NULL == bn) {
		error_message = "Cannot allocate the RSA public exponent";
		goto cleanup;
	}
	if (1 != BN_set_word(bn, rsa_public_exponent)) {
		VEEPORT_LOGGER_LOG_ERR("BN_set_word failed: %s", ERR_error_string(ERR_get_error(), NULL));
		error_message = "Cannot set the RSA public exponent";
		error_code = LLCRYPTO_KEY_PAIR_GENERATOR_UNSUPPORTED_PARAMETER;
		goto cleanup;
	}
	if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn) <= 0) {
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_set1_rsa_keygen_pubexp failed: %s",
		                       ERR_error_string(ERR_get_error(), NULL));
		error_message = "Cannot apply the RSA public exponent";
		error_code = LLCRYPTO_KEY_PAIR_GENERATOR_UNSUPPORTED_PARAMETER;
		goto cleanup;
	}
	BN_free(bn);
	bn = NULL;

	if (EVP_PKEY_keygen(ctx, &pk) <= 0) {
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_generate failed: %s", ERR_error_string(ERR_get_error(), NULL));
		error_message = "RSA key pair generation failed";
		goto cleanup;
	}
	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	key = llcrypto_key_from_evp_pkey(pk);
	if (NULL == key) {
		error_message = "Cannot allocate the key structure";
		goto cleanup;
	}
	/* evp_key ownership transferred to key */
	pk = NULL;

	return_code = (int32_t)key;

cleanup:
	BN_free(bn);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pk);
end:
	if (NULL != error_message) {
		VEEPORT_ERRORS_throw_runtime_exception_message(error_code, "%s", error_message);
	}
	return return_code;
}

static int32_t llcrypto_key_pair_generator_ec_generate_key_pair(const uint8_t *ec_curve_stdname) {
	VEEPORT_LOGGER_LOG_DBG("curve='%s'", ec_curve_stdname);
	int32_t return_code = LLCRYPTO_KEY_PAIR_GENERATOR_ERROR;
	const char *error_message = NULL;
	int32_t error_code = LLCRYPTO_UNSPECIFIED_EXCEPTION;
	EVP_PKEY *pk = NULL;
	struct llcrypto_key *key = NULL;

	int curve_nid = llcrypto_curve_name_to_nid((const char *)ec_curve_stdname);
	if (NID_undef == curve_nid) {
		VEEPORT_LOGGER_LOG_ERR("unknown curve '%s'", ec_curve_stdname);
		error_message = "Unsupported EC curve";
		error_code = LLCRYPTO_KEY_PAIR_GENERATOR_UNSUPPORTED_PARAMETER;
		goto end;
	}

	const char *curve_sn = OBJ_nid2sn(curve_nid);
	VEEPORT_LOGGER_LOG_DBG("nid=%d sn='%s'", curve_nid, curve_sn);

	pk = EVP_EC_gen(curve_sn);
	if (NULL == pk) {
		VEEPORT_LOGGER_LOG_ERR("EVP_EC_gen failed: %s", ERR_error_string(ERR_get_error(), NULL));
		error_message = "EC key pair generation failed";
		goto end;
	}

	key = llcrypto_key_from_evp_pkey(pk);
	if (NULL == key) {
		error_message = "Cannot allocate the key structure";
		goto cleanup;
	}
	/* evp_key ownership transferred to key */
	pk = NULL;

	return_code = (int32_t)key;

cleanup:
	EVP_PKEY_free(pk);
end:
	if (NULL != error_message) {
		VEEPORT_ERRORS_throw_runtime_exception_message(error_code, "%s", error_message);
	}
	return return_code;
}

int32_t LLCRYPTO_KEY_PAIR_GENERATOR_IMPL_get_algorithm(uint8_t *algorithm_name) {
	static const LLCRYPTO_KEY_PAIR_GENERATOR_algorithm available_algorithms[2] = {
		{ .name = "RSA" },
		{ .name = "EC" }
	};

	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = SNI_ERROR;
	size_t nb_algorithms = sizeof(available_algorithms) / sizeof(available_algorithms[0]);
	const LLCRYPTO_KEY_PAIR_GENERATOR_algorithm *algorithm = &available_algorithms[0];

	for (size_t i = 0; i < nb_algorithms; i++) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			return_code = (int32_t)algorithm;
			break;
		}
		algorithm++;
	}
	return return_code;
}

int32_t LLCRYPTO_KEY_PAIR_GENERATOR_IMPL_generateKeyPair(int32_t algorithm_id, int32_t rsa_key_size,
                                                         int32_t rsa_public_exponent, uint8_t *ec_curve_stdname) {
	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = LLCRYPTO_KEY_PAIR_GENERATOR_ERROR;

	const LLCRYPTO_KEY_PAIR_GENERATOR_algorithm *algorithm = (LLCRYPTO_KEY_PAIR_GENERATOR_algorithm *)algorithm_id;
	if (0 == strcmp(algorithm->name, "RSA")) {
		return_code = llcrypto_key_pair_generator_rsa_generate_key_pair(rsa_key_size, rsa_public_exponent);
	} else if (0 == strcmp(algorithm->name, "EC")) {
		return_code = llcrypto_key_pair_generator_ec_generate_key_pair(ec_curve_stdname);
	} else {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "unsupported algorithm");
		return_code = SNI_ERROR;
	}
	return return_code;
}

int32_t LLCRYPTO_KEY_PAIR_GENERATOR_IMPL_get_close_id(int32_t algorithm_id) {
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	return (int32_t)llcrypto_key_free;
}
