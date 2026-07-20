/*
 * C
 *
 * Copyright 2021-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <LLCRYPTO_KEY_PAIR_GENERATOR_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"
#include <sni.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <openssl/objects.h>

#define LLCRYPTO_KEY_PAIR_GENERATOR_SUCCESS 1
#define LLCRYPTO_KEY_PAIR_GENERATOR_ERROR   0

struct ec_curve_alias {
	const char *name;
	int nid;
};

/** Common Java curve name aliases that OBJ_txt2nid may not recognize. */
static const struct ec_curve_alias ec_curve_aliases[] = {
	{ "secp256r1", NID_X9_62_prime256v1 },
	{ "prime256v1", NID_X9_62_prime256v1 },
	{ "P-256", NID_X9_62_prime256v1 },
	{ "secp384r1", NID_secp384r1 },
	{ "P-384", NID_secp384r1 },
	{ "secp521r1", NID_secp521r1 },
	{ "P-521", NID_secp521r1 },
};

/**
 * Map a Java curve name (e.g. "secp256r1") to an OpenSSL NID.
 */
static int ec_curve_name_to_nid(const char *name) {
	int nid = OBJ_txt2nid(name);
	if (nid != NID_undef) {
		return nid;
	}
	for (size_t i = 0; i < sizeof(ec_curve_aliases) / sizeof(ec_curve_aliases[0]); i++) {
		if (strcmp(name, ec_curve_aliases[i].name) == 0) {
			return ec_curve_aliases[i].nid;
		}
	}
	return NID_undef;
}

// #define LLCRYPTO_KEY_PAIR_GENERATOR_DEBUG_TRACE

#ifdef LLCRYPTO_KEY_PAIR_GENERATOR_DEBUG_TRACE
#define LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF(...) ((void)0)
#endif

//RSA
static int32_t LLCRYPTO_KEY_PAIR_GENERATOR_RSA_openssl_generateKeyPair(int32_t rsa_Key_size,
                                                                       int32_t rsa_public_exponent);

//EC
static int32_t LLCRYPTO_KEY_PAIR_GENERATOR_EC_openssl_generateKeyPair(const uint8_t *ec_curve_stdname);

typedef struct {
	char *name;
} LLCRYPTO_KEY_PAIR_GENERATOR_algorithm;

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file
static LLCRYPTO_KEY_PAIR_GENERATOR_algorithm supportedAlgorithms[2] = {
	{ .name = "RSA" },
	{ .name = "EC" }
};

static int32_t LLCRYPTO_KEY_PAIR_GENERATOR_RSA_openssl_generateKeyPair(int32_t rsa_Key_size,
                                                                       int32_t rsa_public_exponent) {
	LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s \n", __func__);
	int32_t return_code = LLCRYPTO_KEY_PAIR_GENERATOR_ERROR;
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	BIGNUM *bn = NULL;
	struct llcrypto_key *key = NULL;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (NULL == ctx) {
		LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_CTX_new_id failed: %s\n", __func__,
		                                   ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_keygen_init failed: %s\n", __func__,
		                                   ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)rsa_Key_size) <= 0) {
		LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_CTX_set_rsa_keygen_bits failed: %s\n", __func__,
		                                   ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}

	bn = BN_new();
	if (NULL == bn) {
		goto cleanup;
	}
	BN_set_word(bn, rsa_public_exponent);
	if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn) <= 0) {
		LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_CTX_set1_rsa_keygen_pubexp failed: %s\n", __func__,
		                                   ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}
	BN_free(bn);
	bn = NULL;

	if (EVP_PKEY_keygen(ctx, &pk) <= 0) {
		LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_generate failed: %s\n", __func__,
		                                   ERR_error_string(ERR_get_error(), NULL));
		goto cleanup;
	}
	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	key = llcrypto_key_from_evp_pkey(pk);
	if (NULL == key) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't allocate llcrypto_key structure");
		goto cleanup;
	}
	/* evp_key ownership transferred to key */
	pk = NULL;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	return_code = (int32_t)key;

cleanup:
	BN_free(bn);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pk);
end:
	return return_code;
}

static int32_t LLCRYPTO_KEY_PAIR_GENERATOR_EC_openssl_generateKeyPair(const uint8_t *ec_curve_stdname) {
	LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s curve='%s'\n", __func__, ec_curve_stdname);
	int32_t return_code = LLCRYPTO_KEY_PAIR_GENERATOR_ERROR;
	EVP_PKEY *pk = NULL;
	struct llcrypto_key *key = NULL;

	int curve_nid = ec_curve_name_to_nid((const char *)ec_curve_stdname);
	if (NID_undef == curve_nid) {
		LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s unknown curve '%s'\n", __func__, ec_curve_stdname);
		goto end;
	}

	const char *curve_sn = OBJ_nid2sn(curve_nid);
	LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s nid=%d sn='%s'\n", __func__, curve_nid, curve_sn);

	pk = EVP_EC_gen(curve_sn);
	if (NULL == pk) {
		LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s EVP_EC_gen failed: %s\n", __func__,
		                                   ERR_error_string(ERR_get_error(), NULL));
		goto end;
	}

	key = llcrypto_key_from_evp_pkey(pk);
	if (NULL == key) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't allocate llcrypto_key structure");
		goto cleanup;
	}
	/* evp_key ownership transferred to key */
	pk = NULL;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	return_code = (int32_t)key;

cleanup:
	EVP_PKEY_free(pk);
end:
	return return_code;
}

int32_t LLCRYPTO_KEY_PAIR_GENERATOR_IMPL_get_algorithm(uint8_t *algorithm_name) {
	LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_algorithms = sizeof(supportedAlgorithms) / sizeof(LLCRYPTO_KEY_PAIR_GENERATOR_algorithm);
	LLCRYPTO_KEY_PAIR_GENERATOR_algorithm *algorithm = &supportedAlgorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			break;
		}
		algorithm++;
	}

	if (nb_algorithms >= 0) {
		// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
		return_code = (int32_t)algorithm;
	}
	return return_code;
}

int32_t LLCRYPTO_KEY_PAIR_GENERATOR_IMPL_generateKeyPair(int32_t algorithm_id, int32_t rsa_key_size,
                                                         int32_t rsa_public_exponent, uint8_t *ec_curve_stdname) {
	LLCRYPTO_KEY_PAIR_GENERATOR_PRINTF("%s \n", __func__);
	int32_t return_code = LLCRYPTO_KEY_PAIR_GENERATOR_ERROR;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLCRYPTO_KEY_PAIR_GENERATOR_algorithm *algorithm = (LLCRYPTO_KEY_PAIR_GENERATOR_algorithm *)algorithm_id;
	if (0 == strcmp(algorithm->name, "RSA")) {
		return_code = LLCRYPTO_KEY_PAIR_GENERATOR_RSA_openssl_generateKeyPair(rsa_key_size, rsa_public_exponent);
	} else if (0 == strcmp(algorithm->name, "EC")) {
		return_code = LLCRYPTO_KEY_PAIR_GENERATOR_EC_openssl_generateKeyPair(ec_curve_stdname);
	} else {
		(void)SNI_throwNativeException(SNI_ERROR, "unsupported algorithm");
		return_code = SNI_ERROR;
	}
	return return_code;
}

int32_t LLCRYPTO_KEY_PAIR_GENERATOR_IMPL_get_close_id(int32_t algorithm_id) {
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)llcrypto_key_free;
}
