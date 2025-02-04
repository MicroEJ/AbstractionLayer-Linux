/*
 * C
 *
 * Copyright 2021-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

#include <LLSEC_KEY_PAIR_GENERATOR_impl.h>
#include "LLSEC_configuration.h"
#include <LLSEC_openssl.h>
#include <sni.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/**
 * @file
 * @brief MicroEJ Security low level API implementation for OpenSSL Library
 * @author MicroEJ Developer Team
 * @version 3.0.0
 * @date 20 August 2024
 */

#define LLSEC_KEY_PAIR_GENERATOR_SUCCESS 1
#define LLSEC_KEY_PAIR_GENERATOR_ERROR   0


// #define LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE

#ifdef LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE
#define LLSEC_KEY_PAIR_GENERATOR_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLSEC_KEY_PAIR_GENERATOR_PRINTF(...) ((void)0)
#endif

typedef void (*LLSEC_KEY_PAIR_GENERATOR_close)(void* native_id);

//RSA
static int32_t LLSEC_KEY_PAIR_GENERATOR_RSA_openssl_generateKeyPair(int32_t rsa_Key_size, int32_t rsa_public_exponent);

//EC
static int32_t LLSEC_KEY_PAIR_GENERATOR_EC_openssl_generateKeyPair(const uint8_t* ec_curve_stdname);

//common
static void LLSEC_KEY_PAIR_GENERATOR_openssl_close(void* native_id);

typedef struct {
	char* name;
	LLSEC_KEY_PAIR_GENERATOR_close close;
} LLSEC_KEY_PAIR_GENERATOR_algorithm;

// cppcheck-suppress misra-c2012-8.9 // Define here for code readability even if it called once in this file
static LLSEC_KEY_PAIR_GENERATOR_algorithm supportedAlgorithms[2] = {
		{
				.name            = "RSA",
				.close           = LLSEC_KEY_PAIR_GENERATOR_openssl_close
		},
		{
				.name            = "EC",
				.close           = LLSEC_KEY_PAIR_GENERATOR_openssl_close
		}

};

static int32_t LLSEC_KEY_PAIR_GENERATOR_RSA_openssl_generateKeyPair(int32_t rsa_Key_size, int32_t rsa_public_exponent) {
	LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s \n", __func__);
	EVP_PKEY *pk = NULL;

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	// Initialize key exponent
	BIGNUM* bn = BN_new();
	if (NULL == bn) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));

		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}
	BN_set_word(bn, rsa_public_exponent); //F0, F4 or other random number

	// Initialize RSA key
	RSA *rsa = RSA_new();
	if (NULL == rsa) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));

		BN_free(bn);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	// Generate RSA key
	if (RSA_generate_key_ex(rsa, rsa_Key_size, bn, NULL) != 1) { // returns 1 on success or 0 on error.
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));

		BN_free(bn);
		RSA_free(rsa);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	BN_free(bn); // not needed any more, clean it.

	pk = EVP_PKEY_new();
	if (NULL == pk) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));

		RSA_free(rsa);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	if (EVP_PKEY_assign_RSA(pk, rsa) <= 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));

		RSA_free(rsa);
		EVP_PKEY_free(pk);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}
#else
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (NULL == ctx) {
		uint32_t err = ERR_get_error();
		LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_CTX_new_id failed: %s\n", __func__, ERR_error_string(err, NULL));
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		uint32_t err = ERR_get_error();
		LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_keygen_init failed: %s\n", __func__, ERR_error_string(err, NULL));
		EVP_PKEY_CTX_free(ctx);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)rsa_Key_size) <=0) {
		uint32_t err = ERR_get_error();
		LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_CTX_set_rsa_keygen_bits for %s failed: %s\n", __func__, ec_curve_stdname, ERR_error_string(err, NULL));
		EVP_PKEY_CTX_free(ctx);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

 	BIGNUM *bn = BN_new();
  	BN_set_word(bn, rsa_public_exponent);
	if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, bn) <=0) {
		uint32_t err = ERR_get_error();
		LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_CTX_set1_rsa_keygen_pubexp for %s failed: %s\n", __func__, ec_curve_stdname, ERR_error_string(err, NULL));
		EVP_PKEY_CTX_free(ctx);
		BN_free(bn);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}
	BN_free(bn);

	if (EVP_PKEY_keygen(ctx, &pk) <= 0) {
		uint32_t err = ERR_get_error();
		LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_generate failed: %s\n", __func__, ERR_error_string(err, NULL));
		EVP_PKEY_CTX_free(ctx);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}
	EVP_PKEY_CTX_free(ctx);
#endif // OPENSSL_VERSION_NUMBER

	LLSEC_priv_key* key = (LLSEC_priv_key*) LLSEC_calloc(1, sizeof(LLSEC_priv_key));
	if (NULL == key) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't allocate LLSEC_priv_key structure");
		EVP_PKEY_free(pk); //rsa structure is freed when the key is freed
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	key->key = pk;
	key->type = TYPE_RSA;

	// Register the key to be managed by SNI as a native resource.
	// the close callback when be called when the key is collected by the GC
	// The key is freed in the close callback
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	int32_t native_id = (int32_t) key;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	if (SNI_registerResource((void*)native_id, LLSEC_KEY_PAIR_GENERATOR_openssl_close, NULL) != SNI_OK) {
		(void)SNI_throwNativeException(SNI_ERROR, "SNI: can't register native resource");
		EVP_PKEY_free(key->key);
		free(key);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	return native_id;
}

static int32_t LLSEC_KEY_PAIR_GENERATOR_EC_openssl_generateKeyPair(const uint8_t* ec_curve_stdname) {
	LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s \n", __func__);
	EVP_PKEY *pk = NULL;

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
	// Initialize EC key
	int eccgrp = OBJ_txt2nid(ec_curve_stdname);
	if(NID_undef == eccgrp) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	EC_KEY *ecc = EC_KEY_new_by_curve_name(eccgrp);
	if (NULL == ecc) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	EC_KEY_set_asn1_flag(ecc, OPENSSL_EC_NAMED_CURVE);

	// Generate EC key pair
	if (EC_KEY_generate_key(ecc) <= 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));

		EC_KEY_free(ecc);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	pk = EVP_PKEY_new();
	if (NULL == pk) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));

		EC_KEY_free(ecc);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	if (EVP_PKEY_assign_EC_KEY(pk, ecc) <= 0) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));

		EC_KEY_free(ecc);
		EVP_PKEY_free(pk);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}
#else
	// Create Key generation context
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (NULL == ctx) {
		uint32_t err = ERR_get_error();
		LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_CTX_new_id failed: %s\n", __func__, ERR_error_string(err, NULL));
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		uint32_t err = ERR_get_error();
		LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_keygen_init failed: %s\n", __func__, ERR_error_string(err, NULL));
		EVP_PKEY_CTX_free(ctx);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	int curve_nid = EC_curve_nist2nid(ec_curve_stdname);
	if (NID_undef == curve_nid) {
		curve_nid = OBJ_sn2nid(ec_curve_stdname);
	}

	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <=0) {
		uint32_t err = ERR_get_error();
		LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_CTX_set_ec_paramgen_curve_nid for %s failed: %s\n", __func__, ec_curve_stdname, ERR_error_string(err, NULL));
		EVP_PKEY_CTX_free(ctx);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	if (EVP_PKEY_keygen(ctx, &pk) <= 0) {
		uint32_t err = ERR_get_error();
		LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s EVP_PKEY_generate failed: %s\n", __func__, ERR_error_string(err, NULL));
		EVP_PKEY_CTX_free(ctx);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}
	EVP_PKEY_CTX_free(ctx);
#endif // OPENSSL_VERSION_NUMBER

	LLSEC_priv_key* key = (LLSEC_priv_key*) LLSEC_calloc(1, sizeof(LLSEC_priv_key));
	if (NULL == key) {
		(void)SNI_throwNativeException(SNI_ERROR, "Can't allocate LLSEC_priv_key structure");

		EVP_PKEY_free(pk); //ecc structure is freed when the key is freed
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	key->key = pk;
	key->type = TYPE_ECDSA;

	// Register the key to be managed by SNI as a native resource.
	// the close callback when be called when the key is collected by the GC
	// The key is freed in the close callback
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	int32_t native_id = (int32_t) key;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	if (SNI_registerResource((void*)native_id, LLSEC_KEY_PAIR_GENERATOR_openssl_close, NULL) != SNI_OK) {
		(void)SNI_throwNativeException(SNI_ERROR, "SNI: can't register native resource");
		EVP_PKEY_free(key->key);
		free(key);
		return LLSEC_KEY_PAIR_GENERATOR_ERROR;
	}

	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	return native_id;
}

static void LLSEC_KEY_PAIR_GENERATOR_openssl_close(void* native_id) {
	// cppcheck-suppress misra-c2012-11.5 // Abstract data type for SNI usage
	LLSEC_priv_key* key = (LLSEC_priv_key*) native_id;
	EVP_PKEY_free(key->key);
	free(key);
}

int32_t LLSEC_KEY_PAIR_GENERATOR_IMPL_get_algorithm(uint8_t* algorithm_name) {
	LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s \n", __func__);
	int32_t return_code = SNI_ERROR;
	int32_t nb_algorithms = sizeof(supportedAlgorithms) / sizeof(LLSEC_KEY_PAIR_GENERATOR_algorithm);
	LLSEC_KEY_PAIR_GENERATOR_algorithm* algorithm = &supportedAlgorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char*) algorithm_name, algorithm->name)) {
			// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
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

int32_t LLSEC_KEY_PAIR_GENERATOR_IMPL_generateKeyPair(int32_t algorithm_id, int32_t rsa_key_size, int32_t rsa_public_exponent, uint8_t* ec_curve_stdname) {
	LLSEC_KEY_PAIR_GENERATOR_PRINTF("%s \n", __func__);
	int32_t return_code = LLSEC_KEY_PAIR_GENERATOR_ERROR;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_KEY_PAIR_GENERATOR_algorithm* algorithm = (LLSEC_KEY_PAIR_GENERATOR_algorithm*) algorithm_id;
	if (0 == strcmp(algorithm->name, "RSA")) {
		return_code = LLSEC_KEY_PAIR_GENERATOR_RSA_openssl_generateKeyPair(rsa_key_size, rsa_public_exponent);
	} else if (0 == strcmp(algorithm->name, "EC")) {
		return_code = LLSEC_KEY_PAIR_GENERATOR_EC_openssl_generateKeyPair(ec_curve_stdname);
	} else {
		// Algorithm not found error.
		// this should never happen because the algorithm_id is a valid algorithm at this level.
		(void)SNI_throwNativeException(SNI_ERROR, "unsupported algorithm");
		return_code = SNI_ERROR;
	}
	return return_code;
}

int32_t LLSEC_KEY_PAIR_GENERATOR_IMPL_get_close_id(int32_t algorithm_id) {
	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	const LLSEC_KEY_PAIR_GENERATOR_algorithm* algorithm = (LLSEC_KEY_PAIR_GENERATOR_algorithm*) algorithm_id;
	// cppcheck-suppress misra-c2012-11.6 // Abstract data type for SNI usage
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t) algorithm->close;
}
