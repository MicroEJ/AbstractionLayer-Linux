/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <LLCRYPTO_SIG_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

#define MICROEJ_LLCRYPTO_SIGNATURE_INVALID 2
#define MICROEJ_LLCRYPTO_SIG_SUCCESS 1
#define MICROEJ_LLCRYPTO_SIG_ERROR   0
/* Distinct from _ERROR because the ECDSA provider reports a short output buffer by
 * returning 0 without queueing an error, so the caller cannot describe it from the
 * OpenSSL error queue. */
#define MICROEJ_LLCRYPTO_SIG_BUFFER_TOO_SMALL 3

typedef struct LLCRYPTO_SIG_algorithm LLCRYPTO_SIG_algorithm;
typedef int (*LLCRYPTO_SIG_verify)(const LLCRYPTO_SIG_algorithm *algorithm, const uint8_t *signature,
                                   int32_t signature_length, const struct llcrypto_key *pub_key, const uint8_t *digest,
                                   int32_t digest_length);

/* signature_capacity is what the signature array can hold; signature_length is out-only,
 * the number of bytes actually written. */
typedef int (*LLCRYPTO_SIG_sign)(const LLCRYPTO_SIG_algorithm *algorithm, uint8_t *signature,
                                 int32_t signature_capacity, int32_t *signature_length,
                                 const struct llcrypto_key *priv_key, const uint8_t *digest, int32_t digest_length);

struct LLCRYPTO_SIG_algorithm {
	char *name;
	char *digest_name;
	char *digest_native_name;
	char *oid;
	LLCRYPTO_SIG_verify verify;
	LLCRYPTO_SIG_sign sign;
};

static int llcrypto_openssl_sig_verify(const LLCRYPTO_SIG_algorithm *algorithm, const uint8_t *signature,
                                       int32_t signature_length, const struct llcrypto_key *pub_key,
                                       const uint8_t *digest,
                                       int32_t digest_length);
static int llcrypto_openssl_sig_sign(const LLCRYPTO_SIG_algorithm *algorithm, uint8_t *signature,
                                     int32_t signature_capacity, int32_t *signature_length,
                                     const struct llcrypto_key *priv_key, const uint8_t *digest, int32_t digest_length);

static LLCRYPTO_SIG_algorithm available_algorithms[] = {
	{
		.name = "SHA256withRSA",
		.digest_name = "SHA-256",
		.digest_native_name = "SHA256",
		.oid = "1.2.840.113549.1.1.11",
		.verify = llcrypto_openssl_sig_verify,
		.sign = llcrypto_openssl_sig_sign
	},
	{
		.name = "SHA256withECDSA",
		.digest_name = "SHA-256",
		.digest_native_name = "SHA256",
		.oid = "1.2.840.10045.4.3.2",
		.verify = llcrypto_openssl_sig_verify,
		.sign = llcrypto_openssl_sig_sign
	}
};

static int llcrypto_openssl_sig_verify(const LLCRYPTO_SIG_algorithm *algorithm, const uint8_t *signature,
                                       int32_t signature_length, const struct llcrypto_key *pub_key,
                                       const uint8_t *digest,
                                       int32_t digest_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	EVP_PKEY_CTX *ctx = NULL;
	int return_code = MICROEJ_LLCRYPTO_SIG_SUCCESS;

	ctx = EVP_PKEY_CTX_new(pub_key->evp_key, NULL);
	if (NULL == ctx) {
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_new failed");
		return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_verify_init(ctx) <= 0) {
			VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_verify_init failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(algorithm->digest_native_name)) <= 0) {
			VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_set_signature_md failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		int rc = EVP_PKEY_verify(ctx, signature, signature_length, digest, digest_length);
		if (1 == rc) {
			return_code = MICROEJ_LLCRYPTO_SIG_SUCCESS;
		} else {
			/* A rejected signature is an expected outcome, not a failure: drop the entry the
			 * verification queued so it cannot surface from a later, unrelated call. */
			ERR_clear_error();
			return_code = MICROEJ_LLCRYPTO_SIGNATURE_INVALID;
		}
	}
	EVP_PKEY_CTX_free(ctx);

	return return_code;
}

static int llcrypto_openssl_sig_sign(const LLCRYPTO_SIG_algorithm *algorithm, uint8_t *signature,
                                     int32_t signature_capacity, int32_t *signature_length,
                                     const struct llcrypto_key *priv_key, const uint8_t *digest,
                                     int32_t digest_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	EVP_PKEY_CTX *ctx = NULL;
	int return_code = MICROEJ_LLCRYPTO_SIG_SUCCESS;
	/* The caller bounded signature_capacity against the signature array, so it is
	 * non-negative and the conversions below are faithful. */
	size_t required = 0;

	ctx = EVP_PKEY_CTX_new(priv_key->evp_key, NULL);
	if (NULL == ctx) {
		VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_new failed");
		return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_sign_init(ctx) <= 0) {
			VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_sign_init failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbyname(algorithm->digest_native_name)) <= 0) {
			VEEPORT_LOGGER_LOG_ERR("EVP_PKEY_CTX_set_signature_md failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		/* Ask for the size this key and algorithm will produce, then refuse up front if the
		 * array cannot hold it. The array is sized from a runtime property rather than from
		 * the key, so it can legitimately be too small. */
		if (EVP_PKEY_sign(ctx, NULL, &required, digest, digest_length) <= 0) {
			VEEPORT_LOGGER_LOG_ERR("First EVP_PKEY_sign failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		} else if ((size_t)signature_capacity < required) {
			VEEPORT_LOGGER_LOG_ERR("Signature needs %u bytes, array holds %d", (unsigned int)required,
			                       (int)signature_capacity);
			return_code = MICROEJ_LLCRYPTO_SIG_BUFFER_TOO_SMALL;
		} else {
			/* nothing to do: the array is large enough */
		}
	}

	if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
		/* Hand the array's capacity, not the size reported above, so OpenSSL bounds the
		 * write by what the array can actually hold. */
		size_t written = (size_t)signature_capacity;
		if (EVP_PKEY_sign(ctx, signature, &written, digest, digest_length) <= 0) {
			VEEPORT_LOGGER_LOG_ERR("Second EVP_PKEY_sign failed");
			return_code = MICROEJ_LLCRYPTO_SIG_ERROR;
		} else {
			*signature_length = (int32_t)written;
		}
	}

	EVP_PKEY_CTX_free(ctx);

	return return_code;
}

int32_t LLCRYPTO_SIG_IMPL_get_algorithm_description(uint8_t *algorithm_name, uint8_t *digest_algorithm_name,
                                                    int32_t digest_algorithm_name_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = SNI_ERROR;

	size_t nb_algorithms = sizeof(available_algorithms) / sizeof(available_algorithms[0]);
	LLCRYPTO_SIG_algorithm *algorithm = &available_algorithms[0];

	/* strncpy pads to the full length it is given rather than stopping at the name, so the
	 * claimed length has to fit the array. The terminator below indexes one before that
	 * length, so a zero length would write ahead of the array. */
	if ((digest_algorithm_name_length <= 0) ||
	    !sni_array_contains_range(digest_algorithm_name, 0, digest_algorithm_name_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		for (size_t i = 0; i < nb_algorithms; i++) {
			if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
				(void)strncpy((char *)digest_algorithm_name, algorithm->digest_name, digest_algorithm_name_length);
				digest_algorithm_name[digest_algorithm_name_length - 1] = '\0';
				return_code = (int32_t)algorithm;
				break;
			}
			algorithm++;
		}
	}
	return return_code;
}

void LLCRYPTO_SIG_IMPL_get_algorithm_oid(uint8_t *algorithm_name, uint8_t *oid, int32_t oid_length) {
	VEEPORT_LOGGER_LOG_DBG("");

	size_t nb_algorithms = sizeof(available_algorithms) / sizeof(available_algorithms[0]);
	LLCRYPTO_SIG_algorithm *algorithm = &available_algorithms[0];

	/* strncpy pads to the length it is given, so the claimed length has to fit the array
	 * before the OID is measured against it. */
	if ((oid_length <= 0) || !sni_array_contains_range(oid, 0, oid_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		bool found = false;
		for (size_t i = 0; i < nb_algorithms; i++) {
			if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
				found = true;
				int32_t length = strlen(algorithm->oid);
				if (length > (oid_length - 1)) {
					VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
					                                               "native oid length is bigger that the output byte array");
				} else {
					(void)strncpy((char *)oid, algorithm->oid, oid_length - 1);
					/* strncpy copied length bytes, so the terminator belongs at length. */
					oid[length] = '\0';
				}
				break;
			}
			algorithm++;
		}
		if (!found) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Algorithm not found");
		}
	}
}

uint8_t LLCRYPTO_SIG_IMPL_verify(int32_t algorithm_id, uint8_t *signature, int32_t signature_length, int32_t nativeId,
                                 uint8_t *digest, int32_t digest_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	int return_jcode = SNI_ERROR;

	LLCRYPTO_SIG_algorithm *algorithm = (LLCRYPTO_SIG_algorithm *)algorithm_id;

	/* Both lengths reach EVP_PKEY_verify as size_t, where a negative one becomes a huge
	 * read bound. */
	if (!sni_array_contains_range(signature, 0, signature_length) ||
	    !sni_array_contains_range(digest, 0, digest_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		int return_code = algorithm->verify(algorithm, signature, signature_length,
		                                    (const struct llcrypto_key *)nativeId, digest, digest_length);

		if (MICROEJ_LLCRYPTO_SIG_SUCCESS == return_code) {
			return_jcode = JTRUE;
		} else if (MICROEJ_LLCRYPTO_SIGNATURE_INVALID == return_code) {
			return_jcode = JFALSE;
		} else {
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
			return_jcode = SNI_ERROR;
		}
	}
	return return_jcode;
}

int32_t LLCRYPTO_SIG_IMPL_sign(int32_t algorithm_id, uint8_t *signature, int32_t signature_length, int32_t nativeId,
                               uint8_t *digest, int32_t digest_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	int return_jcode = SNI_ERROR;

	LLCRYPTO_SIG_algorithm *algorithm = (LLCRYPTO_SIG_algorithm *)algorithm_id;

	/* signature_length is the capacity of the signature array, not the size of the
	 * signature to come: the caller sizes that array from a runtime property. */
	if (!sni_array_contains_range(signature, 0, signature_length) ||
	    !sni_array_contains_range(digest, 0, digest_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		int32_t written = 0;
		int return_code = algorithm->sign(algorithm, signature, signature_length, &written,
		                                  (const struct llcrypto_key *)nativeId, digest, digest_length);

		if (MICROEJ_LLCRYPTO_SIG_BUFFER_TOO_SMALL == return_code) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Signature buffer too small");
		} else if (MICROEJ_LLCRYPTO_SIG_SUCCESS != return_code) {
			/* Leave SNI_ERROR: zero is a valid signature length, so it cannot report failure. */
			int err = ERR_get_error();
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
			                                               ERR_error_string(err, NULL));
		} else {
			return_jcode = written;
		}
	}
	return return_jcode;
}
