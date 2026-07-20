/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include "LLCRYPTO_configuration.h"
#include <LLCRYPTO_CERT_PATH_VALIDATOR_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdint.h>
#include <sni.h>

// #define LLCRYPTO_CPV_DEBUG_TRACE

#ifdef LLCRYPTO_CPV_DEBUG_TRACE
#include <stdio.h>
#define LLCRYPTO_CPV_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_CPV_DEBUG_PRINTF(...) ((void)0)
#endif

/**
 * Internal state for a CertPathValidator instance.
 * Uses plain X509 stacks for both trust store and chain to allow
 * fully manual validation without OpenSSL's X509_verify_cert opinions.
 */
struct llcrypto_cert_path_validator {
	STACK_OF(X509) * trusted_certs; /* trusted certificates (CAs or leaf trust anchors) */
	STACK_OF(X509) * cert_chain;    /* ordered certificate path to validate (forward order) */
};

/**
 * Parse a DER-encoded X.509 certificate from a Java byte[].
 * Uses SNI_getArrayLength to determine the buffer size.
 */
static X509 *llcrypto_cpv_parse_x509(uint8_t *x509_der) {
	X509 *result = NULL;
	int32_t len = SNI_getArrayLength(x509_der);
	if (len > 0) {
		const unsigned char *p = (const unsigned char *)x509_der;
		result = d2i_X509(NULL, &p, (long)len);
	}
	return result;
}

/**
 * Find a trusted certificate whose subject matches the given name.
 * Returns the first match or NULL.
 */
static X509 *llcrypto_cpv_find_trusted_by_subject(const struct llcrypto_cert_path_validator *cpv, X509_NAME *name) {
	X509 *result = NULL;
	int n = sk_X509_num(cpv->trusted_certs);
	for (int i = 0; (i < n) && (NULL == result); i++) {
		X509 *trusted = sk_X509_value(cpv->trusted_certs, i);
		if (X509_NAME_cmp(X509_get_subject_name(trusted), name) == 0) {
			result = trusted;
		}
	}
	return result;
}

int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_new_cert_path_validator(void) {
	LLCRYPTO_CPV_DEBUG_PRINTF("%s\n", __func__);
	int32_t return_code = LLCRYPTO_ERROR_OOM;

	struct llcrypto_cert_path_validator *cpv = LLCRYPTO_calloc(1, sizeof(struct llcrypto_cert_path_validator));
	if (NULL == cpv) {
		goto end;
	}

	cpv->trusted_certs = sk_X509_new_null();
	if (NULL == cpv->trusted_certs) {
		LLCRYPTO_free(cpv);
		goto end;
	}

	cpv->cert_chain = sk_X509_new_null();
	if (NULL == cpv->cert_chain) {
		sk_X509_free(cpv->trusted_certs);
		LLCRYPTO_free(cpv);
		goto end;
	}

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	return_code = (int32_t)cpv;

end:
	return return_code;
}

int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate(int32_t cpv_handle, uint8_t *x509_der) {
	LLCRYPTO_CPV_DEBUG_PRINTF("%s\n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	struct llcrypto_cert_path_validator *cpv = (struct llcrypto_cert_path_validator *)cpv_handle;
	int32_t return_code = LLCRYPTO_ERROR;

	X509 *cert = llcrypto_cpv_parse_x509(x509_der);
	if (NULL == cert) {
		goto end;
	}

	if (sk_X509_push(cpv->trusted_certs, cert) == 0) {
		X509_free(cert);
		return_code = LLCRYPTO_ERROR_OOM;
		goto end;
	}

	return_code = LLCRYPTO_SUCCESS;

end:
	return return_code;
}

jboolean LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_expect_forward_cert_path(void) {
	LLCRYPTO_CPV_DEBUG_PRINTF("%s\n", __func__);
	/* Forward order: target certificate first, then intermediate CAs toward the root */
	return (jboolean)JTRUE;
}

int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path(int32_t cpv_handle, uint8_t *x509_der) {
	LLCRYPTO_CPV_DEBUG_PRINTF("%s\n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	struct llcrypto_cert_path_validator *cpv = (struct llcrypto_cert_path_validator *)cpv_handle;
	int32_t return_code = LLCRYPTO_ERROR;

	X509 *cert = llcrypto_cpv_parse_x509(x509_der);
	if (NULL == cert) {
		goto end;
	}

	if (sk_X509_push(cpv->cert_chain, cert) == 0) {
		X509_free(cert);
		return_code = LLCRYPTO_ERROR_OOM;
		goto end;
	}

	/* cert ownership transferred to the stack */
	return_code = LLCRYPTO_SUCCESS;

end:
	return return_code;
}

int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_validate_cert_path(int32_t cpv_handle) {
	LLCRYPTO_CPV_DEBUG_PRINTF("%s\n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	struct llcrypto_cert_path_validator *cpv = (struct llcrypto_cert_path_validator *)cpv_handle;
	int32_t return_code = LLCRYPTO_SUCCESS;

	int num_certs = sk_X509_num(cpv->cert_chain);

	/*
	 * Step 1: Verify issuer/subject name chaining along the path.
	 * Each cert[i] must be issued by cert[i+1].
	 */
	for (int i = 0; (i < num_certs - 1) && (LLCRYPTO_SUCCESS == return_code); i++) {
		X509 *cert = sk_X509_value(cpv->cert_chain, i);
		X509 *next = sk_X509_value(cpv->cert_chain, i + 1);
		if (X509_NAME_cmp(X509_get_issuer_name(cert), X509_get_subject_name(next)) != 0) {
			LLCRYPTO_CPV_DEBUG_PRINTF("%s: name chaining mismatch at index %d\n", __func__, i);
			return_code = LLCRYPTO_ERROR;
		}
	}

	/*
	 * Step 2: Verify signatures along the chain.
	 * Each cert[i] must be verifiable by cert[i+1]'s public key.
	 */
	for (int i = 0; (i < num_certs - 1) && (LLCRYPTO_SUCCESS == return_code); i++) {
		X509 *cert = sk_X509_value(cpv->cert_chain, i);
		X509 *issuer = sk_X509_value(cpv->cert_chain, i + 1);
		EVP_PKEY *issuer_key = X509_get_pubkey(issuer);
		if (NULL == issuer_key) {
			LLCRYPTO_CPV_DEBUG_PRINTF("%s: cannot extract public key at index %d\n", __func__, i + 1);
			return_code = LLCRYPTO_ERROR;
		} else {
			int rc = X509_verify(cert, issuer_key);
			EVP_PKEY_free(issuer_key);
			if (rc != 1) {
				LLCRYPTO_CPV_DEBUG_PRINTF("%s: signature verification failed at index %d\n", __func__, i);
				return_code = LLCRYPTO_ERROR;
			}
		}
	}

	/*
	 * Step 3: The last certificate in the chain (or the only one) must be
	 * verifiable by a trusted certificate whose subject matches its issuer.
	 */
	if ((LLCRYPTO_SUCCESS == return_code) && (num_certs > 0)) {
		X509 *last = sk_X509_value(cpv->cert_chain, num_certs - 1);
		X509_NAME *issuer_name = X509_get_issuer_name(last);
		X509 *trusted = llcrypto_cpv_find_trusted_by_subject(cpv, issuer_name);

		if (NULL == trusted) {
			LLCRYPTO_CPV_DEBUG_PRINTF("%s: no trusted certificate found for chain root\n", __func__);
			return_code = LLCRYPTO_ERROR;
		} else {
			EVP_PKEY *trusted_key = X509_get_pubkey(trusted);
			if (NULL == trusted_key) {
				LLCRYPTO_CPV_DEBUG_PRINTF("%s: cannot extract trusted certificate public key\n", __func__);
				return_code = LLCRYPTO_ERROR;
			} else {
				int rc = X509_verify(last, trusted_key);
				EVP_PKEY_free(trusted_key);
				if (rc != 1) {
					LLCRYPTO_CPV_DEBUG_PRINTF("%s: chain root not verified by trusted certificate\n", __func__);
					return_code = LLCRYPTO_ERROR;
				}
			}
		}
	}

	return return_code;
}

void LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_close_cert_path_validator(int32_t cpv_handle) {
	LLCRYPTO_CPV_DEBUG_PRINTF("%s\n", __func__);

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	struct llcrypto_cert_path_validator *cpv = (struct llcrypto_cert_path_validator *)cpv_handle;

	if (NULL != cpv) {
		if (NULL != cpv->cert_chain) {
			while (sk_X509_num(cpv->cert_chain) > 0) {
				X509 *cert = sk_X509_pop(cpv->cert_chain);
				X509_free(cert);
			}
			sk_X509_free(cpv->cert_chain);
		}
		if (NULL != cpv->trusted_certs) {
			while (sk_X509_num(cpv->trusted_certs) > 0) {
				X509 *cert = sk_X509_pop(cpv->trusted_certs);
				X509_free(cert);
			}
			sk_X509_free(cpv->trusted_certs);
		}
		LLCRYPTO_free(cpv);
	}
}
