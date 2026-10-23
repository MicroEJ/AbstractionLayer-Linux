/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdbool.h>
#include <stdint.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <LLCRYPTO_CERT_PATH_VALIDATOR_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

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
 * Uses sni_array_get_length to determine the buffer size.
 */
static X509 *llcrypto_cpv_parse_x509(uint8_t *x509_der) {
	X509 *result = NULL;
	int32_t len = sni_array_get_length(x509_der);
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
		if (0 == X509_NAME_cmp(X509_get_subject_name(trusted), name)) {
			result = trusted;
		}
	}
	return result;
}

/**
 * Check the certificate is within its validity period.
 * X509_cmp_current_time returns 0 on a malformed time, which both comparisons
 * reject.
 */
static bool llcrypto_cpv_time_valid(X509 *cert) {
	return (X509_cmp_current_time(X509_get0_notBefore(cert)) < 0)
	       && (X509_cmp_current_time(X509_get0_notAfter(cert)) > 0);
}

/**
 * Check the certificate is allowed to issue the @p intermediates_below
 * intermediate CAs and the end-entity certificate below it in the path: it must
 * be a CA, allowed to sign certificates, and its path length constraint must
 * cover the certificates it certifies.
 *
 * X509_get_key_usage returns UINT32_MAX when the extension is absent, which is
 * RFC 5280's "absent means every usage is allowed". X509_get_pathlen returns
 * -1 when basicConstraints carries no pathLenConstraint, i.e. unlimited.
 */
static bool llcrypto_cpv_issuer_valid(X509 *issuer, int intermediates_below) {
	long path_len = X509_get_pathlen(issuer);
	return (0 != X509_check_ca(issuer))
	       && ((X509_get_key_usage(issuer) & (uint32_t)KU_KEY_CERT_SIGN) != 0U)
	       && ((path_len < 0) || (path_len >= (long)intermediates_below));
}

int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_new_cert_path_validator(void) {
	VEEPORT_LOGGER_LOG_DBG("");
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

	return_code = (int32_t)cpv;

end:
	return return_code;
}

int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate(int32_t cpv_handle, uint8_t *x509_der) {
	VEEPORT_LOGGER_LOG_DBG("");

	struct llcrypto_cert_path_validator *cpv = (struct llcrypto_cert_path_validator *)cpv_handle;
	int32_t return_code = LLCRYPTO_ERROR;

	X509 *cert = llcrypto_cpv_parse_x509(x509_der);
	if (NULL == cert) {
		goto end;
	}

	if (0 == sk_X509_push(cpv->trusted_certs, cert)) {
		X509_free(cert);
		return_code = LLCRYPTO_ERROR_OOM;
		goto end;
	}

	return_code = LLCRYPTO_SUCCESS;

end:
	return return_code;
}

jboolean LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_expect_forward_cert_path(void) {
	VEEPORT_LOGGER_LOG_DBG("");
	/* Forward order: target certificate first, then intermediate CAs toward the root */
	return (jboolean)JTRUE;
}

int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path(int32_t cpv_handle, uint8_t *x509_der) {
	VEEPORT_LOGGER_LOG_DBG("");

	struct llcrypto_cert_path_validator *cpv = (struct llcrypto_cert_path_validator *)cpv_handle;
	int32_t return_code = LLCRYPTO_ERROR;

	X509 *cert = llcrypto_cpv_parse_x509(x509_der);
	if (NULL == cert) {
		goto end;
	}

	if (0 == sk_X509_push(cpv->cert_chain, cert)) {
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
	VEEPORT_LOGGER_LOG_DBG("");

	struct llcrypto_cert_path_validator *cpv = (struct llcrypto_cert_path_validator *)cpv_handle;
	int32_t return_code = LLCRYPTO_SUCCESS;

	int num_certs = sk_X509_num(cpv->cert_chain);

	/*
	 * Step 1: Every certificate in the path must be within its validity period.
	 * The trust anchors are not checked here: RFC 5280 section 6.1 does not
	 * process trust anchor constraints, and the application chose them.
	 */
	for (int i = 0; (i < num_certs) && (LLCRYPTO_SUCCESS == return_code); i++) {
		X509 *cert = sk_X509_value(cpv->cert_chain, i);
		if (!llcrypto_cpv_time_valid(cert)) {
			VEEPORT_LOGGER_LOG_ERR("certificate at index %d is not valid at this time", i);
			return_code = LLCRYPTO_ERROR;
		}
	}

	/*
	 * Step 2: Verify issuer/subject name chaining along the path.
	 * Each cert[i] must be issued by cert[i+1].
	 */
	for (int i = 0; (i < (num_certs - 1)) && (LLCRYPTO_SUCCESS == return_code); i++) {
		X509 *cert = sk_X509_value(cpv->cert_chain, i);
		X509 *next = sk_X509_value(cpv->cert_chain, i + 1);
		if (0 != X509_NAME_cmp(X509_get_issuer_name(cert), X509_get_subject_name(next))) {
			VEEPORT_LOGGER_LOG_ERR("name chaining mismatch at index %d", i);
			return_code = LLCRYPTO_ERROR;
		}
	}

	/*
	 * Step 3: Verify signatures along the chain, and that each certificate
	 * acting as an issuer is entitled to. The path is in forward order, so the
	 * issuer at index i+1 certifies the end-entity certificate at index 0 and
	 * the i intermediate CAs between them.
	 */
	for (int i = 0; (i < (num_certs - 1)) && (LLCRYPTO_SUCCESS == return_code); i++) {
		X509 *cert = sk_X509_value(cpv->cert_chain, i);
		X509 *issuer = sk_X509_value(cpv->cert_chain, i + 1);
		if (!llcrypto_cpv_issuer_valid(issuer, i)) {
			VEEPORT_LOGGER_LOG_ERR("certificate at index %d cannot issue certificates", i + 1);
			return_code = LLCRYPTO_ERROR;
		} else {
			EVP_PKEY *issuer_key = X509_get_pubkey(issuer);
			if (NULL == issuer_key) {
				VEEPORT_LOGGER_LOG_ERR("cannot extract public key at index %d", i + 1);
				return_code = LLCRYPTO_ERROR;
			} else {
				int rc = X509_verify(cert, issuer_key);
				EVP_PKEY_free(issuer_key);
				if (1 != rc) {
					VEEPORT_LOGGER_LOG_ERR("signature verification failed at index %d", i);
					return_code = LLCRYPTO_ERROR;
				}
			}
		}
	}

	/*
	 * Step 4: The last certificate in the chain (or the only one) must be
	 * verifiable by a trusted certificate whose subject matches its issuer.
	 */
	if ((LLCRYPTO_SUCCESS == return_code) && (num_certs > 0)) {
		X509 *last = sk_X509_value(cpv->cert_chain, num_certs - 1);
		X509_NAME *issuer_name = X509_get_issuer_name(last);
		X509 *trusted = llcrypto_cpv_find_trusted_by_subject(cpv, issuer_name);

		if (NULL == trusted) {
			VEEPORT_LOGGER_LOG_ERR("no trusted certificate found for chain root");
			return_code = LLCRYPTO_ERROR;
		} else {
			EVP_PKEY *trusted_key = X509_get_pubkey(trusted);
			if (NULL == trusted_key) {
				VEEPORT_LOGGER_LOG_ERR("cannot extract trusted certificate public key");
				return_code = LLCRYPTO_ERROR;
			} else {
				int rc = X509_verify(last, trusted_key);
				EVP_PKEY_free(trusted_key);
				if (1 != rc) {
					VEEPORT_LOGGER_LOG_ERR("chain root not verified by trusted certificate");
					return_code = LLCRYPTO_ERROR;
				}
			}
		}
	}

	return return_code;
}

void LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_close_cert_path_validator(int32_t cpv_handle) {
	VEEPORT_LOGGER_LOG_DBG("");

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
