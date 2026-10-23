/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <LLCRYPTO_X509_CERT_impl.h>
#include <LLCRYPTO_CONSTANTS.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

/* Most OpenSSL functions return 1 on success. This is that value, not an LLAPI return code. */
#define MICROEJ_LLCRYPTO_OPENSSL_SUCCESS (1)

#define MICROEJ_LLCRYPTO_X509_DER_FORMAT      (int)(1)
#define MICROEJ_LLCRYPTO_X509_PEM_FORMAT      (int)(0)
#define MICROEJ_LLCRYPTO_X509_UNKNOWN_FORMAT  (int)(-1)

/**
 * Try to parse @p cert_data as a DER certificate, then as PEM.
 *
 * @return a new certificate the caller must X509_free, or NULL if neither format parses.
 */
static X509 * try_parse_x509_certificate(int8_t * cert_data, int32_t len, int *cert_format) {
	VEEPORT_LOGGER_LOG_DBG("");
	/* d2i_X509 advances the pointer it is given, and is only documented to do so on success. It
	 * gets this throwaway copy so cert_data and len stay a matching pair for the PEM attempt
	 * below, which would otherwise read len bytes from an already-advanced start — past the end
	 * of the array. */
	const unsigned char *der = (const unsigned char *)cert_data;
	X509 *x509 = d2i_X509(NULL, &der, len);
	if (NULL != x509) {
		if (NULL != cert_format) {
			*cert_format = MICROEJ_LLCRYPTO_X509_DER_FORMAT;
		}
	} else {
		BIO *bp = BIO_new_mem_buf(cert_data, len);
		if (NULL != bp) {
			x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);
			BIO_free_all(bp);
		}
		if (NULL != cert_format) {
			if (NULL != x509) {
				*cert_format = MICROEJ_LLCRYPTO_X509_PEM_FORMAT;
			} else {
				*cert_format = MICROEJ_LLCRYPTO_X509_UNKNOWN_FORMAT;
			}
		}
	}
	return x509;
}

int32_t LLCRYPTO_X509_CERT_IMPL_parse(int8_t *cert, int32_t off, int32_t len) {
	VEEPORT_LOGGER_LOG_DBG("");
	int cert_format = MICROEJ_LLCRYPTO_X509_UNKNOWN_FORMAT;
	/* off and len index the array below, and try_parse_x509_certificate receives the interior
	 * pointer, where the array length is no longer recoverable. Bound them here. An
	 * out-of-bounds range is reported as an unknown format, like any content this native
	 * cannot parse: it has no throw path. */
	if (sni_array_contains_range(cert, off, len)) {
		X509 *x509 = try_parse_x509_certificate(&cert[off], len, &cert_format);
		X509_free(x509);
	}
	return cert_format;
}

int32_t LLCRYPTO_X509_CERT_IMPL_get_key(int8_t *cert_data, int32_t cert_data_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	int32_t return_code = LLCRYPTO_ERROR;

	if (!sni_array_contains_range(cert_data, 0, cert_data_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		X509 *x509 = try_parse_x509_certificate(cert_data, cert_data_length, NULL);
		if (NULL == x509) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Bad x509 certificate");
		} else {
			EVP_PKEY *evp_key = X509_get_pubkey(x509);
			X509_free(x509);

			if (NULL == evp_key) {
				VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
				                                               "Invalid public key from x509 certificate");
			} else {
				struct llcrypto_key *key = llcrypto_key_from_evp_pkey(evp_key);
				if (NULL == key) {
					VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_OOM_EXCEPTION,
					                                               "Cannot allocate the key structure");
					EVP_PKEY_free(evp_key);
				} else {
					return_code = (int32_t)key;
				}
			}
		}
	}

	return return_code;
}

int32_t LLCRYPTO_X509_CERT_IMPL_verify(int8_t *cert_data, int32_t cert_data_length, int32_t native_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	const struct llcrypto_key *pub_key = (const struct llcrypto_key *)native_id;
	/* Verification is a security boundary, so the value returned when nothing set it says "not verified". */
	int32_t return_code = LLCRYPTO_X509_SIGNATURE_EXCEPTION;
	bool can_verify = false;
	X509 *x509 = NULL;

	if (!sni_array_contains_range(cert_data, 0, cert_data_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		x509 = try_parse_x509_certificate(cert_data, cert_data_length, NULL);
		if (NULL == x509) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Bad x509 certificate");
			return_code = LLCRYPTO_X509_CERTIFICATE_EXCEPTION;
		} else {
			can_verify = true;
		}
	}

	if (can_verify) {
		int rc = X509_verify(x509, pub_key->evp_key);
		if (MICROEJ_LLCRYPTO_OPENSSL_SUCCESS == rc) {
			return_code = LLCRYPTO_SUCCESS;
		} else {
			VEEPORT_LOGGER_LOG_ERR("verify error");
			return_code = LLCRYPTO_X509_SIGNATURE_EXCEPTION;
		}
	}

	X509_free(x509);
	return return_code;
}

int32_t LLCRYPTO_X509_CERT_IMPL_get_x500_principal_data(int8_t *cert_data, int32_t cert_data_length,
                                                        uint8_t *principal_data, int32_t principal_data_length,
                                                        uint8_t get_issuer) {
	VEEPORT_LOGGER_LOG_DBG("");
	const X509_NAME *name = NULL;
	char *data = NULL;
	size_t length = 0;
	int32_t return_code = LLCRYPTO_ERROR;
	bool can_continue = true;

	X509 *x509 = NULL;

	if (!sni_array_contains_range(cert_data, 0, cert_data_length) ||
	    !sni_array_contains_range(principal_data, 0, principal_data_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		can_continue = false;
	}

	if (can_continue) {
		x509 = try_parse_x509_certificate(cert_data, cert_data_length, NULL);
		if (NULL == x509) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Bad x509 certificate");
			can_continue = false;
		}
	}

	if (can_continue) {
		if ((uint8_t)1 == get_issuer) {
			name = X509_get_issuer_name(x509);
		} else {
			name = X509_get_subject_name(x509);
		}

		if (NULL == name) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Null name.");
			can_continue = false;
		}
	}

	if (can_continue) {
		if (MICROEJ_LLCRYPTO_OPENSSL_SUCCESS !=
		    X509_NAME_get0_der(name, (const unsigned char **)&data, &length)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Null or bad encoding name.");
			can_continue = false;
		}
	}

	if (can_continue) {
		/* principal_data_length is known non-negative here, so the conversion below is
		 * faithful. Without that guarantee a negative length becomes a huge size_t and
		 * this comparison lets the copy through. */
		if (length > (size_t)principal_data_length) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "The principal data buffer is too small");
			can_continue = false;
		}
	}

	if (can_continue) {
		/* data points into x509's own storage, so the copy must happen before the free below. */
		(void)memcpy(principal_data, data, length);
		return_code = (int32_t)length;
	}

	/* X509_free is a no-op on NULL, so the failure paths above need no guard. */
	X509_free(x509);

	return return_code;
}

int32_t LLCRYPTO_X509_CERT_IMPL_get_close_key() {
	VEEPORT_LOGGER_LOG_DBG("");
	return (int32_t)llcrypto_key_free;
}

int32_t LLCRYPTO_X509_CERT_IMPL_check_validity(int8_t *cert_data, int32_t cert_data_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	/* J_SEC_NO_ERROR, the value that says the certificate is valid, is 0. The value returned when nothing set it
	 * must therefore not be 0, or every path that leaves it untouched reports a valid certificate. */
	int32_t return_code = LLCRYPTO_ERROR;
	bool can_check = true;

	int cert_format = MICROEJ_LLCRYPTO_X509_UNKNOWN_FORMAT;
	X509 *x509 = NULL;

	if (!sni_array_contains_range(cert_data, 0, cert_data_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		can_check = false;
	}

	if (can_check) {
		x509 = try_parse_x509_certificate(cert_data, cert_data_length, &cert_format);
		if (NULL == x509) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Bad x509 certificate");
			can_check = false;
		}
	}

	if (can_check) {
		const ASN1_TIME *notBefore = X509_get_notBefore(x509);
		const ASN1_TIME *notAfter = X509_get_notAfter(x509);

		if (X509_cmp_current_time(notBefore) > 0) {
			VEEPORT_LOGGER_LOG_ERR("certificate not yet valid");
			return_code = J_X509_CERT_NOT_YET_VALID_ERROR;
		} else if (X509_cmp_current_time(notAfter) < 0) {
			VEEPORT_LOGGER_LOG_ERR("certificate expired");
			return_code = J_X509_CERT_EXPIRED_ERROR;
		} else {
			return_code = J_SEC_NO_ERROR;
		}
	}

	X509_free(x509);

	return return_code;
}
