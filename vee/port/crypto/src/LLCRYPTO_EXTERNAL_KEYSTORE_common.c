/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief Shared implementation between the PKCS#11 and PKCS#12 External
 *        KeyStore backends. See LLCRYPTO_EXTERNAL_KEYSTORE_common.h for the
 *        rationale and API contract.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <LLCRYPTO_EXTERNAL_KEYSTORE_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_EXTERNAL_KEYSTORE_common.h"
#include "LLCRYPTO_key.h"

/** Highest code unit the password conversion accepts. */
#define LLCRYPTO_EKS_ASCII_MAX (0x7FU)

// -----------------------------------------------------------------------------
// SNI close functions
// -----------------------------------------------------------------------------

void llcrypto_eks_cert_free(struct llcrypto_eks_cert *c) {
	if (NULL != c) {
		if (SNI_OK != SNI_unregisterResource(c, (SNI_closeFunction)llcrypto_eks_cert_free)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Can't unregister SNI native resource");
		}
		LLCRYPTO_free(c->der_data);
		LLCRYPTO_free(c);
	}
}

void llcrypto_eks_chain_free(struct llcrypto_eks_chain *ch) {
	if (NULL != ch) {
		if (SNI_OK != SNI_unregisterResource(ch, (SNI_closeFunction)llcrypto_eks_chain_free)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Can't unregister SNI native resource");
		}
		for (int i = 0; i < ch->cert_count; i++) {
			if (NULL != ch->certs[i]) {
				LLCRYPTO_free(ch->certs[i]->der_data);
				LLCRYPTO_free(ch->certs[i]);
			}
		}
		LLCRYPTO_free(ch->certs);
		LLCRYPTO_free(ch);
	}
}

// -----------------------------------------------------------------------------
// String helpers
// -----------------------------------------------------------------------------

int llcrypto_eks_jchar_to_ascii_cstring(jchar *password, char **out, size_t *out_len) {
	int result = LLCRYPTO_ERROR_OOM;
	*out = NULL;
	*out_len = 0;

	jint array_len = 0;
	if (NULL != password) {
		array_len = sni_array_get_length(password);
	}

	char *buffer = (char *)LLCRYPTO_calloc(1, (size_t)array_len + 1U);
	if (NULL == buffer) {
		goto end;
	}

	for (jint i = 0; i < array_len; i++) {
		if ((0U == password[i]) || (password[i] > LLCRYPTO_EKS_ASCII_MAX)) {
			OPENSSL_cleanse(buffer, (size_t)array_len);
			LLCRYPTO_free(buffer);
			result = LLCRYPTO_ERROR;
			goto end;
		}
		buffer[i] = (char)password[i];
	}
	buffer[array_len] = '\0';

	*out = buffer;
	*out_len = (size_t)array_len;
	result = LLCRYPTO_SUCCESS;

end:
	return result;
}

// -----------------------------------------------------------------------------
// X509 → SNI cert blob
// -----------------------------------------------------------------------------

struct llcrypto_eks_cert *llcrypto_eks_x509_to_cert(X509 *cert) {
	struct llcrypto_eks_cert *result = NULL;

	int der_len = i2d_X509(cert, NULL);
	if (der_len <= 0) {
		goto end;
	}

	struct llcrypto_eks_cert *h = (struct llcrypto_eks_cert *)LLCRYPTO_calloc(1, sizeof(*h));
	if (NULL == h) {
		goto end;
	}
	h->der_data = (uint8_t *)LLCRYPTO_calloc(1, (size_t)der_len);
	if (NULL == h->der_data) {
		LLCRYPTO_free(h);
		goto end;
	}
	unsigned char *p = h->der_data;
	h->der_length = i2d_X509(cert, &p);
	if (h->der_length <= 0) {
		LLCRYPTO_free(h->der_data);
		LLCRYPTO_free(h);
		goto end;
	}
	result = h;

end:
	return result;
}

// -----------------------------------------------------------------------------
// Certificate chain walk
// -----------------------------------------------------------------------------

/* The certificate that issued @p cert, or NULL when @p cert is self-signed or when its issuer is
 * absent from @p all_certs. Both answers end the chain walk, so they share one return value. */
static X509 *find_issuer_cert(const X509 *cert, X509 **all_certs, int total_certs) {
	X509 *issuer = NULL;
	X509_NAME *issuer_name = X509_get_issuer_name(cert);

	if (0 != X509_NAME_cmp(issuer_name, X509_get_subject_name(cert))) {
		for (int i = 0; i < total_certs; i++) {
			if ((all_certs[i] != cert) &&
			    (0 == X509_NAME_cmp(X509_get_subject_name(all_certs[i]), issuer_name))) {
				issuer = all_certs[i];
				break;
			}
		}
	}
	return issuer;
}

struct llcrypto_eks_chain *llcrypto_eks_build_chain(
	const char *alias,
	X509 **all_certs,
	char (*cert_labels)[LLCRYPTO_EKS_MAX_ALIAS_LEN],
	int total_certs) {
	struct llcrypto_eks_chain *result = NULL;
	struct llcrypto_eks_cert *ordered[LLCRYPTO_EKS_MAX_OBJECTS];
	int chain_len = 0;

	/* Find the leaf cert by alias match. */
	X509 *leaf = NULL;
	for (int i = 0; i < total_certs; i++) {
		if (0 == strcasecmp(cert_labels[i], alias)) {
			leaf = all_certs[i];
			break;
		}
	}
	if (NULL == leaf) {
		goto end;
	}

	ordered[chain_len] = llcrypto_eks_x509_to_cert(leaf);
	if (NULL == ordered[chain_len]) {
		goto end;
	}
	chain_len++;

	/* Walk up while there is an issuer to add and room to hold it. A self-signed root and an
	 * issuer that is absent from the keystore both surface as a NULL parent, which ends the walk
	 * with whatever the chain holds so far. */
	X509 *parent = find_issuer_cert(leaf, all_certs, total_certs);
	while ((NULL != parent) && (chain_len < LLCRYPTO_EKS_MAX_OBJECTS)) {
		ordered[chain_len] = llcrypto_eks_x509_to_cert(parent);
		if (NULL == ordered[chain_len]) {
			break;
		}
		chain_len++;
		parent = find_issuer_cert(parent, all_certs, total_certs);
	}

	/* Build the SNI-managed chain handle. */
	struct llcrypto_eks_chain *chain = (struct llcrypto_eks_chain *)LLCRYPTO_calloc(1, sizeof(*chain));
	if (NULL == chain) {
		goto cleanup_ordered;
	}
	chain->certs = (struct llcrypto_eks_cert **)LLCRYPTO_calloc((size_t)chain_len, sizeof(struct llcrypto_eks_cert *));
	if (NULL == chain->certs) {
		LLCRYPTO_free(chain);
		goto cleanup_ordered;
	}
	for (int i = 0; i < chain_len; i++) {
		chain->certs[i] = ordered[i];
	}
	chain->cert_count = chain_len;

	if (SNI_OK != SNI_registerResource(chain, (SNI_closeFunction)llcrypto_eks_chain_free, NULL)) {
		LLCRYPTO_free(chain->certs);
		LLCRYPTO_free(chain);
		goto cleanup_ordered;
	}

	result = chain;
	goto end;

cleanup_ordered:
	for (int i = 0; i < chain_len; i++) {
		LLCRYPTO_free(ordered[i]->der_data);
		LLCRYPTO_free(ordered[i]);
	}

end:
	return result;
}

// -----------------------------------------------------------------------------
// LLAPI entry points whose implementation is backend-agnostic
// -----------------------------------------------------------------------------

/*
 * The LLAPI grants no capacity for `algorithm`: the Java side sizes it from the
 * ej.crypto.externalks.algorithm.max.length constant, which an application may set to
 * anything. The name is therefore selected first and written once, past a check against the
 * array's real length, rather than copied on a claim about what the caller allocated.
 */
void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyAlgorithm(jint key_id, jbyte *algorithm) {
	struct llcrypto_key *key = (struct llcrypto_key *)key_id;
	const char *name = NULL;

	if (LLCRYPTO_KEY_TYPE_EVP_PKEY == key->type) {
		int base_id = EVP_PKEY_base_id(key->evp_key);
		if (EVP_PKEY_RSA == base_id) {
			name = "RSA";
		} else if (EVP_PKEY_EC == base_id) {
			name = "EC";
		} else if (EVP_PKEY_ED25519 == base_id) {
			name = "Ed25519";
		} else if (EVP_PKEY_ED448 == base_id) {
			name = "Ed448";
		} else {
			name = "UNKNOWN";
		}
	} else if (LLCRYPTO_KEY_TYPE_SECRET_KEY == key->type) {
		/* Heap-allocated from the key's own algorithm string, so it has no compile-time bound. */
		name = (NULL != key->secret_key.algorithm) ? key->secret_key.algorithm : "AES";
	} else {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Unknown key type");
	}

	if (NULL != name) {
		/* One past the name for the terminator the Java side scans for. */
		size_t name_size = strlen(name) + 1U;
		if (!sni_array_contains_range(algorithm, 0, (int32_t)name_size)) {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Invalid buffer offset or length");
		} else {
			(void)strcpy((char *)algorithm, name);
		}
	}
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateSize(jint handle) {
	struct llcrypto_eks_cert *c = (struct llcrypto_eks_cert *)handle;
	return (jint)c->der_length;
}

void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateData(jint handle, jbyte *buffer) {
	struct llcrypto_eks_cert *c = (struct llcrypto_eks_cert *)handle;

	/* The Java side sizes this array from getCertificateSize() on the same handle, so the two
	 * agree today, but the LLAPI grants no capacity — the agreement is checked, not assumed. */
	if (!sni_array_contains_range(buffer, 0, (int32_t)c->der_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
	} else {
		(void)memcpy(buffer, c->der_data, (size_t)c->der_length);
	}
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainLength(jint handle) {
	struct llcrypto_eks_chain *chain = (struct llcrypto_eks_chain *)handle;
	return (jint)chain->cert_count;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateFromChain(jint handle, jint cert_index) {
	jint result = LLCRYPTO_ERROR;

	struct llcrypto_eks_chain *chain = (struct llcrypto_eks_chain *)handle;
	if ((cert_index < 0) || (cert_index >= chain->cert_count)) {
		goto end;
	}

	result = (jint)chain->certs[cert_index];

end:
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_closeCertificateChainHandle(jint handle) {
	struct llcrypto_eks_chain *chain = (struct llcrypto_eks_chain *)handle;
	llcrypto_eks_chain_free(chain);
	return LLCRYPTO_SUCCESS;
}

/* The mutating LLAPI entry points (getEntryType, deleteEntry,
 * setCertificateEntry, openKeyEntryWith*, closeKeyEntry) are backend-
 * specific because they touch the token / .p12 file directly. They live in
 * LLCRYPTO_EXTERNAL_KEYSTORE_pkcs11.c and LLCRYPTO_EXTERNAL_KEYSTORE_pkcs12.c
 * respectively. insertCertificateInChain only buffers DER bytes into the
 * shared import handle, so it is implemented here. */

// -----------------------------------------------------------------------------
// Shared setKeyEntry import handle (used by both backends)
// -----------------------------------------------------------------------------

struct llcrypto_eks_key_import *llcrypto_eks_key_import_new(const char *alias, int chain_len) {
	struct llcrypto_eks_key_import *result = NULL;
	struct llcrypto_eks_key_import *h = NULL;

	/* An alias that does not fit is rejected, not truncated. Truncating commits the entry under a
	 * name no later getKey / deleteEntry can match, and can silently overwrite an unrelated entry
	 * that shares the truncated prefix. The PKCS#11 read paths already reject for the same reason. */
	if (strlen(alias) >= LLCRYPTO_EKS_MAX_ALIAS_LEN) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Alias too long for the keystore");
		goto end;
	}

	h = (struct llcrypto_eks_key_import *)LLCRYPTO_calloc(1, sizeof(*h));
	if (NULL != h) {
		(void)strcpy(h->alias, alias);
		h->chain_len = chain_len;
		if (chain_len > 0) {
			h->chain_certs = (struct llcrypto_eks_chain_cert *)LLCRYPTO_calloc(
				(size_t)chain_len, sizeof(*h->chain_certs));
			if (NULL == h->chain_certs) {
				LLCRYPTO_free(h);
				h = NULL;
			}
		}
	}

	if (NULL == h) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Out of memory");
	} else {
		result = h;
	}

end:
	return result;
}

void llcrypto_eks_key_import_free(struct llcrypto_eks_key_import *h) {
	if (NULL == h) {
		return;
	}
	EVP_PKEY_free(h->key_evp);
	if (NULL != h->chain_certs) {
		for (int i = 0; i < h->chain_len; i++) {
			LLCRYPTO_free(h->chain_certs[i].der);
		}
		LLCRYPTO_free(h->chain_certs);
	}
	LLCRYPTO_free(h);
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_insertCertificateInChain(jint handle, jint cert_index, jbyte *certificate) {
	jint result = LLCRYPTO_ERROR;

	struct llcrypto_eks_key_import *h = (struct llcrypto_eks_key_import *)handle;
	/* Require strictly contiguous inserts (cert_index == chain_count). The
	 * sole Java caller iterates 0..chainLength-1 sequentially, so this
	 * matches the contract; rejecting holes keeps closeKeyEntry from
	 * later dereferencing a NULL chain_certs[i].der. */
	if ((NULL == h) || (cert_index != h->chain_count) || (cert_index >= h->chain_len)) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Invalid chain index");
		goto end;
	}
	jint cert_len = sni_array_get_length((void *)certificate);
	if (cert_len <= 0) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Empty certificate in chain");
		goto end;
	}
	uint8_t *copy = (uint8_t *)LLCRYPTO_calloc(1, (size_t)cert_len);
	if (NULL == copy) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Out of memory");
		goto end;
	}
	(void)memcpy(copy, certificate, (size_t)cert_len);
	h->chain_certs[cert_index].der = copy;
	h->chain_certs[cert_index].len = (int)cert_len;
	h->chain_count = cert_index + 1;
	result = LLCRYPTO_SUCCESS;

end:
	return result;
}
