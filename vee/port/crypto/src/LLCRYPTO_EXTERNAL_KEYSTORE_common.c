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

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"
#include "LLCRYPTO_EXTERNAL_KEYSTORE_common.h"
#include <LLCRYPTO_EXTERNAL_KEYSTORE_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// SNI close functions
// -----------------------------------------------------------------------------

void llcrypto_eks_cert_free(struct llcrypto_eks_cert *c) {
	if (c != NULL) {
		if (SNI_unregisterResource(c, (SNI_closeFunction)llcrypto_eks_cert_free) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource\n");
		}
		LLCRYPTO_free(c->der_data);
		LLCRYPTO_free(c);
	}
}

void llcrypto_eks_chain_free(struct llcrypto_eks_chain *ch) {
	if (ch != NULL) {
		if (SNI_unregisterResource(ch, (SNI_closeFunction)llcrypto_eks_chain_free) != SNI_OK) {
			(void)SNI_throwNativeException(SNI_ERROR, "Can't unregister SNI native resource\n");
		}
		for (int i = 0; i < ch->count; i++) {
			if (ch->certs[i] != NULL) {
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

char *llcrypto_eks_jchar_to_cstring(const jchar *password) {
	char *result = NULL;

	if (password == NULL) {
		result = (char *)LLCRYPTO_calloc(1, 1);
		goto end;
	}

	jint array_len = SNI_getArrayLength((void *)password);
	char *out = (char *)LLCRYPTO_calloc(1, (size_t)array_len + 1);
	if (out == NULL) {
		goto end;
	}
	for (jint i = 0; i < array_len; i++) {
		out[i] = (char)(password[i] & 0xFF); /* take low byte — sufficient for ASCII passwords */
	}
	out[array_len] = '\0';
	result = out;

end:
	return result;
}

int llcrypto_eks_strcasecmp(const char *a, const char *b) {
	int diff = 0;
	while (*a && *b) {
		diff = tolower((unsigned char)*a) - tolower((unsigned char)*b);
		if (diff != 0) {
			goto end;
		}
		a++;
		b++;
	}
	diff = tolower((unsigned char)*a) - tolower((unsigned char)*b);
end:
	return diff;
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
	if (h == NULL) {
		goto end;
	}
	h->der_data = (uint8_t *)LLCRYPTO_calloc(1, (size_t)der_len);
	if (h->der_data == NULL) {
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
		if (llcrypto_eks_strcasecmp(cert_labels[i], alias) == 0) {
			leaf = all_certs[i];
			break;
		}
	}
	if (leaf == NULL) {
		goto end;
	}

	ordered[chain_len] = llcrypto_eks_x509_to_cert(leaf);
	if (ordered[chain_len] == NULL) {
		goto end;
	}
	chain_len++;

	/* Walk up: issuer == some other cert's subject. Stop at self-signed or
	 * when the issuer is not found in the array. */
	X509 *current = leaf;
	for (int depth = 0; depth < LLCRYPTO_EKS_MAX_OBJECTS; depth++) {
		X509_NAME *issuer_name = X509_get_issuer_name(current);
		X509_NAME *subject_name = X509_get_subject_name(current);

		if (X509_NAME_cmp(issuer_name, subject_name) == 0) {
			break; /* self-signed root */
		}

		X509 *parent = NULL;
		for (int i = 0; i < total_certs; i++) {
			if (all_certs[i] == current) {
				continue;
			}
			if (X509_NAME_cmp(X509_get_subject_name(all_certs[i]), issuer_name) == 0) {
				parent = all_certs[i];
				break;
			}
		}
		if (parent == NULL) {
			break; /* partial chain — issuer not in the keystore */
		}

		if (chain_len >= LLCRYPTO_EKS_MAX_OBJECTS) {
			break;
		}
		ordered[chain_len] = llcrypto_eks_x509_to_cert(parent);
		if (ordered[chain_len] == NULL) {
			break;
		}
		chain_len++;
		current = parent;
	}

	/* Build the SNI-managed chain handle. */
	struct llcrypto_eks_chain *chain = (struct llcrypto_eks_chain *)LLCRYPTO_calloc(1, sizeof(*chain));
	if (chain == NULL) {
		goto cleanup_ordered;
	}
	chain->certs = (struct llcrypto_eks_cert **)LLCRYPTO_calloc((size_t)chain_len, sizeof(struct llcrypto_eks_cert *));
	if (chain->certs == NULL) {
		LLCRYPTO_free(chain);
		goto cleanup_ordered;
	}
	for (int i = 0; i < chain_len; i++) {
		chain->certs[i] = ordered[i];
	}
	chain->count = chain_len;

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
 * LLAPI contract: the Java side allocates `algorithm` with enough capacity for
 * the longest algorithm name returned ("Ed25519" / "UNKNOWN" /
 * secret_key.algorithm), so the strcpy calls below are safe.
 */
void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyAlgorithm(jint key_id, jbyte *algorithm) {
	/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
	struct llcrypto_key *key = (struct llcrypto_key *)(intptr_t)key_id;

	if (key->type == LLCRYPTO_KEY_TYPE_EVP_PKEY) {
		int base_id = EVP_PKEY_base_id(key->evp_key);
		if (base_id == EVP_PKEY_RSA) {
			(void)strcpy((char *)algorithm, "RSA");
		} else if (base_id == EVP_PKEY_EC) {
			(void)strcpy((char *)algorithm, "EC");
		} else if (base_id == EVP_PKEY_ED25519) {
			(void)strcpy((char *)algorithm, "Ed25519");
		} else if (base_id == EVP_PKEY_ED448) {
			(void)strcpy((char *)algorithm, "Ed448");
		} else {
			(void)strcpy((char *)algorithm, "UNKNOWN");
		}
	} else if (key->type == LLCRYPTO_KEY_TYPE_SECRET_KEY) {
		if (key->secret_key.algorithm != NULL) {
			(void)strcpy((char *)algorithm, key->secret_key.algorithm);
		} else {
			(void)strcpy((char *)algorithm, "AES");
		}
	} else {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeException(LLCRYPTO_ERROR, "Unknown key type"));
	}
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateSize(jint handle) {
	/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
	struct llcrypto_eks_cert *c = (struct llcrypto_eks_cert *)(intptr_t)handle;
	return (jint)c->der_length;
}

void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateData(jint handle, jbyte *buffer) {
	/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
	struct llcrypto_eks_cert *c = (struct llcrypto_eks_cert *)(intptr_t)handle;
	(void)memcpy(buffer, c->der_data, (size_t)c->der_length);
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainLength(jint handle) {
	/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
	struct llcrypto_eks_chain *chain = (struct llcrypto_eks_chain *)(intptr_t)handle;
	return (jint)chain->count;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateFromChain(jint handle, jint index) {
	jint result = LLCRYPTO_ERROR;

	/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
	struct llcrypto_eks_chain *chain = (struct llcrypto_eks_chain *)(intptr_t)handle;
	if (index < 0 || index >= chain->count) {
		goto end;
	}

	result = (jint)(intptr_t)chain->certs[index];

end:
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_closeCertificateChainHandle(jint handle) {
	/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
	struct llcrypto_eks_chain *chain = (struct llcrypto_eks_chain *)(intptr_t)handle;
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
	struct llcrypto_eks_key_import *h =
		(struct llcrypto_eks_key_import *)LLCRYPTO_calloc(1, sizeof(*h));
	if (h == NULL) {
		goto end;
	}
	size_t alias_len = strlen(alias);
	if (alias_len >= sizeof(h->alias)) {
		alias_len = sizeof(h->alias) - 1;
	}
	(void)memcpy(h->alias, alias, alias_len);
	h->alias[alias_len] = '\0';
	h->chain_len = chain_len;
	if (chain_len > 0) {
		h->chain_certs = (struct llcrypto_eks_chain_cert *)LLCRYPTO_calloc(
			(size_t)chain_len, sizeof(*h->chain_certs));
		if (h->chain_certs == NULL) {
			LLCRYPTO_free(h);
			goto end;
		}
	}
	result = h;

end:
	return result;
}

void llcrypto_eks_key_import_free(struct llcrypto_eks_key_import *h) {
	if (h == NULL) {
		return;
	}
	EVP_PKEY_free(h->key_evp);
	if (h->chain_certs != NULL) {
		for (int i = 0; i < h->chain_len; i++) {
			LLCRYPTO_free(h->chain_certs[i].der);
		}
		LLCRYPTO_free(h->chain_certs);
	}
	LLCRYPTO_free(h);
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_insertCertificateInChain(jint handle, jint index, jbyte *certificate) {
	jint result = LLCRYPTO_ERROR;

	/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
	struct llcrypto_eks_key_import *h = (struct llcrypto_eks_key_import *)(intptr_t)handle;
	/* Require strictly contiguous inserts (index == chain_count). The
	 * sole Java caller iterates 0..chainLength-1 sequentially, so this
	 * matches the contract; rejecting holes keeps closeKeyEntry from
	 * later dereferencing a NULL chain_certs[i].der. */
	if (h == NULL || index != h->chain_count || index >= h->chain_len) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Invalid chain index"));
		goto end;
	}
	jint cert_len = SNI_getArrayLength((void *)certificate);
	if (cert_len <= 0) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Empty certificate in chain"));
		goto end;
	}
	uint8_t *copy = (uint8_t *)LLCRYPTO_calloc(1, (size_t)cert_len);
	if (copy == NULL) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Out of memory"));
		goto end;
	}
	(void)memcpy(copy, certificate, (size_t)cert_len);
	h->chain_certs[index].der = copy;
	h->chain_certs[index].len = (int)cert_len;
	h->chain_count = index + 1;
	result = LLCRYPTO_SUCCESS;

end:
	return result;
}
