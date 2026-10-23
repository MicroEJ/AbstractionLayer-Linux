/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

#ifndef LLCRYPTO_EXTERNAL_KEYSTORE_COMMON_H
#define LLCRYPTO_EXTERNAL_KEYSTORE_COMMON_H

/**
 * @file
 * @brief Shared helpers and types for the External KeyStore backends.
 *
 * The PKCS#11 and PKCS#12 backends differ in how they source aliases, keys
 * and certificates, but everything downstream — SNI-managed DER blobs,
 * certificate chain walks, jchar-to-C string conversion, case-insensitive
 * alias comparison — is identical and lives here. The LLAPI entry points
 * whose implementation is backend-agnostic (operating on llcrypto_key and
 * llcrypto_eks_* handles without touching backend state) are also defined in
 * LLCRYPTO_EXTERNAL_KEYSTORE_common.c so each backend can stay focused on
 * key/cert acquisition.
 */

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <sni.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum alias length in bytes (including NUL). */
#define LLCRYPTO_EKS_MAX_ALIAS_LEN 256U

/** Maximum number of objects (aliases) supported per keystore. */
#define LLCRYPTO_EKS_MAX_OBJECTS 32

/** Length in bytes of the binary key identifier shared between backends:
 *  PKCS#12 localKeyID (random 20 bytes attached to key/leaf-cert pairs) and
 *  PKCS#11 CKA_ID (SHA-1 of the alias, conveniently the same length). 20 is
 *  the conventional choice — PKCS#11 v2.40 doesn't fix CKA_ID width but tools
 *  expect SHA-1; PKCS#12 traditionally uses 20-byte localKeyIDs. */
#define LLCRYPTO_EKS_LOCAL_KEY_ID_LEN 20

/**
 * SNI-managed DER certificate blob. Returned as an opaque handle by
 * LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateHandle and
 * LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateFromChain. Freed by the Java
 * GC via SNI_registerResource.
 */
struct llcrypto_eks_cert {
	uint8_t *der_data;
	int der_length;
};

/**
 * SNI-managed certificate chain. Returned as an opaque handle by
 * LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainHandle. Freed by the Java
 * GC via SNI_registerResource.
 */
struct llcrypto_eks_chain {
	struct llcrypto_eks_cert **certs;
	int cert_count;
};

/**
 * SNI close function for a single cert handle. Safe to call with NULL.
 */
void llcrypto_eks_cert_free(struct llcrypto_eks_cert *c);

/**
 * SNI close function for a certificate chain handle. Safe to call with NULL.
 */
void llcrypto_eks_chain_free(struct llcrypto_eks_chain *ch);

/**
 * Convert a jchar* (UTF-16) SNI password array to a NUL-terminated ASCII
 * C string. The character count comes from sni_array_get_length() and is
 * reported in @p out_len, so no caller has to scan for a terminator.
 *
 * Code units outside 0x01-0x7F are rejected rather than truncated to their low
 * byte: both backends carry the credential as a C string (the PKCS#11 one
 * embeds it in a pkcs11: URI, where a PIN is inherently a string), so a lossy
 * conversion would authenticate and compare on a prefix of the real password.
 * The returned buffer therefore holds no embedded NUL, which is what makes
 * strlen() on the cached credential exact.
 *
 * Caller must LLCRYPTO_free() @p out (and should OPENSSL_cleanse it beforehand
 * for secret data). An empty string is returned if @p password is NULL.
 *
 * @param[in]  password  the SNI password array, or NULL.
 * @param[out] out       the converted C string.
 * @param[out] out_len   the converted length in bytes, excluding the NUL.
 * @return LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR_OOM on allocation
 *         failure, or LLCRYPTO_ERROR if the password is not ASCII.
 */
int llcrypto_eks_jchar_to_ascii_cstring(jchar *password, char **out, size_t *out_len);

/**
 * DER-encode an X509 cert and wrap it in a heap-allocated llcrypto_eks_cert.
 * Ownership of the returned struct is transferred to the caller (not yet
 * registered as an SNI resource). Returns NULL on failure.
 */
struct llcrypto_eks_cert *llcrypto_eks_x509_to_cert(X509 *cert);

/**
 * Build an SNI-managed certificate chain by finding the leaf cert whose
 * label matches `alias` (case-insensitive) in all_certs, then walking the
 * issuer chain by matching issuer name against other certs' subject names.
 * Stops at a self-signed cert or when no parent is found in the array.
 *
 * On success the returned chain is registered as an SNI resource. The
 * caller retains ownership of all_certs / cert_labels in every outcome —
 * this function neither stores nor frees them (it DER-encodes the matched
 * certs into new heap blobs).
 *
 * @param alias        Leaf alias to look up (case-insensitive).
 * @param all_certs    X509* array (caller keeps ownership).
 * @param cert_labels  Parallel alias array, one row per cert.
 * @param total_certs  Number of entries in all_certs / cert_labels.
 * @return SNI-registered chain handle, or NULL if the leaf is missing,
 *         allocation fails, or SNI registration fails.
 */
struct llcrypto_eks_chain *llcrypto_eks_build_chain(const char *alias,
                                                    X509 **all_certs,
                                                    char (*cert_labels)[LLCRYPTO_EKS_MAX_ALIAS_LEN],
                                                    int total_certs);

/**
 * Heap-allocated state carried across the multi-step setKeyEntry import:
 *   openKeyEntryWith{Data,NativeId} → N×insertCertificateInChain → closeKeyEntry
 *
 * Both backends use the same shape; closeKeyEntry is backend-specific
 * because it commits the entry to the token / file. The Java side allocates
 * this implicitly; the backend hands back the pointer cast to jint.
 */
struct llcrypto_eks_key_import {
	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];

	/* Mutually exclusive: openKeyEntryWithData decodes the protected PKCS#8
	 * blob into key_evp; openKeyEntryWithNativeId stores a llcrypto_key handle
	 * in key_native_id. */
	jint key_native_id; /* 0 if unused; otherwise a llcrypto_key* held as an integer */
	EVP_PKEY *key_evp;  /* set by openKeyEntryWithData, NULL otherwise */

	int chain_len;   /* expected number of chain certs */
	int chain_count; /* number inserted so far */
	struct llcrypto_eks_chain_cert {
		uint8_t *der;
		int len;
	} *chain_certs;
};

/**
 * Allocate a new import handle for @p alias with capacity for @p chain_len
 * certs. Returns NULL on allocation failure, or if @p alias does not fit in
 * LLCRYPTO_EKS_MAX_ALIAS_LEN — an over-long alias is rejected rather than
 * truncated.
 *
 * @throws NativeIOException on either failure, so a caller must not throw again on NULL.
 */
struct llcrypto_eks_key_import *llcrypto_eks_key_import_new(const char *alias, int chain_len);

/**
 * Free an import handle and any owned key/cert payload. Safe to call with NULL.
 */
void llcrypto_eks_key_import_free(struct llcrypto_eks_key_import *h);

#ifdef __cplusplus
}
#endif

#endif /* LLCRYPTO_EXTERNAL_KEYSTORE_COMMON_H */
