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

#include <sni.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum alias length in bytes (including NUL). */
#define LLCRYPTO_EKS_MAX_ALIAS_LEN 256

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
	int count;
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
 * C string. Caller must LLCRYPTO_free() the returned pointer (and should
 * OPENSSL_cleanse it beforehand for secret data). Returns NULL on
 * allocation failure; returns an empty string if password is NULL.
 */
char *llcrypto_eks_jchar_to_cstring(const jchar *password);

/**
 * Case-insensitive string comparison (portable).
 */
int llcrypto_eks_strcasecmp(const char *a, const char *b);

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
	jint key_native_id; /* 0 if unused; otherwise (intptr_t)llcrypto_key* */
	EVP_PKEY *key_evp;  /* set by openKeyEntryWithData, NULL otherwise */

	int chain_len;   /* expected number of chain certs */
	int chain_count; /* number inserted so far */
	struct llcrypto_eks_chain_cert {
		uint8_t *der;
		int len;
	} *chain_certs;
};

/**
 * Derive an ECDH shared secret on a PKCS#11 token via the direct C API.
 *
 * The pkcs11-provider encodes the ECDH peer point as a DER-wrapped OCTET STRING
 * (PKCS#11 v3.0 optional form), which the OP-TEE PKCS#11 TA mis-parses, so an
 * EVP_PKEY_derive() against a token-resident key yields a wrong shared secret.
 * This bypasses the provider and calls C_DeriveKey
 * with CKM_ECDH1_DERIVE / CKD_NULL and the raw uncompressed peer point
 * (0x04 || X || Y, the v2.40 mandatory form the TA derives correctly from).
 *
 * Defined only by the PKCS#11 backend; never called when @p alias is NULL.
 *
 * @param alias            CKA_LABEL of the EC private key on the token.
 * @param peer_point       Peer EC public point, raw uncompressed (0x04 || X || Y).
 * @param peer_point_len   Length of @p peer_point in bytes.
 * @param secret_out       Output buffer for the raw shared secret.
 * @param secret_out_len   In: capacity of @p secret_out. Out: bytes written.
 * @return LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR on failure (an exception is thrown).
 */
int llcrypto_eks_ecdh_derive(const char *alias, const uint8_t *peer_point, size_t peer_point_len,
                             uint8_t *secret_out, size_t *secret_out_len);

/**
 * Allocate a new import handle for @p alias with capacity for @p chain_len
 * certs. Returns NULL on allocation failure.
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
