/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO_EXTERNAL_KEYSTORE implementation backed by a PKCS#12 (.p12) file.
 *
 * Nothing is cached in memory between LLAPI calls. Each function re-opens the
 * PKCS#12 file, extracts exactly the data it needs, and frees all OpenSSL objects
 * before returning. Keys are returned as SNI-managed llcrypto_key handles. Certificates
 * are returned as SNI-managed DER blobs. Both are freed by the Java GC when no
 * longer referenced.
 */

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"
#include "LLCRYPTO_EXTERNAL_KEYSTORE_common.h"
#include <LLCRYPTO_EXTERNAL_KEYSTORE_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

// #define LLCRYPTO_EKS_DEBUG_TRACE

#ifdef LLCRYPTO_EKS_DEBUG_TRACE
#define LLCRYPTO_EKS_DEBUG_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_EKS_DEBUG_PRINTF(...) ((void)0)
#endif

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/** Filesystem path for the PKCS#12 keystore file. Project-specific; set at
 *  build time from project_options.cmake via -DLLCRYPTO_KEYSTORE_PATH="...". */
#ifndef LLCRYPTO_KEYSTORE_PATH
#define LLCRYPTO_KEYSTORE_PATH "/tmp/test-keystore.p12"
#endif

// -----------------------------------------------------------------------------
// Internal data structures
// -----------------------------------------------------------------------------

/**
 * Global keystore state — holds only the file path and cached password.
 * No entry table, no keys, no certificates.
 */
static struct {
	int loaded;
	char path[PATH_MAX];
	char *password;      /**< Heap-allocated copy of the login password (needed by cert APIs). */
	int pw_len;
} g_keystore;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/**
 * Extract the friendlyName attribute from a PKCS12 safe bag as a C string.
 * Writes into buf (max buf_len bytes including NUL). Returns LLCRYPTO_SUCCESS on
 * success, LLCRYPTO_ERROR if absent.
 */
static int extract_bag_alias(const PKCS12_SAFEBAG *bag, char *buf, size_t buf_len) {
	int result = LLCRYPTO_ERROR;

	const STACK_OF(X509_ATTRIBUTE) * attrs = PKCS12_SAFEBAG_get0_attrs(bag);
	if (attrs == NULL) {
		goto end;
	}

	int idx = X509at_get_attr_by_NID(attrs, NID_friendlyName, -1);
	if (idx < 0) {
		goto end;
	}

	const X509_ATTRIBUTE *attr = X509at_get_attr(attrs, idx);
	if (attr == NULL) {
		goto end;
	}

	const ASN1_TYPE *val = X509_ATTRIBUTE_get0_type((X509_ATTRIBUTE *)attr, 0);
	if (val == NULL) {
		goto end;
	}

	/* friendlyName is a BMPString (UTF-16BE). Convert to ASCII. */
	const ASN1_STRING *str = val->value.asn1_string;
	if (str == NULL) {
		goto end;
	}

	const unsigned char *data = ASN1_STRING_get0_data(str);
	int len = ASN1_STRING_length(str);

	/* BMPString: 2 bytes per character, big-endian. Take the low byte. */
	int chars = len / 2;
	if (chars >= (int)buf_len) {
		chars = (int)buf_len - 1;
	}
	for (int i = 0; i < chars; i++) {
		buf[i] = (char)data[i * 2 + 1]; /* low byte of BE pair */
	}
	buf[chars] = '\0';
	result = LLCRYPTO_SUCCESS;

end:
	return result;
}

/**
 * Extract the alias from a cert bag, falling back to the certificate's friendlyName.
 */
static void extract_cert_alias(const PKCS12_SAFEBAG *bag, X509 *cert, char *buf, size_t buf_len) {
	buf[0] = '\0';
	(void)extract_bag_alias(bag, buf, buf_len);
	if (buf[0] == '\0' && cert != NULL) {
		int alias_len = 0;
		const unsigned char *alias_data = X509_alias_get0(cert, &alias_len);
		if (alias_data != NULL && alias_len > 0) {
			int copy_len = (alias_len < (int)buf_len - 1) ? alias_len : (int)buf_len - 1;
			(void)memcpy(buf, alias_data, (size_t)copy_len);
			buf[copy_len] = '\0';
		}
	}
}

/**
 * Determine if an OID belongs to the AES family.
 * Returns 1 if AES, 0 otherwise.
 */
static int is_aes_oid(const ASN1_OBJECT *obj) {
	int result = 0;
	int nid = OBJ_obj2nid(obj);

	switch (nid) {
	case NID_aes_128_cbc:
	case NID_aes_128_ecb:
	case NID_aes_128_cfb128:
	case NID_aes_128_ofb128:
	case NID_aes_128_gcm:
	case NID_aes_128_ccm:
	case NID_aes_192_cbc:
	case NID_aes_192_ecb:
	case NID_aes_192_cfb128:
	case NID_aes_192_ofb128:
	case NID_aes_192_gcm:
	case NID_aes_192_ccm:
	case NID_aes_256_cbc:
	case NID_aes_256_ecb:
	case NID_aes_256_cfb128:
	case NID_aes_256_ofb128:
	case NID_aes_256_gcm:
	case NID_aes_256_ccm:
		result = 1;
		break;
	default:
		break;
	}

	if (result == 0) {
		/* Java keytool uses the base AES OID (2.16.840.1.101.3.4.1) which has no NID. */
		char oid_buf[64];
		if (OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1) > 0) {
			if (strncmp(oid_buf, "2.16.840.1.101.3.4.1", 21) == 0) {
				result = 1;
			}
		}
	}

	return result;
}

// -----------------------------------------------------------------------------
// PKCS#12 iteration helper
// -----------------------------------------------------------------------------

/**
 * Callback invoked for every safe bag during PKCS#12 iteration.
 * @param bag      The safe bag.
 * @param password The PKCS#12 password (C string).
 * @param pw_len   Password length.
 * @param ctx      Opaque caller context.
 * @return 0 to continue iteration, 1 to stop.
 */
typedef int (*llcrypto_eks_bag_callback)(PKCS12_SAFEBAG *bag, const char *password,
                                         int pw_len, void *ctx);

/**
 * Open the PKCS#12 file, verify MAC, and invoke cb for every safe bag.
 * Returns LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR on error (file/parse/mac failure).
 */
static int iterate_p12_bags(const char *path, const char *password, int pw_len,
                            llcrypto_eks_bag_callback cb, void *ctx) {
	int result = LLCRYPTO_ERROR;
	PKCS12 *p12 = NULL;
	STACK_OF(PKCS7) * authsafes = NULL;

	BIO *bio = BIO_new_file(path, "rb");
	if (bio == NULL) {
		goto end;
	}

	p12 = d2i_PKCS12_bio(bio, NULL);
	BIO_free(bio);
	if (p12 == NULL) {
		goto end;
	}

	if (!PKCS12_verify_mac(p12, password, pw_len)) {
		goto end;
	}

	authsafes = PKCS12_unpack_authsafes(p12);
	if (authsafes == NULL) {
		goto end;
	}

	int stop = 0;
	for (int i = 0; i < sk_PKCS7_num(authsafes) && !stop; i++) {
		PKCS7 *p7 = sk_PKCS7_value(authsafes, i);
		int bagnid = OBJ_obj2nid(p7->type);

		STACK_OF(PKCS12_SAFEBAG) * bags = NULL;
		if (bagnid == NID_pkcs7_data) {
			bags = PKCS12_unpack_p7data(p7);
		} else if (bagnid == NID_pkcs7_encrypted) {
			bags = PKCS12_unpack_p7encdata(p7, password, pw_len);
		} else {
			continue;
		}
		if (bags == NULL) {
			continue;
		}

		for (int j = 0; j < sk_PKCS12_SAFEBAG_num(bags) && !stop; j++) {
			stop = cb(sk_PKCS12_SAFEBAG_value(bags, j), password, pw_len, ctx);
		}

		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	}

	result = LLCRYPTO_SUCCESS;

end:
	if (authsafes != NULL) {
		sk_PKCS7_pop_free(authsafes, PKCS7_free);
	}
	if (p12 != NULL) {
		PKCS12_free(p12);
	}
	return result;
}

// -----------------------------------------------------------------------------
// Bag-level key extraction helpers
// -----------------------------------------------------------------------------

/**
 * Try to extract a secret key from a PKCS8_PRIV_KEY_INFO that wraps a symmetric key.
 * Returns a new llcrypto_key on success, NULL otherwise.
 */
static struct llcrypto_key *extract_secret_key_from_p8(const PKCS8_PRIV_KEY_INFO *p8) {
	struct llcrypto_key *result = NULL;
	const ASN1_OBJECT *alg_obj = NULL;
	const unsigned char *pk = NULL;
	int pk_len = 0;

	if (PKCS8_pkey_get0(&alg_obj, &pk, &pk_len, NULL, p8) == 0) {
		goto end;
	}
	if (alg_obj == NULL || pk == NULL || pk_len <= 0) {
		goto end;
	}
	if (!is_aes_oid(alg_obj)) {
		goto end;
	}

	const unsigned char *key_data = pk;
	int key_len = pk_len;

	ASN1_OCTET_STRING *octet = NULL;
	const unsigned char *tmp = pk;
	octet = d2i_ASN1_OCTET_STRING(NULL, &tmp, pk_len);
	if (octet != NULL) {
		key_data = ASN1_STRING_get0_data(octet);
		key_len = ASN1_STRING_length(octet);
	}

	result = llcrypto_key_from_secret_key(
		(uint8_t *)key_data, (size_t)key_len, (uint8_t *)"AES");

	if (octet != NULL) {
		ASN1_OCTET_STRING_free(octet);
	}

end:
	return result;
}

/**
 * Extract a key (asymmetric or secret) from a key bag (shrouded or plain).
 * Returns a new llcrypto_key on success, NULL if the bag is not a key bag or extraction fails.
 */
static struct llcrypto_key *extract_key_from_keybag(PKCS12_SAFEBAG *bag, const char *password, int pw_len) {
	struct llcrypto_key *result = NULL;
	PKCS8_PRIV_KEY_INFO *p8_decrypted = NULL;
	const PKCS8_PRIV_KEY_INFO *p8 = NULL;

	int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
	if (bag_nid != NID_pkcs8ShroudedKeyBag && bag_nid != NID_keyBag) {
		goto end;
	}

	if (bag_nid == NID_pkcs8ShroudedKeyBag) {
		p8_decrypted = PKCS12_decrypt_skey(bag, password, pw_len);
		p8 = p8_decrypted;
	} else {
		p8 = PKCS12_SAFEBAG_get0_p8inf(bag);
	}

	if (p8 == NULL) {
		goto end;
	}

	/* Try as secret key first. */
	struct llcrypto_key *key = extract_secret_key_from_p8(p8);
	if (key == NULL) {
		/* Try as asymmetric key. */
		EVP_PKEY *pkey = EVP_PKCS82PKEY(p8);
		if (pkey != NULL) {
			int base_id = EVP_PKEY_base_id(pkey);
			if (base_id == EVP_PKEY_RSA || base_id == EVP_PKEY_EC ||
			    base_id == EVP_PKEY_ED25519 || base_id == EVP_PKEY_ED448) {
				key = llcrypto_key_from_evp_pkey(pkey);
				if (key == NULL) {
					EVP_PKEY_free(pkey);
				}
				/* else: ownership transferred to key */
			} else {
				EVP_PKEY_free(pkey);
			}
		} else {
			ERR_clear_error();
		}
	}

	result = key;

end:
	PKCS8_PRIV_KEY_INFO_free(p8_decrypted);
	return result;
}

/**
 * Extract a key from a secretBag (Java keytool AES format).
 * Returns a new llcrypto_key on success, NULL otherwise.
 */
static struct llcrypto_key *extract_key_from_secretbag(PKCS12_SAFEBAG *bag, const char *password, int pw_len) {
	struct llcrypto_key *result = NULL;

	if (PKCS12_SAFEBAG_get_nid(bag) != NID_secretBag) {
		goto end;
	}

	const ASN1_TYPE *bag_value = PKCS12_SAFEBAG_get0_bag_obj(bag);
	if (bag_value == NULL) {
		goto end;
	}
	if (bag_value->type != V_ASN1_OCTET_STRING && bag_value->type != V_ASN1_SEQUENCE) {
		goto end;
	}

	const ASN1_STRING *os = (bag_value->type == V_ASN1_OCTET_STRING)
	    ? bag_value->value.octet_string
	    : bag_value->value.asn1_string;
	if (os == NULL) {
		goto end;
	}

	const unsigned char *enc_data = ASN1_STRING_get0_data(os);
	int enc_len = ASN1_STRING_length(os);
	const unsigned char *tmp = enc_data;

	X509_SIG *epki = d2i_X509_SIG(NULL, &tmp, enc_len);
	if (epki == NULL) {
		ERR_clear_error();
		goto end;
	}

	PKCS8_PRIV_KEY_INFO *p8 = PKCS8_decrypt(epki, password, pw_len);
	X509_SIG_free(epki);

	if (p8 != NULL) {
		result = extract_secret_key_from_p8(p8);
		PKCS8_PRIV_KEY_INFO_free(p8);
	} else {
		ERR_clear_error();
	}

end:
	return result;
}

// -----------------------------------------------------------------------------
// Callback contexts and implementations for iterate_p12_bags
// -----------------------------------------------------------------------------

/**
 * Determine if a cert bag is a top-level keystore entry (key-associated or trusted cert)
 * as opposed to a chain cert.
 *
 * Key-associated certs have a localKeyID attribute.
 * Java trusted certs have a trustedKeyUsage attribute (OID 2.16.840.1.113894.746875.1.1).
 * Chain certs have neither and should not appear as separate keystore entries.
 */
static int llcrypto_eks_is_toplevel_cert_bag(const PKCS12_SAFEBAG *bag) {
	int result = 0;
	const STACK_OF(X509_ATTRIBUTE) * attrs = PKCS12_SAFEBAG_get0_attrs(bag);
	if (attrs == NULL) {
		goto end;
	}

	/* Key-associated cert: has localKeyID. */
	if (X509at_get_attr_by_NID(attrs, NID_localKeyID, -1) >= 0) {
		result = 1;
		goto end;
	}

	/* Java trusted cert: has trustedKeyUsage (OID 2.16.840.1.113894.746875.1.1).
	 * This OID has no NID in OpenSSL, so we look it up by OID string. */
	ASN1_OBJECT *trusted_oid = OBJ_txt2obj("2.16.840.1.113894.746875.1.1", 1);
	if (trusted_oid != NULL) {
		int nid = OBJ_obj2nid(trusted_oid);
		if (nid == NID_undef) {
			/* No registered NID — search attributes manually. */
			for (int i = 0; i < X509at_get_attr_count(attrs); i++) {
				const X509_ATTRIBUTE *attr = X509at_get_attr(attrs, i);
				if (OBJ_cmp(X509_ATTRIBUTE_get0_object((X509_ATTRIBUTE *)attr), trusted_oid) == 0) {
					result = 1;
					break;
				}
			}
		} else if (X509at_get_attr_by_NID(attrs, nid, -1) >= 0) {
			result = 1;
		}
		ASN1_OBJECT_free(trusted_oid);
	}

end:
	return result;
}

/** Context for counting unique aliases (size). */
struct count_ctx {
	char aliases[LLCRYPTO_EKS_MAX_OBJECTS][LLCRYPTO_EKS_MAX_ALIAS_LEN]; /* deduplicated alias list */
	int count;
};

static int count_bag_cb(PKCS12_SAFEBAG *bag, const char *password, int pw_len, void *ctx) {
	LLCRYPTO_UNUSED_PARAM(password);
	LLCRYPTO_UNUSED_PARAM(pw_len);
	int result = 0;
	struct count_ctx *c = (struct count_ctx *)ctx;

	int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
	if (bag_nid != NID_pkcs8ShroudedKeyBag && bag_nid != NID_keyBag &&
	    bag_nid != NID_certBag && bag_nid != NID_secretBag) {
		goto end;
	}

	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	alias[0] = '\0';
	if (bag_nid == NID_certBag) {
		/* Only count cert bags that are top-level keystore entries.
		 * In PKCS#12, key-associated certs have a localKeyID attribute, and
		 * Java trusted certs have a trustedKeyUsage attribute (OID 2.16.840.1.113894.746875.1.1).
		 * Chain certs (CA certs stored as part of a key entry's chain) have neither
		 * and should not be counted as separate entries. */
		if (!llcrypto_eks_is_toplevel_cert_bag(bag)) {
			goto end; /* Chain cert — skip. */
		}
		(void)extract_bag_alias(bag, alias, sizeof(alias));
	} else {
		(void)extract_bag_alias(bag, alias, sizeof(alias));
	}

	LLCRYPTO_EKS_DEBUG_PRINTF("%s: bag_nid=%d alias='%s'\n", __func__, bag_nid, alias);

	/* Deduplicate. */
	for (int i = 0; i < c->count; i++) {
		if (llcrypto_eks_strcasecmp(c->aliases[i], alias) == 0) {
			goto end; /* already counted */
		}
	}
	if (c->count < LLCRYPTO_EKS_MAX_OBJECTS) {
		size_t len = strlen(alias);
		if (len >= LLCRYPTO_EKS_MAX_ALIAS_LEN) {
			len = LLCRYPTO_EKS_MAX_ALIAS_LEN - 1;
		}
		(void)memcpy(c->aliases[c->count], alias, len);
		c->aliases[c->count][len] = '\0';
		c->count++;
	}

end:
	return result;
}

/** Context for getAlias. */
struct alias_ctx {
	int target_index;
	int current_index;
	char aliases[LLCRYPTO_EKS_MAX_OBJECTS][LLCRYPTO_EKS_MAX_ALIAS_LEN];
	int alias_count;
	char *result; /**< Points to the alias at target_index, or NULL. */
};

static int alias_bag_cb(PKCS12_SAFEBAG *bag, const char *password, int pw_len, void *ctx) {
	LLCRYPTO_UNUSED_PARAM(password);
	LLCRYPTO_UNUSED_PARAM(pw_len);
	int result = 0;
	struct alias_ctx *c = (struct alias_ctx *)ctx;

	int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
	if (bag_nid != NID_pkcs8ShroudedKeyBag && bag_nid != NID_keyBag &&
	    bag_nid != NID_certBag && bag_nid != NID_secretBag) {
		goto end;
	}

	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	alias[0] = '\0';
	if (bag_nid == NID_certBag) {
		/* Skip chain certs — only count top-level cert entries. */
		if (!llcrypto_eks_is_toplevel_cert_bag(bag)) {
			goto end;
		}
		(void)extract_bag_alias(bag, alias, sizeof(alias));
	} else {
		(void)extract_bag_alias(bag, alias, sizeof(alias));
	}

	/* Deduplicate. */
	for (int i = 0; i < c->alias_count; i++) {
		if (llcrypto_eks_strcasecmp(c->aliases[i], alias) == 0) {
			goto end;
		}
	}
	if (c->alias_count < LLCRYPTO_EKS_MAX_OBJECTS) {
		size_t len = strlen(alias);
		if (len >= LLCRYPTO_EKS_MAX_ALIAS_LEN) {
			len = LLCRYPTO_EKS_MAX_ALIAS_LEN - 1;
		}
		(void)memcpy(c->aliases[c->alias_count], alias, len);
		c->aliases[c->alias_count][len] = '\0';

		if (c->alias_count == c->target_index) {
			c->result = c->aliases[c->alias_count];
		}
		c->alias_count++;

		if (c->result != NULL) {
			result = 1; /* found — stop iteration */
		}
	}

end:
	return result;
}

/** Context for getKeyId — find key by alias. */
struct key_ctx {
	const char *target_alias;
	struct llcrypto_key *result;
};

static int key_bag_cb(PKCS12_SAFEBAG *bag, const char *password, int pw_len, void *ctx) {
	int result = 0;
	struct key_ctx *c = (struct key_ctx *)ctx;

	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	alias[0] = '\0';
	(void)extract_bag_alias(bag, alias, sizeof(alias));

	if (llcrypto_eks_strcasecmp(alias, c->target_alias) != 0) {
		goto end;
	}

	int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
	struct llcrypto_key *key = NULL;

	if (bag_nid == NID_pkcs8ShroudedKeyBag || bag_nid == NID_keyBag) {
		key = extract_key_from_keybag(bag, password, pw_len);
	} else if (bag_nid == NID_secretBag) {
		key = extract_key_from_secretbag(bag, password, pw_len);
	}

	if (key != NULL) {
		c->result = key;
		result = 1; /* found — stop */
	}

end:
	return result;
}

/** Context for getCertificateHandle — find leaf cert by alias. */
struct cert_ctx {
	const char *target_alias;
	struct llcrypto_eks_cert *result;
};

static int cert_bag_cb(PKCS12_SAFEBAG *bag, const char *password, int pw_len, void *ctx) {
	LLCRYPTO_UNUSED_PARAM(password);
	LLCRYPTO_UNUSED_PARAM(pw_len);
	int result = 0;
	struct cert_ctx *c = (struct cert_ctx *)ctx;

	if (PKCS12_SAFEBAG_get_nid(bag) != NID_certBag) {
		goto end;
	}

	X509 *cert = PKCS12_SAFEBAG_get1_cert(bag);
	if (cert == NULL) {
		goto end;
	}

	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	extract_cert_alias(bag, cert, alias, sizeof(alias));

	if (llcrypto_eks_strcasecmp(alias, c->target_alias) != 0) {
		X509_free(cert);
		goto end;
	}

	/* First cert matching the alias is the leaf. */
	if (c->result != NULL) {
		X509_free(cert);
		goto end; /* already have the leaf — skip additional certs for this alias */
	}

	/* DER-encode and wrap in an SNI-managed handle. */
	int der_len = i2d_X509(cert, NULL);
	if (der_len <= 0) {
		X509_free(cert);
		goto end;
	}

	struct llcrypto_eks_cert *h = (struct llcrypto_eks_cert *)LLCRYPTO_calloc(1, sizeof(*h));
	if (h == NULL) {
		X509_free(cert);
		goto end;
	}
	h->der_data = (uint8_t *)LLCRYPTO_calloc(1, (size_t)der_len);
	if (h->der_data == NULL) {
		LLCRYPTO_free(h);
		X509_free(cert);
		goto end;
	}
	unsigned char *p = h->der_data;
	h->der_length = i2d_X509(cert, &p);
	X509_free(cert);

	if (h->der_length <= 0) {
		LLCRYPTO_free(h->der_data);
		LLCRYPTO_free(h);
		goto end;
	}

	if (SNI_OK != SNI_registerResource(h, (SNI_closeFunction)llcrypto_eks_cert_free, NULL)) {
		LLCRYPTO_free(h->der_data);
		LLCRYPTO_free(h);
		goto end;
	}

	c->result = h;
	result = 1; /* found — stop */

end:
	return result;
}

/** Context for getCertificateChainHandle — collect all certs from the PKCS#12. */
struct chain_ctx {
	const char *target_alias;
	X509 *all_certs[LLCRYPTO_EKS_MAX_OBJECTS]; /**< All X509 certs found in the PKCS#12. */
	char aliases[LLCRYPTO_EKS_MAX_OBJECTS][LLCRYPTO_EKS_MAX_ALIAS_LEN]; /**< Alias for each cert. */
	int total;                        /**< Total number of certs collected. */
};

/**
 * Callback that collects all certificate bags from the PKCS#12.
 */
static int chain_collect_cb(PKCS12_SAFEBAG *bag, const char *password, int pw_len, void *ctx) {
	LLCRYPTO_UNUSED_PARAM(password);
	LLCRYPTO_UNUSED_PARAM(pw_len);
	int result = 0;
	struct chain_ctx *c = (struct chain_ctx *)ctx;

	if (PKCS12_SAFEBAG_get_nid(bag) != NID_certBag) {
		goto end;
	}

	X509 *cert = PKCS12_SAFEBAG_get1_cert(bag);
	if (cert == NULL || c->total >= LLCRYPTO_EKS_MAX_OBJECTS) {
		X509_free(cert);
		goto end;
	}

	extract_cert_alias(bag, cert, c->aliases[c->total], LLCRYPTO_EKS_MAX_ALIAS_LEN);
	c->all_certs[c->total] = cert; /* ownership transferred to ctx */
	c->total++;

end:
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Common
// -----------------------------------------------------------------------------

void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_login(jchar *password) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s\n", __func__);

	if (g_keystore.loaded) {
		goto end; /* Already validated — idempotent. */
	}

	char *pw = llcrypto_eks_jchar_to_cstring(password);
	if (pw == NULL) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Out of memory"));
		goto end;
	}
	int pw_len = (int)strlen(pw);

	/* Compiled-in keystore path, so the application runs with no env. */
	const char *path = LLCRYPTO_KEYSTORE_PATH;

	LLCRYPTO_EKS_DEBUG_PRINTF("%s: validating %s\n", __func__, path);

	/* Validate: open, parse, verify MAC, then close immediately. */
	BIO *bio = BIO_new_file(path, "rb");
	if (bio == NULL) {
		OPENSSL_cleanse(pw, (size_t)pw_len);
		LLCRYPTO_free(pw);
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot open keystore file"));
		goto end;
	}

	PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
	BIO_free(bio);
	if (p12 == NULL) {
		OPENSSL_cleanse(pw, (size_t)pw_len);
		LLCRYPTO_free(pw);
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot parse PKCS12 file"));
		goto end;
	}

	if (!PKCS12_verify_mac(p12, pw, pw_len)) {
		PKCS12_free(p12);
		OPENSSL_cleanse(pw, (size_t)pw_len);
		LLCRYPTO_free(pw);
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore password verification failed"));
		goto end;
	}

	PKCS12_free(p12);

	/* Cache path and password for subsequent LLAPI calls. */
	size_t path_len = strlen(path);
	if (path_len >= sizeof(g_keystore.path)) {
		path_len = sizeof(g_keystore.path) - 1;
	}
	(void)memcpy(g_keystore.path, path, path_len);
	g_keystore.path[path_len] = '\0';

	g_keystore.password = pw; /* ownership transferred — freed at process exit */
	g_keystore.pw_len = pw_len;
	g_keystore.loaded = 1;

	LLCRYPTO_EKS_DEBUG_PRINTF("%s: keystore validated, path=%s\n", __func__, g_keystore.path);

end:
	; /* single exit point for void function */
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_size(void) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s\n", __func__);
	jint result = SNI_IGNORED_RETURNED_VALUE;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	struct count_ctx ctx;
	(void)memset(&ctx, 0, sizeof(ctx));

	if (iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     count_bag_cb, &ctx) != LLCRYPTO_SUCCESS) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot read keystore"));
		goto end;
	}

	LLCRYPTO_EKS_DEBUG_PRINTF("%s: %d entries\n", __func__, ctx.count);
	result = (jint)ctx.count;

end:
	LLCRYPTO_EKS_DEBUG_PRINTF("%s return %d\n", __func__, result);
	return result;
}

/*
 * LLAPI contract: the Java side allocates `alias` with a capacity of at least
 * LLCRYPTO_EKS_MAX_ALIAS_LEN bytes, so strcpy is safe for any alias produced by
 * the iterate_p12_bags callback (which truncates to LLCRYPTO_EKS_MAX_ALIAS_LEN - 1).
 */
jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getAlias(jint index, jbyte *alias) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s index=%d\n", __func__, (int)index);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	struct alias_ctx ctx;
	(void)memset(&ctx, 0, sizeof(ctx));
	ctx.target_index = (int)index;

	if (iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     alias_bag_cb, &ctx) != LLCRYPTO_SUCCESS) {
		goto end;
	}

	if (ctx.result == NULL) {
		goto end;
	}

	(void)strcpy((char *)alias, ctx.result);
	result = LLCRYPTO_SUCCESS;
	LLCRYPTO_EKS_DEBUG_PRINTF("%s alias='%s'\n", __func__, (const char *)alias);

end:
	LLCRYPTO_EKS_DEBUG_PRINTF("%s return %d\n", __func__, result);
	return result;
}

jboolean LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_containsAlias(jbyte *alias) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s alias='%s'\n", __func__, (const char *)alias);
	jboolean result = (jboolean)JFALSE;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	/* Re-use the count callback to build the alias list, then search. */
	struct count_ctx ctx;
	(void)memset(&ctx, 0, sizeof(ctx));

	if (iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     count_bag_cb, &ctx) != LLCRYPTO_SUCCESS) {
		goto end;
	}

	for (int i = 0; i < ctx.count; i++) {
		if (llcrypto_eks_strcasecmp(ctx.aliases[i], (const char *)alias) == 0) {
			result = (jboolean)JTRUE;
			goto end;
		}
	}

end:
	LLCRYPTO_EKS_DEBUG_PRINTF("%s return %d\n", __func__, result);
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Key
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyId(jbyte *alias, jchar *password) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s alias='%s'\n", __func__, (const char *)alias);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	LLCRYPTO_UNUSED_PARAM(password);

	struct key_ctx ctx;
	ctx.target_alias = (const char *)alias;
	ctx.result = NULL;

	int rc = iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len, key_bag_cb, &ctx);

	if (rc != LLCRYPTO_SUCCESS || ctx.result == NULL) {
		goto end;
	}

	LLCRYPTO_EKS_DEBUG_PRINTF("%s: returning key_id=%p\n", __func__, (void *)ctx.result);
	result = (jint)(intptr_t)ctx.result;

end:
	LLCRYPTO_EKS_DEBUG_PRINTF("%s return %d\n", __func__, result);
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyType(jint key_id) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s key_id=%p\n", __func__, (void *)(intptr_t)key_id);
	jint result = SNI_IGNORED_RETURNED_VALUE;

	struct llcrypto_key *key = (struct llcrypto_key *)(intptr_t)key_id;

	switch (key->type) {
	case LLCRYPTO_KEY_TYPE_EVP_PKEY:
	{
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->evp_key, NULL);
		if ((pctx != NULL) && (EVP_PKEY_private_check(pctx) == 1)) {
			result = (jint)LLCRYPTO_KEY_TYPE_PRIVATE;
		} else if ((pctx != NULL) && (EVP_PKEY_public_check(pctx) == 1)) {
			result = (jint)LLCRYPTO_KEY_TYPE_PUBLIC;
		} else {
			LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeException(LLCRYPTO_ERROR, "Unable to determine key type"));
		}
		EVP_PKEY_CTX_free(pctx);
		break;
	}
	case LLCRYPTO_KEY_TYPE_SECRET_KEY:
		result = (jint)LLCRYPTO_KEY_TYPE_SECRET;
		break;
	default:
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeException(LLCRYPTO_ERROR, "Unknown key type"));
		break;
	}

	LLCRYPTO_EKS_DEBUG_PRINTF("%s return %d\n", __func__, result);
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Certificate
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateHandle(jbyte *alias) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s alias='%s'\n", __func__, (const char *)alias);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	struct cert_ctx ctx;
	ctx.target_alias = (const char *)alias;
	ctx.result = NULL;

	if (iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     cert_bag_cb, &ctx) != LLCRYPTO_SUCCESS || ctx.result == NULL) {
		goto end;
	}

	LLCRYPTO_EKS_DEBUG_PRINTF("%s: handle=%p size=%d\n", __func__,
	                          (void *)ctx.result, ctx.result->der_length);
	result = (jint)(intptr_t)ctx.result;

end:
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Certificate Chain
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainHandle(jbyte *alias) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s alias='%s'\n", __func__, (const char *)alias);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	struct chain_ctx ctx;
	(void)memset(&ctx, 0, sizeof(ctx));
	ctx.target_alias = (const char *)alias;

	/* Collect all certs from the PKCS#12. */
	if (iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     chain_collect_cb, &ctx) != LLCRYPTO_SUCCESS || ctx.total == 0) {
		goto end;
	}

	struct llcrypto_eks_chain *chain = llcrypto_eks_build_chain(
		(const char *)alias, ctx.all_certs, ctx.aliases, ctx.total);

	for (int i = 0; i < ctx.total; i++) {
		X509_free(ctx.all_certs[i]);
	}

	if (chain != NULL) {
		LLCRYPTO_EKS_DEBUG_PRINTF("%s: chain handle=%p count=%d\n", __func__, (void *)chain, chain->count);
		result = (jint)(intptr_t)chain;
	}

end:
	return result;
}

// -----------------------------------------------------------------------------
// Write path — read-modify-write the PKCS#12 file
//
// All mutators load every existing entry into an in-memory list, apply the
// requested change, and re-encode the file atomically (temp file + rename).
// The PKCS#11 backend can mutate the token live; PKCS#12 is just a file, so
// we have to rewrite it on every change.
//
// Entries are kept at the keystore level (alias + type + payload) rather than
// at the safebag level so we don't have to preserve every quirky attribute of
// the input file: we extract what KeyStore semantics expose, then rebuild from
// scratch with a consistent shape (one cert bag per cert; private keys go in
// pkcs8ShroudedKeyBag; AES secrets go in pkcs8ShroudedKeyBag with the AES OID
// — the read path already handles both that and Java keytool's secretBag).
// -----------------------------------------------------------------------------

/** Trusted-cert marker the read path also recognizes (besides localKeyID):
 *  Java keytool's oracleTrustedKeyUsage attribute, used in the input file. */
#define LLCRYPTO_EKS_TRUSTED_KEY_USAGE_OID "2.16.840.1.113894.746875.1.1"

/** Default PBE iterations (matches OpenSSL's PKCS12_DEFAULT_ITER). */
#define LLCRYPTO_EKS_PBE_ITER 2048
/* LLCRYPTO_EKS_LOCAL_KEY_ID_LEN is shared with the PKCS#11 backend in
 * LLCRYPTO_EXTERNAL_KEYSTORE_common.h. */

enum p12_entry_type {
	P12_ENTRY_PRIVATE_KEY,    /**< asymmetric key + optional cert chain (leaf at index 0). */
	P12_ENTRY_SECRET_KEY,     /**< raw symmetric key bytes. */
	P12_ENTRY_TRUSTED_CERT,   /**< standalone certificate, no key. */
};

/**
 * One keystore entry as exposed by the LLAPI. We rebuild every safebag from
 * these on save, so we keep just enough to round-trip what KeyStore exposes.
 */
struct p12_entry {
	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	enum p12_entry_type type;
	/* PRIVATE_KEY */
	EVP_PKEY *pkey;
	STACK_OF(X509) * chain;       /**< leaf at index 0; may be NULL. */
	/* SECRET_KEY */
	uint8_t *secret_bytes;
	int secret_len;
	char secret_algorithm[32];
	/* TRUSTED_CERT */
	X509 *trusted_cert;
};

/* setKeyEntry import handle and insertCertificateInChain are shared with the
 * PKCS#11 backend — see LLCRYPTO_EXTERNAL_KEYSTORE_common.{h,c}. */

static void p12_entry_clear(struct p12_entry *e) {
	if (e == NULL) {
		return;
	}
	EVP_PKEY_free(e->pkey);
	e->pkey = NULL;
	if (e->chain != NULL) {
		sk_X509_pop_free(e->chain, X509_free);
		e->chain = NULL;
	}
	if (e->secret_bytes != NULL) {
		OPENSSL_cleanse(e->secret_bytes, (size_t)e->secret_len);
		LLCRYPTO_free(e->secret_bytes);
		e->secret_bytes = NULL;
	}
	X509_free(e->trusted_cert);
	e->trusted_cert = NULL;
}

static void p12_entries_free(struct p12_entry *entries, int n) {
	if (entries == NULL) {
		return;
	}
	for (int i = 0; i < n; i++) {
		p12_entry_clear(&entries[i]);
	}
	LLCRYPTO_free(entries);
}

static int p12_entry_set_alias(struct p12_entry *e, const char *alias) {
	size_t len = strlen(alias);
	if (len >= sizeof(e->alias)) {
		len = sizeof(e->alias) - 1;
	}
	(void)memcpy(e->alias, alias, len);
	e->alias[len] = '\0';
	return LLCRYPTO_SUCCESS;
}

/**
 * Find an entry by alias (case-insensitive). Returns -1 if not found.
 */
static int p12_entries_find(const struct p12_entry *entries, int n, const char *alias) {
	int result = -1;
	for (int i = 0; i < n; i++) {
		if (llcrypto_eks_strcasecmp(entries[i].alias, alias) == 0) {
			result = i;
			break;
		}
	}
	return result;
}

/**
 * Remove every entry with the given alias (case-insensitive).
 * Returns the new count.
 */
static int p12_entries_remove(struct p12_entry *entries, int n, const char *alias) {
	int dst = 0;
	for (int src = 0; src < n; src++) {
		if (llcrypto_eks_strcasecmp(entries[src].alias, alias) == 0) {
			p12_entry_clear(&entries[src]);
		} else {
			if (dst != src) {
				entries[dst] = entries[src];
				(void)memset(&entries[src], 0, sizeof(entries[src]));
			}
			dst++;
		}
	}
	return dst;
}

// -----------------------------------------------------------------------------
// Loading entries: walk every safebag, group certs by localKeyID + alias.
// -----------------------------------------------------------------------------

/**
 * Intermediate representation for the load callback. We collect raw safebag
 * data first (since chain certs reference key entries by localKeyID, we can
 * only resolve associations after a full pass), then assemble entries.
 */
struct loaded_keybag {
	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	/* localKeyID raw bytes (or empty if absent). */
	unsigned char localkeyid[64];
	int localkeyid_len;
	EVP_PKEY *pkey;             /**< asymmetric key (NULL for secret). */
	uint8_t *secret_bytes;      /**< raw AES bytes (NULL for asymmetric). */
	int secret_len;
};

struct loaded_certbag {
	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	unsigned char localkeyid[64];
	int localkeyid_len;
	int trusted;                /**< has trustedKeyUsage. */
	X509 *cert;
};

struct load_ctx {
	struct loaded_keybag keys[LLCRYPTO_EKS_MAX_OBJECTS];
	int key_count;
	struct loaded_certbag certs[LLCRYPTO_EKS_MAX_OBJECTS * 4]; /* certs include chain */
	int cert_count;
};

/**
 * Extract the localKeyID attribute as raw bytes. Returns LLCRYPTO_SUCCESS on
 * success, LLCRYPTO_ERROR if absent.
 */
static int extract_local_key_id(const PKCS12_SAFEBAG *bag, unsigned char *buf, size_t buf_len, int *out_len) {
	int result = LLCRYPTO_ERROR;
	*out_len = 0;
	const STACK_OF(X509_ATTRIBUTE) * attrs = PKCS12_SAFEBAG_get0_attrs(bag);
	if (attrs == NULL) {
		goto end;
	}
	int idx = X509at_get_attr_by_NID(attrs, NID_localKeyID, -1);
	if (idx < 0) {
		goto end;
	}
	const X509_ATTRIBUTE *attr = X509at_get_attr(attrs, idx);
	const ASN1_TYPE *val = X509_ATTRIBUTE_get0_type((X509_ATTRIBUTE *)attr, 0);
	if (val == NULL || val->type != V_ASN1_OCTET_STRING) {
		goto end;
	}
	const ASN1_OCTET_STRING *os = val->value.octet_string;
	int len = ASN1_STRING_length(os);
	if (len <= 0 || (size_t)len > buf_len) {
		goto end;
	}
	(void)memcpy(buf, ASN1_STRING_get0_data(os), (size_t)len);
	*out_len = len;
	result = LLCRYPTO_SUCCESS;

end:
	return result;
}

static int has_trusted_key_usage_attr(const PKCS12_SAFEBAG *bag) {
	int found = 0;
	const STACK_OF(X509_ATTRIBUTE) * attrs = PKCS12_SAFEBAG_get0_attrs(bag);
	if (attrs == NULL) {
		goto end;
	}
	ASN1_OBJECT *trusted = OBJ_txt2obj(LLCRYPTO_EKS_TRUSTED_KEY_USAGE_OID, 1);
	if (trusted == NULL) {
		goto end;
	}
	for (int i = 0; i < X509at_get_attr_count(attrs); i++) {
		const X509_ATTRIBUTE *attr = X509at_get_attr(attrs, i);
		if (OBJ_cmp(X509_ATTRIBUTE_get0_object((X509_ATTRIBUTE *)attr), trusted) == 0) {
			found = 1;
			break;
		}
	}
	ASN1_OBJECT_free(trusted);

end:
	return found;
}

/**
 * Try to extract raw AES key bytes from a PKCS8_PRIV_KEY_INFO. Returns a
 * heap-allocated copy on success (caller frees), NULL otherwise.
 */
static uint8_t *extract_secret_bytes_from_p8(const PKCS8_PRIV_KEY_INFO *p8, int *out_len) {
	uint8_t *out = NULL;
	*out_len = 0;
	const ASN1_OBJECT *alg_obj = NULL;
	const unsigned char *pk = NULL;
	int pk_len = 0;
	if (PKCS8_pkey_get0(&alg_obj, &pk, &pk_len, NULL, p8) == 0) {
		goto end;
	}
	if (alg_obj == NULL || pk == NULL || pk_len <= 0 || !is_aes_oid(alg_obj)) {
		goto end;
	}
	const unsigned char *key_data = pk;
	int key_len = pk_len;
	const unsigned char *tmp = pk;
	ASN1_OCTET_STRING *octet = d2i_ASN1_OCTET_STRING(NULL, &tmp, pk_len);
	if (octet != NULL) {
		key_data = ASN1_STRING_get0_data(octet);
		key_len = ASN1_STRING_length(octet);
	}
	out = (uint8_t *)LLCRYPTO_calloc(1, (size_t)key_len);
	if (out != NULL) {
		(void)memcpy(out, key_data, (size_t)key_len);
		*out_len = key_len;
	}
	if (octet != NULL) {
		ASN1_OCTET_STRING_free(octet);
	}

end:
	return out;
}

static int load_bag_cb(PKCS12_SAFEBAG *bag, const char *password, int pw_len, void *ctx) {
	struct load_ctx *c = (struct load_ctx *)ctx;
	int bag_nid = PKCS12_SAFEBAG_get_nid(bag);

	if (bag_nid == NID_pkcs8ShroudedKeyBag || bag_nid == NID_keyBag) {
		if (c->key_count >= LLCRYPTO_EKS_MAX_OBJECTS) {
			goto end;
		}
		PKCS8_PRIV_KEY_INFO *p8_decrypted = NULL;
		const PKCS8_PRIV_KEY_INFO *p8 = NULL;
		if (bag_nid == NID_pkcs8ShroudedKeyBag) {
			p8_decrypted = PKCS12_decrypt_skey(bag, password, pw_len);
			p8 = p8_decrypted;
		} else {
			p8 = PKCS12_SAFEBAG_get0_p8inf(bag);
		}
		if (p8 == NULL) {
			ERR_clear_error();
			goto end;
		}

		struct loaded_keybag *k = &c->keys[c->key_count];
		(void)memset(k, 0, sizeof(*k));
		(void)extract_bag_alias(bag, k->alias, sizeof(k->alias));
		(void)extract_local_key_id(bag, k->localkeyid, sizeof(k->localkeyid), &k->localkeyid_len);

		int slen = 0;
		uint8_t *sbytes = extract_secret_bytes_from_p8(p8, &slen);
		if (sbytes != NULL) {
			k->secret_bytes = sbytes;
			k->secret_len = slen;
		} else {
			EVP_PKEY *pkey = EVP_PKCS82PKEY(p8);
			if (pkey == NULL) {
				ERR_clear_error();
				PKCS8_PRIV_KEY_INFO_free(p8_decrypted);
				goto end;
			}
			k->pkey = pkey;
		}
		c->key_count++;
		PKCS8_PRIV_KEY_INFO_free(p8_decrypted);
	} else if (bag_nid == NID_secretBag) {
		if (c->key_count >= LLCRYPTO_EKS_MAX_OBJECTS) {
			goto end;
		}
		const ASN1_TYPE *bag_value = PKCS12_SAFEBAG_get0_bag_obj(bag);
		if (bag_value == NULL) {
			goto end;
		}
		if (bag_value->type != V_ASN1_OCTET_STRING && bag_value->type != V_ASN1_SEQUENCE) {
			goto end;
		}
		const ASN1_STRING *os = (bag_value->type == V_ASN1_OCTET_STRING)
		    ? bag_value->value.octet_string : bag_value->value.asn1_string;
		if (os == NULL) {
			goto end;
		}
		const unsigned char *enc_data = ASN1_STRING_get0_data(os);
		int enc_len = ASN1_STRING_length(os);
		const unsigned char *tmp = enc_data;
		X509_SIG *epki = d2i_X509_SIG(NULL, &tmp, enc_len);
		if (epki == NULL) {
			ERR_clear_error();
			goto end;
		}
		PKCS8_PRIV_KEY_INFO *p8 = PKCS8_decrypt(epki, password, pw_len);
		X509_SIG_free(epki);
		if (p8 == NULL) {
			ERR_clear_error();
			goto end;
		}
		int slen = 0;
		uint8_t *sbytes = extract_secret_bytes_from_p8(p8, &slen);
		PKCS8_PRIV_KEY_INFO_free(p8);
		if (sbytes == NULL) {
			goto end;
		}
		struct loaded_keybag *k = &c->keys[c->key_count];
		(void)memset(k, 0, sizeof(*k));
		(void)extract_bag_alias(bag, k->alias, sizeof(k->alias));
		(void)extract_local_key_id(bag, k->localkeyid, sizeof(k->localkeyid), &k->localkeyid_len);
		k->secret_bytes = sbytes;
		k->secret_len = slen;
		c->key_count++;
	} else if (bag_nid == NID_certBag) {
		if (c->cert_count >= (int)(sizeof(c->certs) / sizeof(c->certs[0]))) {
			goto end;
		}
		X509 *cert = PKCS12_SAFEBAG_get1_cert(bag);
		if (cert == NULL) {
			goto end;
		}
		struct loaded_certbag *cb = &c->certs[c->cert_count];
		(void)memset(cb, 0, sizeof(*cb));
		extract_cert_alias(bag, cert, cb->alias, sizeof(cb->alias));
		(void)extract_local_key_id(bag, cb->localkeyid, sizeof(cb->localkeyid), &cb->localkeyid_len);
		cb->trusted = has_trusted_key_usage_attr(bag);
		cb->cert = cert;
		c->cert_count++;
	}

end:
	return 0;
}

/**
 * Build a chain stack for a leaf cert by walking issuer→subject names through
 * the available cert bags. The leaf is NOT pushed (caller does that). Stops at
 * a self-signed cert or when no parent is found.
 *
 * Returns ownership of the chain stack to the caller (NULL on alloc failure).
 * X509_up_ref is used so the caller's chain owns its own references.
 */
static STACK_OF(X509) * build_chain_for_leaf(X509 * leaf, struct loaded_certbag *certs, int cert_count) {
	STACK_OF(X509) * result = NULL;
	STACK_OF(X509) * chain = sk_X509_new_null();
	if (chain == NULL) {
		goto end;
	}
	if (sk_X509_push(chain, leaf) <= 0) {
		sk_X509_free(chain);
		goto end;
	}
	X509_up_ref(leaf);

	X509 *current = leaf;
	while (1) {
		X509_NAME *issuer = X509_get_issuer_name(current);
		X509_NAME *subject = X509_get_subject_name(current);
		if (issuer == NULL || subject == NULL || X509_NAME_cmp(issuer, subject) == 0) {
			break; /* self-signed root */
		}
		X509 *parent = NULL;
		for (int i = 0; i < cert_count; i++) {
			X509 *cand = certs[i].cert;
			if (cand == NULL || cand == current) {
				continue;
			}
			if (X509_NAME_cmp(X509_get_subject_name(cand), issuer) == 0) {
				parent = cand;
				break;
			}
		}
		if (parent == NULL) {
			break;
		}
		if (sk_X509_push(chain, parent) <= 0) {
			break;
		}
		X509_up_ref(parent);
		current = parent;
	}
	result = chain;

end:
	return result;
}

/**
 * Load every keystore entry from disk into a fresh array. On success, sets
 * *out_entries / *out_count and returns LLCRYPTO_SUCCESS. On any error, returns LLCRYPTO_ERROR.
 */
static int p12_load_entries(const char *path, const char *password, int pw_len,
                            struct p12_entry **out_entries, int *out_count) {
	*out_entries = NULL;
	*out_count = 0;

	struct load_ctx ctx;
	(void)memset(&ctx, 0, sizeof(ctx));

	/* Empty file = empty keystore. Treat as success with zero entries — Java
	 * lets you setEntry on a freshly-loaded but empty keystore, and our login
	 * may have validated an empty .p12 we wrote ourselves on a previous run. */
	if (access(path, F_OK) != 0) {
		struct p12_entry *empty = (struct p12_entry *)LLCRYPTO_calloc(1, sizeof(*empty));
		*out_entries = empty;
		return (empty != NULL) ? LLCRYPTO_SUCCESS : LLCRYPTO_ERROR;
	}

	if (iterate_p12_bags(path, password, pw_len, load_bag_cb, &ctx) != LLCRYPTO_SUCCESS) {
		for (int i = 0; i < ctx.cert_count; i++) {
			X509_free(ctx.certs[i].cert);
		}
		for (int i = 0; i < ctx.key_count; i++) {
			EVP_PKEY_free(ctx.keys[i].pkey);
			LLCRYPTO_free(ctx.keys[i].secret_bytes);
		}
		return LLCRYPTO_ERROR;
	}

	/* Allocate worst case: every key + every trusted cert is its own entry. */
	int max_entries = ctx.key_count + ctx.cert_count;
	if (max_entries == 0) {
		max_entries = 1; /* avoid 0-sized alloc */
	}
	struct p12_entry *entries = (struct p12_entry *)LLCRYPTO_calloc((size_t)max_entries, sizeof(*entries));
	if (entries == NULL) {
		for (int i = 0; i < ctx.cert_count; i++) {
			X509_free(ctx.certs[i].cert);
		}
		for (int i = 0; i < ctx.key_count; i++) {
			EVP_PKEY_free(ctx.keys[i].pkey);
			LLCRYPTO_free(ctx.keys[i].secret_bytes);
		}
		return LLCRYPTO_ERROR;
	}
	int count = 0;

	/* 1) Build one entry per key. Find the leaf cert by matching localKeyID
	 *    (preferred) or, if missing, by matching alias. */
	for (int i = 0; i < ctx.key_count; i++) {
		struct loaded_keybag *k = &ctx.keys[i];
		struct p12_entry *e = &entries[count];
		(void)p12_entry_set_alias(e, k->alias);
		if (k->pkey != NULL) {
			e->type = P12_ENTRY_PRIVATE_KEY;
			e->pkey = k->pkey;
			k->pkey = NULL;
			/* Find leaf cert matching this key. */
			X509 *leaf = NULL;
			int leaf_idx = -1;
			for (int j = 0; j < ctx.cert_count; j++) {
				struct loaded_certbag *cb = &ctx.certs[j];
				if (cb->cert == NULL) {
					continue;
				}
				int matches = 0;
				if (k->localkeyid_len > 0 && cb->localkeyid_len == k->localkeyid_len &&
				    memcmp(k->localkeyid, cb->localkeyid, (size_t)k->localkeyid_len) == 0) {
					matches = 1;
				} else if (cb->localkeyid_len == 0 && cb->alias[0] != '\0' &&
				           llcrypto_eks_strcasecmp(cb->alias, k->alias) == 0 && !cb->trusted) {
					matches = 1;
				}
				if (matches) {
					leaf = cb->cert;
					leaf_idx = j;
					break;
				}
			}
			if (leaf != NULL) {
				e->chain = build_chain_for_leaf(leaf, ctx.certs, ctx.cert_count);
				/* Mark all chain certs as consumed (clear from the cert table)
				 * so they don't end up as separate trusted entries. */
				if (e->chain != NULL) {
					for (int k2 = 0; k2 < sk_X509_num(e->chain); k2++) {
						X509 *cc = sk_X509_value(e->chain, k2);
						for (int j = 0; j < ctx.cert_count; j++) {
							if (ctx.certs[j].cert == cc) {
								X509_free(ctx.certs[j].cert);
								ctx.certs[j].cert = NULL;
								break;
							}
						}
					}
				} else {
					/* At least drop the leaf. */
					X509_free(ctx.certs[leaf_idx].cert);
					ctx.certs[leaf_idx].cert = NULL;
				}
			}
		} else {
			e->type = P12_ENTRY_SECRET_KEY;
			e->secret_bytes = k->secret_bytes;
			e->secret_len = k->secret_len;
			k->secret_bytes = NULL;
			(void)strcpy(e->secret_algorithm, "AES");
		}
		count++;
	}

	/* 2) Whatever certs are left are standalone — typically Java trusted-cert
	 *    entries. We expose them iff they have an alias (anything else is an
	 *    orphaned chain cert, which can't be retrieved anyway). */
	for (int j = 0; j < ctx.cert_count; j++) {
		struct loaded_certbag *cb = &ctx.certs[j];
		if (cb->cert == NULL || cb->alias[0] == '\0') {
			X509_free(cb->cert);
			cb->cert = NULL;
			continue;
		}
		if (count >= max_entries) {
			X509_free(cb->cert);
			cb->cert = NULL;
			continue;
		}
		struct p12_entry *e = &entries[count];
		(void)p12_entry_set_alias(e, cb->alias);
		e->type = P12_ENTRY_TRUSTED_CERT;
		e->trusted_cert = cb->cert;
		cb->cert = NULL;
		count++;
	}

	*out_entries = entries;
	*out_count = count;
	return LLCRYPTO_SUCCESS;
}

// -----------------------------------------------------------------------------
// Saving entries: rebuild the .p12 from scratch using OpenSSL safebag helpers.
// -----------------------------------------------------------------------------

/**
 * Build a PKCS8 PrivateKeyInfo wrapping a raw AES secret. The reader's
 * extract_secret_bytes_from_p8 accepts either raw bytes or an OCTET-STRING
 * wrapper; we use the wrapper for compatibility with Java keytool's format.
 */
static PKCS8_PRIV_KEY_INFO *aes_secret_to_p8(const uint8_t *bytes, int len) {
	PKCS8_PRIV_KEY_INFO *result = NULL;
	PKCS8_PRIV_KEY_INFO *p8 = PKCS8_PRIV_KEY_INFO_new();
	if (p8 == NULL) {
		goto end;
	}
	ASN1_OBJECT *aes_oid = OBJ_txt2obj("2.16.840.1.101.3.4.1", 1);
	if (aes_oid == NULL) {
		PKCS8_PRIV_KEY_INFO_free(p8);
		goto end;
	}
	ASN1_OCTET_STRING *octet = ASN1_OCTET_STRING_new();
	if (octet == NULL || !ASN1_OCTET_STRING_set(octet, bytes, len)) {
		ASN1_OCTET_STRING_free(octet);
		ASN1_OBJECT_free(aes_oid);
		PKCS8_PRIV_KEY_INFO_free(p8);
		goto end;
	}
	int wrapped_len = i2d_ASN1_OCTET_STRING(octet, NULL);
	unsigned char *wrapped = (unsigned char *)OPENSSL_malloc((size_t)wrapped_len);
	if (wrapped == NULL) {
		ASN1_OCTET_STRING_free(octet);
		ASN1_OBJECT_free(aes_oid);
		PKCS8_PRIV_KEY_INFO_free(p8);
		goto end;
	}
	unsigned char *p = wrapped;
	(void)i2d_ASN1_OCTET_STRING(octet, &p);
	ASN1_OCTET_STRING_free(octet);

	if (!PKCS8_pkey_set0(p8, aes_oid, 0, V_ASN1_NULL, NULL, wrapped, wrapped_len)) {
		OPENSSL_free(wrapped);
		ASN1_OBJECT_free(aes_oid);
		PKCS8_PRIV_KEY_INFO_free(p8);
		goto end;
	}
	/* PKCS8_pkey_set0 took ownership of aes_oid + wrapped on success. */
	result = p8;

end:
	return result;
}

/* Trusted certs need to be flagged as top-level entries so the read path
 * (llcrypto_eks_is_toplevel_cert_bag) does not skip them as chain certs. The
 * standard marker is Java keytool's oracleTrustedKeyUsage attribute (an
 * X509_ATTRIBUTE with an OBJECT-typed value). OpenSSL 3's encode path for
 * X509_ATTRIBUTE.set rejects ASN1_TYPE values built via the public API
 * ("illegal zero content"), so we use a different recognized marker
 * instead: a random localKeyID. Certs without an associated key still get
 * classified correctly — they become top-level (because the marker is
 * present) and orphan (because no key has a matching localKeyID), which is
 * exactly P12_ENTRY_TRUSTED_CERT. */

/**
 * Push a private/secret-key safebag onto key_bags, with friendlyName + (if
 * non-empty) localKeyID attributes. Returns the new bag pointer (still owned
 * by the stack) or NULL on failure.
 */
static PKCS12_SAFEBAG *push_key_bag(STACK_OF(PKCS12_SAFEBAG) **key_bags,
                                    PKCS8_PRIV_KEY_INFO *p8,
                                    const char *password, int pw_len,
                                    const char *alias,
                                    const unsigned char *local_id, int local_id_len) {
	unsigned char salt[PKCS12_SALT_LEN];
	if (RAND_bytes(salt, sizeof(salt)) != 1) {
		return NULL;
	}
	PKCS12_SAFEBAG *bag = PKCS12_SAFEBAG_create_pkcs8_encrypt(
		NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
		password, pw_len,
		salt, sizeof(salt),
		LLCRYPTO_EKS_PBE_ITER, p8);
	if (bag == NULL) {
		return NULL;
	}

	if (alias != NULL && PKCS12_add_friendlyname(bag, alias, -1) != 1) {
		PKCS12_SAFEBAG_free(bag);
		return NULL;
	}
	if (local_id_len > 0 &&
	    PKCS12_add_localkeyid(bag, (unsigned char *)local_id, local_id_len) != 1) {
		PKCS12_SAFEBAG_free(bag);
		return NULL;
	}

	if (*key_bags == NULL) {
		*key_bags = sk_PKCS12_SAFEBAG_new_null();
		if (*key_bags == NULL) {
			PKCS12_SAFEBAG_free(bag);
			return NULL;
		}
	}
	if (sk_PKCS12_SAFEBAG_push(*key_bags, bag) <= 0) {
		PKCS12_SAFEBAG_free(bag);
		return NULL;
	}
	return bag;
}

/**
 * Push a cert safebag with friendlyName (if alias non-empty) + localKeyID
 * (if local_id_len > 0) + optional trustedKeyUsage. Returns the bag (owned by
 * the stack) or NULL on failure.
 */
static PKCS12_SAFEBAG *push_cert_bag(STACK_OF(PKCS12_SAFEBAG) **cert_bags,
                                     X509 *cert,
                                     const char *alias,
                                     const unsigned char *local_id, int local_id_len,
                                     int trusted) {
	PKCS12_SAFEBAG *bag = PKCS12_add_cert(cert_bags, cert);
	if (bag == NULL) {
		return NULL;
	}
	if (alias != NULL && alias[0] != '\0' &&
	    PKCS12_add_friendlyname(bag, alias, -1) != 1) {
		return NULL;
	}

	unsigned char trusted_id[LLCRYPTO_EKS_LOCAL_KEY_ID_LEN];
	if (trusted && local_id_len == 0) {
		if (RAND_bytes(trusted_id, sizeof(trusted_id)) != 1) {
			return NULL;
		}
		local_id = trusted_id;
		local_id_len = (int)sizeof(trusted_id);
	}
	if (local_id_len > 0 &&
	    PKCS12_add_localkeyid(bag, (unsigned char *)local_id, local_id_len) != 1) {
		return NULL;
	}
	return bag;
}

/**
 * Build the new PKCS#12 in memory and write it atomically (temp file + rename
 * onto path). Returns LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR on failure.
 */
static int p12_save_entries(const char *path, const char *password, int pw_len,
                            const struct p12_entry *entries, int count) {
	int result = LLCRYPTO_ERROR;
	STACK_OF(PKCS7) * safes = NULL;
	STACK_OF(PKCS12_SAFEBAG) * cert_bags = NULL;
	STACK_OF(PKCS12_SAFEBAG) * key_bags = NULL;
	PKCS12 *p12 = NULL;
	BIO *out = NULL;
	char tmp_path[PATH_MAX];

	int tlen = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
	if (tlen < 0 || (size_t)tlen >= sizeof(tmp_path)) {
		goto end;
	}

	for (int i = 0; i < count; i++) {
		const struct p12_entry *e = &entries[i];
		if (e->type == P12_ENTRY_PRIVATE_KEY) {
			unsigned char local_id[LLCRYPTO_EKS_LOCAL_KEY_ID_LEN];
			if (RAND_bytes(local_id, sizeof(local_id)) != 1) {
				goto end;
			}
			PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(e->pkey);
			if (p8 == NULL) {
				goto end;
			}
			PKCS12_SAFEBAG *kb = push_key_bag(&key_bags, p8, password, pw_len,
			                                  e->alias, local_id, sizeof(local_id));
			PKCS8_PRIV_KEY_INFO_free(p8);
			if (kb == NULL) {
				goto end;
			}
			/* Add chain certs. Leaf gets friendlyName + localKeyID; others
			 * are pure chain links (no alias, no marker). */
			if (e->chain != NULL) {
				int n_chain = sk_X509_num(e->chain);
				for (int j = 0; j < n_chain; j++) {
					X509 *cc = sk_X509_value(e->chain, j);
					const char *cert_alias = (j == 0) ? e->alias : NULL;
					const unsigned char *cert_local = (j == 0) ? local_id : NULL;
					int cert_local_len = (j == 0) ? (int)sizeof(local_id) : 0;
					if (push_cert_bag(&cert_bags, cc, cert_alias,
					                  cert_local, cert_local_len, 0) == NULL) {
						goto end;
					}
				}
			}
		} else if (e->type == P12_ENTRY_SECRET_KEY) {
			PKCS8_PRIV_KEY_INFO *p8 = aes_secret_to_p8(e->secret_bytes, e->secret_len);
			if (p8 == NULL) {
				goto end;
			}
			PKCS12_SAFEBAG *kb = push_key_bag(&key_bags, p8, password, pw_len,
			                                  e->alias, NULL, 0);
			PKCS8_PRIV_KEY_INFO_free(p8);
			if (kb == NULL) {
				goto end;
			}
		} else { /* P12_ENTRY_TRUSTED_CERT */
			if (push_cert_bag(&cert_bags, e->trusted_cert, e->alias, NULL, 0, 1) == NULL) {
				goto end;
			}
		}
	}

	/* Wrap each non-empty bag stack in a PKCS7 safe.
	 *
	 * Both safes use NID_pkcs7_data (nid_safe = -1, no outer encryption).
	 * Java keytool wraps cert bags in NID_pbe_WithSHA1And40BitRC2_CBC, but
	 * RC2 isn't in the OpenSSL 3 default provider — it's relegated to the
	 * legacy provider, which we don't enable here. The certs are public
	 * regardless, and Java's KeyStore.load happily reads either form.
	 *
	 * PKCS12_add_safe does NOT consume the bag stack — the bags get
	 * serialized into the produced PKCS7 but their lifetime stays with us.
	 * They are freed unconditionally by the cleanup block below. */
	if (cert_bags != NULL && sk_PKCS12_SAFEBAG_num(cert_bags) > 0) {
		if (PKCS12_add_safe(&safes, cert_bags, -1, 0, NULL) != 1) {
			goto end;
		}
	}
	if (key_bags != NULL && sk_PKCS12_SAFEBAG_num(key_bags) > 0) {
		if (PKCS12_add_safe(&safes, key_bags, -1, 0, NULL) != 1) {
			goto end;
		}
	}

	p12 = PKCS12_add_safes(safes, 0);
	if (p12 == NULL) {
		goto end;
	}
	/* PKCS12_add_safes consumed the safes stack. */
	safes = NULL;

	if (PKCS12_set_mac(p12, password, pw_len, NULL, 0, LLCRYPTO_EKS_PBE_ITER, NULL) != 1) {
		goto end;
	}

	out = BIO_new_file(tmp_path, "wb");
	if (out == NULL) {
		goto end;
	}
	if (i2d_PKCS12_bio(out, p12) <= 0) {
		BIO_free(out);
		out = NULL;
		(void)unlink(tmp_path);
		goto end;
	}
	BIO_free(out);
	out = NULL;

	if (rename(tmp_path, path) != 0) {
		(void)unlink(tmp_path);
		goto end;
	}

	result = LLCRYPTO_SUCCESS;

end:
	/* PKCS12_add_safe took ownership of the bag stacks on success. On
	 * failure they may still hold bags we created, so free them. */
	if (cert_bags != NULL && sk_PKCS12_SAFEBAG_num(cert_bags) > 0) {
		sk_PKCS12_SAFEBAG_pop_free(cert_bags, PKCS12_SAFEBAG_free);
	} else {
		sk_PKCS12_SAFEBAG_free(cert_bags);
	}
	if (key_bags != NULL && sk_PKCS12_SAFEBAG_num(key_bags) > 0) {
		sk_PKCS12_SAFEBAG_pop_free(key_bags, PKCS12_SAFEBAG_free);
	} else {
		sk_PKCS12_SAFEBAG_free(key_bags);
	}
	sk_PKCS7_pop_free(safes, PKCS7_free);
	PKCS12_free(p12);
	BIO_free(out);
	return result;
}

// -----------------------------------------------------------------------------
// Mutator helpers
// -----------------------------------------------------------------------------

/**
 * Same parsing strategy as the PKCS#11 backend: try unencrypted PKCS#8, then
 * fall back to PBES2-encrypted PKCS#8 using the keystore PIN.
 */
static EVP_PKEY *p12_parse_protected_key(const uint8_t *data, int32_t len) {
	EVP_PKEY *result = NULL;
	const unsigned char *p = data;
	PKCS8_PRIV_KEY_INFO *p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)len);
	if (p8inf != NULL) {
		EVP_PKEY *pkey = EVP_PKCS82PKEY(p8inf);
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		if (pkey != NULL) {
			result = pkey;
			goto end;
		}
	}
	ERR_clear_error();

	p = data;
	X509_SIG *sig = d2i_X509_SIG(NULL, &p, (long)len);
	if (sig == NULL) {
		ERR_clear_error();
		goto end;
	}
	p8inf = PKCS8_decrypt(sig, g_keystore.password, g_keystore.pw_len);
	X509_SIG_free(sig);
	if (p8inf == NULL) {
		ERR_clear_error();
		goto end;
	}
	result = EVP_PKCS82PKEY(p8inf);
	PKCS8_PRIV_KEY_INFO_free(p8inf);

end:
	return result;
}

// -----------------------------------------------------------------------------
// LLAPI write entry points
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getEntryType(jbyte *alias) {
	jint result = LLCRYPTO_ERROR;
	/* A key entry holds a private/secret key (and possibly a chain); a cert
	 * entry holds only a certificate. Probe the key path first — getKeyId
	 * returns LLCRYPTO_ERROR for cert-only aliases. */
	jint key_id = LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyId(alias, NULL);
	if (key_id != LLCRYPTO_ERROR) {
		/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
		struct llcrypto_key *key = (struct llcrypto_key *)(intptr_t)key_id;
		llcrypto_key_free(key);
		result = (jint)LLCRYPTO_ENTRY_TYPE_KEY;
	} else {
		jint cert_handle = LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateHandle(alias);
		if (cert_handle != LLCRYPTO_ERROR) {
			/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
			struct llcrypto_eks_cert *c = (struct llcrypto_eks_cert *)(intptr_t)cert_handle;
			llcrypto_eks_cert_free(c);
			result = (jint)LLCRYPTO_ENTRY_TYPE_CERTIFICATE;
		}
	}
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_deleteEntry(jbyte *alias) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s alias='%s'\n", __func__, (const char *)alias);
	jint result = LLCRYPTO_ERROR;
	struct p12_entry *entries = NULL;
	int count = 0;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	if (p12_load_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len, &entries,
	                     &count) != LLCRYPTO_SUCCESS) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot read keystore"));
		goto end;
	}

	int new_count = p12_entries_remove(entries, count, (const char *)alias);
	/* Java semantics: deleting a non-existent alias is a silent no-op, so we
	 * still rewrite (no-op write) to be consistent and avoid surprising the
	 * caller with a no-write outcome. */
	if (p12_save_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     entries, new_count) != LLCRYPTO_SUCCESS) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot write keystore"));
		goto end;
	}
	result = LLCRYPTO_SUCCESS;

end:
	p12_entries_free(entries, count);
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_setCertificateEntry(jbyte *alias, jbyte *certificate) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s alias='%s'\n", __func__, (const char *)alias);
	jint result = LLCRYPTO_ERROR;
	struct p12_entry *entries = NULL;
	int count = 0;
	X509 *cert = NULL;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	jint cert_len = SNI_getArrayLength((void *)certificate);
	if (cert_len <= 0) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Empty certificate"));
		goto end;
	}
	const unsigned char *p = (const unsigned char *)certificate;
	cert = d2i_X509(NULL, &p, (long)cert_len);
	if (cert == NULL) {
		ERR_clear_error();
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot parse X.509 certificate"));
		goto end;
	}

	if (p12_load_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len, &entries,
	                     &count) != LLCRYPTO_SUCCESS) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot read keystore"));
		goto end;
	}

	count = p12_entries_remove(entries, count, (const char *)alias);

	/* Append the new trusted-cert entry. Reallocate to grow by one if needed. */
	struct p12_entry *grown = (struct p12_entry *)LLCRYPTO_calloc((size_t)(count + 1), sizeof(*grown));
	if (grown == NULL) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Out of memory"));
		goto end;
	}
	if (count > 0) {
		(void)memcpy(grown, entries, (size_t)count * sizeof(*grown));
		(void)memset(entries, 0, (size_t)count * sizeof(*entries));
	}
	LLCRYPTO_free(entries);
	entries = grown;
	(void)p12_entry_set_alias(&entries[count], (const char *)alias);
	entries[count].type = P12_ENTRY_TRUSTED_CERT;
	entries[count].trusted_cert = cert;
	cert = NULL; /* ownership moved into entry */
	count++;

	if (p12_save_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     entries, count) != LLCRYPTO_SUCCESS) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot write keystore"));
		goto end;
	}
	result = LLCRYPTO_SUCCESS;

end:
	X509_free(cert);
	p12_entries_free(entries, count);
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_openKeyEntryWithData(jbyte *alias, jbyte *key, jint chain_len) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s alias='%s' chain_len=%d\n", __func__, (const char *)alias, (int)chain_len);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	jint key_len = SNI_getArrayLength((void *)key);
	if (key_len <= 0) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Empty key data"));
		goto end;
	}

	struct llcrypto_eks_key_import *h = llcrypto_eks_key_import_new((const char *)alias, (int)chain_len);
	if (h == NULL) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Out of memory"));
		goto end;
	}
	h->key_evp = p12_parse_protected_key((const uint8_t *)key, key_len);
	if (h->key_evp == NULL) {
		llcrypto_eks_key_import_free(h);
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR,
		                                                     "Cannot parse key data (PKCS#8 plain or PBES2-encrypted)"));
		goto end;
	}
	/* cppcheck-suppress misra-c2012-11.6 */ // Abstract data type for SNI usage
	result = (jint)(intptr_t)h;

end:
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_openKeyEntryWithNativeId(jbyte *alias, jint key_id, jchar *password,
                                                              jint chain_len) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s alias='%s' key_id=%p chain_len=%d\n",
	                          __func__, (const char *)alias, (void *)(intptr_t)key_id, (int)chain_len);
	LLCRYPTO_UNUSED_PARAM(password); /* keystore password authenticates writes */
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}
	struct llcrypto_eks_key_import *h = llcrypto_eks_key_import_new((const char *)alias, (int)chain_len);
	if (h == NULL) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Out of memory"));
		goto end;
	}
	h->key_native_id = key_id;
	/* cppcheck-suppress misra-c2012-11.6 */ // Abstract data type for SNI usage
	result = (jint)(intptr_t)h;

end:
	return result;
}

/* insertCertificateInChain is implemented in LLCRYPTO_EXTERNAL_KEYSTORE_common.c. */

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_closeKeyEntry(jint handle) {
	LLCRYPTO_EKS_DEBUG_PRINTF("%s handle=%p\n", __func__, (void *)(intptr_t)handle);
	jint result = LLCRYPTO_ERROR;
	struct p12_entry *entries = NULL;
	int count = 0;
	/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
	struct llcrypto_eks_key_import *h = (struct llcrypto_eks_key_import *)(intptr_t)handle;
	if (h == NULL) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "NULL key entry handle"));
		goto end;
	}

	/* Java calls closeKeyEntry from a `finally` block whether or not the
	 * preceding insertCertificateInChain loop completed. If chain_count is
	 * short of chain_len, the Java side aborted (an insert failed and the
	 * loop broke out before filling every slot). Returning without rewriting
	 * the .p12 leaves the previous binding intact — committing a truncated
	 * chain would silently destroy it while the caller already saw a
	 * KeyStoreException. */
	if (h->chain_count < h->chain_len) {
		LLCRYPTO_EKS_DEBUG_PRINTF("%s aborting commit: chain_count=%d chain_len=%d\n",
		                          __func__, h->chain_count, h->chain_len);
		result = LLCRYPTO_SUCCESS;
		goto end;
	}

	if (!g_keystore.loaded) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Keystore not loaded"));
		goto end;
	}

	if (p12_load_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len, &entries,
	                     &count) != LLCRYPTO_SUCCESS) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot read keystore"));
		goto end;
	}

	count = p12_entries_remove(entries, count, h->alias);

	struct p12_entry *grown = (struct p12_entry *)LLCRYPTO_calloc((size_t)(count + 1), sizeof(*grown));
	if (grown == NULL) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Out of memory"));
		goto end;
	}
	if (count > 0) {
		(void)memcpy(grown, entries, (size_t)count * sizeof(*grown));
		(void)memset(entries, 0, (size_t)count * sizeof(*entries));
	}
	LLCRYPTO_free(entries);
	entries = grown;

	struct p12_entry *new_entry = &entries[count];
	(void)p12_entry_set_alias(new_entry, h->alias);
	/* Bump count now so any goto end below routes new_entry through
	 * p12_entries_free → p12_entry_clear. The slot is zero-initialized
	 * (LLCRYPTO_calloc on `grown`) and p12_entry_clear is NULL-safe on every
	 * field, so an early bump can't leak — but a *late* bump would, since
	 * the failure paths in the key-resolution and chain-build blocks below
	 * each set new_entry->pkey / ->chain / ->secret_bytes before the
	 * eventual count++. */
	count++;

	/* Resolve the key — three sources, mutually exclusive. */
	if (h->key_evp != NULL) {
		new_entry->type = P12_ENTRY_PRIVATE_KEY;
		new_entry->pkey = h->key_evp;
		h->key_evp = NULL;
	} else if (h->key_native_id != 0) {
		/* cppcheck-suppress misra-c2012-11.4 */ // Abstract data type for SNI usage
		struct llcrypto_key *src = (struct llcrypto_key *)(intptr_t)h->key_native_id;
		if (src->type == LLCRYPTO_KEY_TYPE_EVP_PKEY) {
			new_entry->type = P12_ENTRY_PRIVATE_KEY;
			EVP_PKEY_up_ref(src->evp_key);
			new_entry->pkey = src->evp_key;
		} else if (src->type == LLCRYPTO_KEY_TYPE_SECRET_KEY) {
			new_entry->type = P12_ENTRY_SECRET_KEY;
			new_entry->secret_bytes = (uint8_t *)LLCRYPTO_calloc(1, src->secret_key.length);
			if (new_entry->secret_bytes == NULL) {
				LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Out of memory"));
				goto end;
			}
			(void)memcpy(new_entry->secret_bytes, src->secret_key.buffer, src->secret_key.length);
			new_entry->secret_len = (int)src->secret_key.length;
			const char *alg = (src->secret_key.algorithm != NULL) ? src->secret_key.algorithm : "AES";
			size_t alg_len = strlen(alg);
			if (alg_len >= sizeof(new_entry->secret_algorithm)) {
				alg_len = sizeof(new_entry->secret_algorithm) - 1;
			}
			(void)memcpy(new_entry->secret_algorithm, alg, alg_len);
			new_entry->secret_algorithm[alg_len] = '\0';
		} else {
			LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Unsupported key type"));
			goto end;
		}
	} else {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "No key source for entry"));
		goto end;
	}

	/* Attach the chain (only meaningful for asymmetric keys). For secrets we
	 * silently ignore the chain — the LLAPI permits it, but Java's KeyStore
	 * doesn't allow chains on secret keys, so chain_count is always 0. */
	if (new_entry->type == P12_ENTRY_PRIVATE_KEY && h->chain_count > 0) {
		new_entry->chain = sk_X509_new_null();
		if (new_entry->chain == NULL) {
			LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Out of memory"));
			goto end;
		}
		for (int i = 0; i < h->chain_count; i++) {
			if (h->chain_certs[i].der == NULL) {
				LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Missing chain cert"));
				goto end;
			}
			const unsigned char *p = h->chain_certs[i].der;
			X509 *cc = d2i_X509(NULL, &p, h->chain_certs[i].len);
			if (cc == NULL) {
				ERR_clear_error();
				LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot parse chain cert"));
				goto end;
			}
			if (sk_X509_push(new_entry->chain, cc) <= 0) {
				X509_free(cc);
				goto end;
			}
		}
	}

	if (p12_save_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     entries, count) != LLCRYPTO_SUCCESS) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Cannot write keystore"));
		goto end;
	}
	result = LLCRYPTO_SUCCESS;

end:
	p12_entries_free(entries, count);
	llcrypto_eks_key_import_free(h);
	return result;
}
