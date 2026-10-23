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
 * No keystore entry — key or certificate — is cached between LLAPI calls. Each
 * function re-opens the PKCS#12 file, extracts exactly the data it needs, and frees
 * all OpenSSL objects before returning. Keys are returned as SNI-managed llcrypto_key
 * handles. Certificates are returned as SNI-managed DER blobs. Both are freed by the
 * Java GC when no longer referenced.
 *
 * The login password is the one exception: it is cached in g_keystore.password for the
 * process lifetime, both because the certificate APIs need it to re-read the file and
 * because login() validates every call after the first against that cached copy instead
 * of touching the file again.
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <LLCRYPTO_EXTERNAL_KEYSTORE_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_EXTERNAL_KEYSTORE_common.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/** Filesystem path for the PKCS#12 keystore file. Project-specific; set at
 *  build time from project_options.cmake via -DLLCRYPTO_KEYSTORE_PATH="...". */
#ifndef LLCRYPTO_KEYSTORE_PATH
#define LLCRYPTO_KEYSTORE_PATH "/tmp/test-keystore.p12"
#endif

/** Base AES OID. Java keytool writes this rather than one of the per-mode AES OIDs, and it has
 *  no NID, so it has to be matched as text. */
#define LLCRYPTO_EKS_AES_BASE_OID "2.16.840.1.101.3.4.1"

/** Buffer for an OID rendered as dotted-decimal text by OBJ_obj2txt. */
#define LLCRYPTO_EKS_OID_TEXT_BUF_LEN 64

/** Buffer for a localKeyID read off the file. Generated IDs are
 *  LLCRYPTO_EKS_LOCAL_KEY_ID_LEN bytes, but a foreign writer may have used a longer one. */
#define LLCRYPTO_EKS_LOCAL_KEY_ID_MAX_LEN 64

/** Certificates collectable per key entry: the entry's own certificate plus its chain. */
#define LLCRYPTO_EKS_MAX_CERTS_PER_ENTRY 4

// -----------------------------------------------------------------------------
// Internal data structures
// -----------------------------------------------------------------------------

/**
 * Global keystore state — holds only the file path and cached password.
 * No entry table, no keys, no certificates.
 */
static struct {
	bool loaded;
	char path[PATH_MAX];
	/** Heap-allocated copy of the login password. Needed by the certificate APIs to
	 *  re-read the file, and by login() as the authority for its re-check. */
	char *password;
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
	if (NULL == attrs) {
		goto end;
	}

	int idx = X509at_get_attr_by_NID(attrs, NID_friendlyName, -1);
	if (idx < 0) {
		goto end;
	}

	X509_ATTRIBUTE *attr = X509at_get_attr(attrs, idx);
	if (NULL == attr) {
		goto end;
	}

	const ASN1_TYPE *val = X509_ATTRIBUTE_get0_type(attr, 0);
	if (NULL == val) {
		goto end;
	}

	/* friendlyName is a BMPString (UTF-16BE). Convert to ASCII. */
	const ASN1_STRING *str = val->value.asn1_string;
	if (NULL == str) {
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
		buf[i] = (char)data[(i * 2) + 1]; /* low byte of BE pair */
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
	if ((buf[0] == '\0') && (NULL != cert)) {
		int alias_len = 0;
		const unsigned char *alias_data = X509_alias_get0(cert, &alias_len);
		if ((NULL != alias_data) && (alias_len > 0)) {
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

	if (0 == result) {
		/* Java keytool uses the base AES OID (2.16.840.1.101.3.4.1) which has no NID. */
		char oid_buf[LLCRYPTO_EKS_OID_TEXT_BUF_LEN];
		if (OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1) > 0) {
			if (0 == strcmp(oid_buf, LLCRYPTO_EKS_AES_BASE_OID)) {
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
	if (NULL == bio) {
		goto end;
	}

	p12 = d2i_PKCS12_bio(bio, NULL);
	/* The BIO is released anyway, so a failure leaves nothing to act on. */
	(void)BIO_free(bio);
	if (NULL == p12) {
		goto end;
	}

	if (!PKCS12_verify_mac(p12, password, pw_len)) {
		goto end;
	}

	authsafes = PKCS12_unpack_authsafes(p12);
	if (NULL == authsafes) {
		goto end;
	}

	int stop = 0;
	for (int i = 0; i < sk_PKCS7_num(authsafes) && !stop; i++) {
		PKCS7 *p7 = sk_PKCS7_value(authsafes, i);
		int bagnid = OBJ_obj2nid(p7->type);

		STACK_OF(PKCS12_SAFEBAG) * bags = NULL;
		if (NID_pkcs7_data == bagnid) {
			bags = PKCS12_unpack_p7data(p7);
		} else if (NID_pkcs7_encrypted == bagnid) {
			bags = PKCS12_unpack_p7encdata(p7, password, pw_len);
		} else {
			continue;
		}
		if (NULL == bags) {
			continue;
		}

		for (int j = 0; j < sk_PKCS12_SAFEBAG_num(bags) && !stop; j++) {
			stop = cb(sk_PKCS12_SAFEBAG_value(bags, j), password, pw_len, ctx);
		}

		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
	}

	result = LLCRYPTO_SUCCESS;

end:
	if (NULL != authsafes) {
		sk_PKCS7_pop_free(authsafes, PKCS7_free);
	}
	if (NULL != p12) {
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

	if (0 == PKCS8_pkey_get0(&alg_obj, &pk, &pk_len, NULL, p8)) {
		goto end;
	}
	if ((NULL == alg_obj) || (NULL == pk) || (pk_len <= 0)) {
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
	if (NULL != octet) {
		key_data = ASN1_STRING_get0_data(octet);
		key_len = ASN1_STRING_length(octet);
	}

	result = llcrypto_key_from_secret_key(
		key_data, (size_t)key_len, (const uint8_t *)"AES");

	if (NULL != octet) {
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
	if ((NID_pkcs8ShroudedKeyBag != bag_nid) && (NID_keyBag != bag_nid)) {
		goto end;
	}

	if (NID_pkcs8ShroudedKeyBag == bag_nid) {
		p8_decrypted = PKCS12_decrypt_skey(bag, password, pw_len);
		p8 = p8_decrypted;
	} else {
		p8 = PKCS12_SAFEBAG_get0_p8inf(bag);
	}

	if (NULL == p8) {
		goto end;
	}

	/* Try as secret key first. */
	struct llcrypto_key *key = extract_secret_key_from_p8(p8);
	if (NULL == key) {
		/* Try as asymmetric key. */
		EVP_PKEY *pkey = EVP_PKCS82PKEY(p8);
		if (NULL != pkey) {
			int base_id = EVP_PKEY_base_id(pkey);
			if ((EVP_PKEY_RSA == base_id) || (EVP_PKEY_EC == base_id) ||
			    (base_id == EVP_PKEY_ED25519) || (EVP_PKEY_ED448 == base_id)) {
				key = llcrypto_key_from_evp_pkey(pkey);
				if (NULL == key) {
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
	if (NULL == bag_value) {
		goto end;
	}
	if ((V_ASN1_OCTET_STRING != bag_value->type) && (V_ASN1_SEQUENCE != bag_value->type)) {
		goto end;
	}

	const ASN1_STRING *os = (V_ASN1_OCTET_STRING == bag_value->type)
	    ? bag_value->value.octet_string
	    : bag_value->value.asn1_string;
	if (NULL == os) {
		goto end;
	}

	const unsigned char *enc_data = ASN1_STRING_get0_data(os);
	int enc_len = ASN1_STRING_length(os);
	const unsigned char *tmp = enc_data;

	X509_SIG *epki = d2i_X509_SIG(NULL, &tmp, enc_len);
	if (NULL == epki) {
		ERR_clear_error();
		goto end;
	}

	PKCS8_PRIV_KEY_INFO *p8 = PKCS8_decrypt(epki, password, pw_len);
	X509_SIG_free(epki);

	if (NULL != p8) {
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
	if (NULL == attrs) {
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
	if (NULL != trusted_oid) {
		int nid = OBJ_obj2nid(trusted_oid);
		if (NID_undef == nid) {
			/* No registered NID — search attributes manually. */
			for (int i = 0; i < X509at_get_attr_count(attrs); i++) {
				X509_ATTRIBUTE *attr = X509at_get_attr(attrs, i);
				if (0 == OBJ_cmp(X509_ATTRIBUTE_get0_object(attr), trusted_oid)) {
					result = 1;
					break;
				}
			}
		} else if (X509at_get_attr_by_NID(attrs, nid, -1) >= 0) {
			result = 1;
		} else {
			/* The OID is registered but the attribute is absent. */
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
	if ((NID_pkcs8ShroudedKeyBag != bag_nid) && (NID_keyBag != bag_nid) &&
	    (NID_certBag != bag_nid) && (NID_secretBag != bag_nid)) {
		goto end;
	}

	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	alias[0] = '\0';
	if (NID_certBag == bag_nid) {
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

	VEEPORT_LOGGER_LOG_DBG("bag_nid=%d alias='%s'", bag_nid, alias);

	/* Deduplicate. */
	for (int i = 0; i < c->count; i++) {
		if (0 == strcasecmp(c->aliases[i], alias)) {
			goto end; /* already counted */
		}
	}
	if (c->count < LLCRYPTO_EKS_MAX_OBJECTS) {
		size_t len = strlen(alias);
		if (len >= LLCRYPTO_EKS_MAX_ALIAS_LEN) {
			len = LLCRYPTO_EKS_MAX_ALIAS_LEN - 1U;
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
	if ((NID_pkcs8ShroudedKeyBag != bag_nid) && (NID_keyBag != bag_nid) &&
	    (NID_certBag != bag_nid) && (NID_secretBag != bag_nid)) {
		goto end;
	}

	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	alias[0] = '\0';
	if (NID_certBag == bag_nid) {
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
		if (0 == strcasecmp(c->aliases[i], alias)) {
			goto end;
		}
	}
	if (c->alias_count < LLCRYPTO_EKS_MAX_OBJECTS) {
		size_t len = strlen(alias);
		if (len >= LLCRYPTO_EKS_MAX_ALIAS_LEN) {
			len = LLCRYPTO_EKS_MAX_ALIAS_LEN - 1U;
		}
		(void)memcpy(c->aliases[c->alias_count], alias, len);
		c->aliases[c->alias_count][len] = '\0';

		if (c->alias_count == c->target_index) {
			c->result = c->aliases[c->alias_count];
		}
		c->alias_count++;

		if (NULL != c->result) {
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

	if (0 != strcasecmp(alias, c->target_alias)) {
		goto end;
	}

	int bag_nid = PKCS12_SAFEBAG_get_nid(bag);
	struct llcrypto_key *key = NULL;

	if ((NID_pkcs8ShroudedKeyBag == bag_nid) || (NID_keyBag == bag_nid)) {
		key = extract_key_from_keybag(bag, password, pw_len);
	} else if (NID_secretBag == bag_nid) {
		key = extract_key_from_secretbag(bag, password, pw_len);
	} else {
		/* Any other bag type carries no key. */
	}

	if (NULL != key) {
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
	if (NULL == cert) {
		goto end;
	}

	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	extract_cert_alias(bag, cert, alias, sizeof(alias));

	if (0 != strcasecmp(alias, c->target_alias)) {
		X509_free(cert);
		goto end;
	}

	/* First cert matching the alias is the leaf. */
	if (NULL != c->result) {
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
	if (NULL == h) {
		X509_free(cert);
		goto end;
	}
	h->der_data = (uint8_t *)LLCRYPTO_calloc(1, (size_t)der_len);
	if (NULL == h->der_data) {
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
	if ((NULL == cert) || (c->total >= LLCRYPTO_EKS_MAX_OBJECTS)) {
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
	VEEPORT_LOGGER_LOG_DBG("");

	char *pw = NULL;
	size_t pw_size = 0;
	int conv_rc = llcrypto_eks_jchar_to_ascii_cstring(password, &pw, &pw_size);
	if (LLCRYPTO_SUCCESS != conv_rc) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                              (LLCRYPTO_ERROR_OOM == conv_rc) ? "Out of memory" :
		                                              "Keystore password must be ASCII");
		goto end;
	}
	/* The OpenSSL PKCS#12 API takes password lengths as int. */
	int pw_len = (int)pw_size;

	if (g_keystore.loaded) {
		/* Re-check instead of short-circuiting: the contract requires login()
		 * to throw when the password check fails, on every call. The cached
		 * password is the authority here — the file is not re-read. */
		bool same = (pw_len == g_keystore.pw_len)
		            && (0 == CRYPTO_memcmp(pw, g_keystore.password, (size_t)pw_len));
		if (!same) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_EXTERNAL_KEYSTORE_BAD_PASSWORD,
			                                              "Keystore password verification failed");
		}
		goto end;
	}

	/* Compiled-in keystore path, so the application runs with no env. */
	const char *path = LLCRYPTO_KEYSTORE_PATH;

	VEEPORT_LOGGER_LOG_DBG("validating %s", path);

	/* Validate: open, parse, verify MAC, then close immediately. */
	BIO *bio = BIO_new_file(path, "rb");
	if (NULL == bio) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot open keystore file");
		goto end;
	}

	PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
	/* The BIO is released anyway, so a failure leaves nothing to act on. */
	(void)BIO_free(bio);
	if (NULL == p12) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot parse PKCS12 file");
		goto end;
	}

	if (!PKCS12_verify_mac(p12, pw, pw_len)) {
		PKCS12_free(p12);
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_EXTERNAL_KEYSTORE_BAD_PASSWORD,
		                                              "Keystore password verification failed");
		goto end;
	}

	PKCS12_free(p12);

	/* Cache path and password for subsequent LLAPI calls. */
	size_t path_len = strlen(path);
	if (path_len >= sizeof(g_keystore.path)) {
		path_len = sizeof(g_keystore.path) - 1U;
	}
	(void)memcpy(g_keystore.path, path, path_len);
	g_keystore.path[path_len] = '\0';

	/* Ownership transferred. The password is deliberately retained, unscrubbed, for the
	 * process lifetime: there is no logout entry point, the certificate APIs re-read the
	 * file on every call, and login() re-checks against this copy. Scrubbing it would
	 * break both. It is never freed — the process teardown releases the pages. */
	g_keystore.password = pw;
	g_keystore.pw_len = pw_len;
	g_keystore.loaded = true;
	pw = NULL;

	VEEPORT_LOGGER_LOG_DBG("keystore validated, path=%s", g_keystore.path);

end:
	/* Single scrub point: every failure path reaches here with pw still owned,
	 * so a new one cannot forget to wipe the password. pw_size is used rather
	 * than pw_len because the conversion failure path jumps over pw_len. */
	if (NULL != pw) {
		OPENSSL_cleanse(pw, pw_size);
		LLCRYPTO_free(pw);
	}
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_size(void) {
	VEEPORT_LOGGER_LOG_DBG("");
	jint result = SNI_IGNORED_RETURNED_VALUE;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	struct count_ctx ctx;
	(void)memset(&ctx, 0, sizeof(ctx));

	if (iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     count_bag_cb, &ctx) != LLCRYPTO_SUCCESS) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot read keystore");
		goto end;
	}

	VEEPORT_LOGGER_LOG_DBG("%d entries", ctx.count);
	result = (jint)ctx.count;

end:
	VEEPORT_LOGGER_LOG_DBG("return %d", result);
	return result;
}

/*
 * The alias is copied out only once it is known to fit. extract_bag_alias accepts a friendlyName
 * of up to LLCRYPTO_EKS_MAX_ALIAS_LEN - 1 bytes, while the Java side sizes this array from the
 * ej.crypto.externalks.alias.max.length constant — a far smaller value by default — so the two are
 * not interchangeable and only the array's own length can bound the copy.
 */
jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getAlias(jint alias_index, jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("index=%d", (int)alias_index);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	struct alias_ctx ctx;
	(void)memset(&ctx, 0, sizeof(ctx));
	ctx.target_index = (int)alias_index;

	if (iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     alias_bag_cb, &ctx) != LLCRYPTO_SUCCESS) {
		goto end;
	}

	if (NULL == ctx.result) {
		goto end;
	}

	/* One past the alias for the terminator the Java side scans for. */
	size_t alias_size = strlen(ctx.result) + 1U;
	if (!sni_array_contains_range(alias, 0, (int32_t)alias_size)) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Alias too long for the caller's buffer");
		goto end;
	}

	(void)strcpy((char *)alias, ctx.result);
	result = LLCRYPTO_SUCCESS;
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);

end:
	VEEPORT_LOGGER_LOG_DBG("return %d", result);
	return result;
}

jboolean LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_containsAlias(jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jboolean result = (jboolean)JFALSE;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
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
		if (0 == strcasecmp(ctx.aliases[i], (const char *)alias)) {
			result = (jboolean)JTRUE;
			goto end;
		}
	}

end:
	VEEPORT_LOGGER_LOG_DBG("return %d", result);
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Key
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyId(jbyte *alias, jchar *password) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	LLCRYPTO_UNUSED_PARAM(password);

	struct key_ctx ctx;
	ctx.target_alias = (const char *)alias;
	ctx.result = NULL;

	int rc = iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len, key_bag_cb, &ctx);

	if ((LLCRYPTO_SUCCESS != rc) || (NULL == ctx.result)) {
		goto end;
	}

	VEEPORT_LOGGER_LOG_DBG("returning key_id=%p", (void *)ctx.result);
	result = (jint)ctx.result;

end:
	VEEPORT_LOGGER_LOG_DBG("return %d", result);
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyType(jint key_id) {
	VEEPORT_LOGGER_LOG_DBG("key_id=%d", key_id);
	jint result = SNI_IGNORED_RETURNED_VALUE;

	struct llcrypto_key *key = (struct llcrypto_key *)key_id;

	switch (key->type) {
	case LLCRYPTO_KEY_TYPE_EVP_PKEY:
	{
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(NULL, key->evp_key, NULL);
		if ((NULL != pctx) && (1 == EVP_PKEY_private_check(pctx))) {
			result = (jint)LLCRYPTO_KEY_TYPE_PRIVATE;
		} else if ((NULL != pctx) && (1 == EVP_PKEY_public_check(pctx))) {
			result = (jint)LLCRYPTO_KEY_TYPE_PUBLIC;
		} else {
			VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                               "Unable to determine key type");
		}
		EVP_PKEY_CTX_free(pctx);
		break;
	}
	case LLCRYPTO_KEY_TYPE_SECRET_KEY:
		result = (jint)LLCRYPTO_KEY_TYPE_SECRET;
		break;
	default:
	{
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Unknown key type");
		break;
	}
	}

	VEEPORT_LOGGER_LOG_DBG("return %d", result);
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Certificate
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateHandle(jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	struct cert_ctx ctx;
	ctx.target_alias = (const char *)alias;
	ctx.result = NULL;

	if ((iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                      cert_bag_cb, &ctx) != LLCRYPTO_SUCCESS) || (NULL == ctx.result)) {
		goto end;
	}

	VEEPORT_LOGGER_LOG_DBG("handle=%p size=%d", (void *)ctx.result, ctx.result->der_length);
	result = (jint)ctx.result;

end:
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Certificate Chain
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainHandle(jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	struct chain_ctx ctx;
	(void)memset(&ctx, 0, sizeof(ctx));
	ctx.target_alias = (const char *)alias;

	/* Collect all certs from the PKCS#12. */
	if ((iterate_p12_bags(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                      chain_collect_cb, &ctx) != LLCRYPTO_SUCCESS) || (0 == ctx.total)) {
		goto end;
	}

	struct llcrypto_eks_chain *chain = llcrypto_eks_build_chain(
		(const char *)alias, ctx.all_certs, ctx.aliases, ctx.total);

	for (int i = 0; i < ctx.total; i++) {
		X509_free(ctx.all_certs[i]);
	}

	if (NULL != chain) {
		VEEPORT_LOGGER_LOG_DBG("chain handle=%p count=%d", (void *)chain, chain->cert_count);
		result = (jint)chain;
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
	P12_ENTRY_TRUSTED_CERT   /**< standalone certificate, no key. */
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
	if (NULL == e) {
		return;
	}
	EVP_PKEY_free(e->pkey);
	e->pkey = NULL;
	if (NULL != e->chain) {
		sk_X509_pop_free(e->chain, X509_free);
		e->chain = NULL;
	}
	if (NULL != e->secret_bytes) {
		OPENSSL_cleanse(e->secret_bytes, (size_t)e->secret_len);
		LLCRYPTO_free(e->secret_bytes);
		e->secret_bytes = NULL;
	}
	X509_free(e->trusted_cert);
	e->trusted_cert = NULL;
}

static void p12_entries_free(struct p12_entry *entries, int n) {
	if (NULL == entries) {
		return;
	}
	for (int i = 0; i < n; i++) {
		p12_entry_clear(&entries[i]);
	}
	LLCRYPTO_free(entries);
}

/**
 * Set an entry's alias. Returns LLCRYPTO_ERROR without touching @p e if @p alias does not fit:
 * truncating would commit the entry under a name no later lookup can match, and could overwrite
 * an unrelated entry sharing the truncated prefix.
 */
static int p12_entry_set_alias(struct p12_entry *e, const char *alias) {
	int result = LLCRYPTO_ERROR;

	if (strlen(alias) < sizeof(e->alias)) {
		(void)strcpy(e->alias, alias);
		result = LLCRYPTO_SUCCESS;
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
		if (0 == strcasecmp(entries[src].alias, alias)) {
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
	unsigned char localkeyid[LLCRYPTO_EKS_LOCAL_KEY_ID_MAX_LEN];
	int localkeyid_len;
	EVP_PKEY *pkey;             /**< asymmetric key (NULL for secret). */
	uint8_t *secret_bytes;      /**< raw AES bytes (NULL for asymmetric). */
	int secret_len;
};

struct loaded_certbag {
	char alias[LLCRYPTO_EKS_MAX_ALIAS_LEN];
	unsigned char localkeyid[LLCRYPTO_EKS_LOCAL_KEY_ID_MAX_LEN];
	int localkeyid_len;
	int trusted;                /**< has trustedKeyUsage. */
	X509 *cert;
};

struct load_ctx {
	struct loaded_keybag keys[LLCRYPTO_EKS_MAX_OBJECTS];
	int key_count;
	struct loaded_certbag certs[LLCRYPTO_EKS_MAX_OBJECTS * LLCRYPTO_EKS_MAX_CERTS_PER_ENTRY];
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
	if (NULL == attrs) {
		goto end;
	}
	int idx = X509at_get_attr_by_NID(attrs, NID_localKeyID, -1);
	if (idx < 0) {
		goto end;
	}
	X509_ATTRIBUTE *attr = X509at_get_attr(attrs, idx);
	const ASN1_TYPE *val = X509_ATTRIBUTE_get0_type(attr, 0);
	if ((NULL == val) || (V_ASN1_OCTET_STRING != val->type)) {
		goto end;
	}
	const ASN1_OCTET_STRING *os = val->value.octet_string;
	int len = ASN1_STRING_length(os);
	if ((len <= 0) || ((size_t)len > buf_len)) {
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
	if (NULL == attrs) {
		goto end;
	}
	ASN1_OBJECT *trusted = OBJ_txt2obj(LLCRYPTO_EKS_TRUSTED_KEY_USAGE_OID, 1);
	if (NULL == trusted) {
		goto end;
	}
	for (int i = 0; i < X509at_get_attr_count(attrs); i++) {
		X509_ATTRIBUTE *attr = X509at_get_attr(attrs, i);
		if (0 == OBJ_cmp(X509_ATTRIBUTE_get0_object(attr), trusted)) {
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
	if (0 == PKCS8_pkey_get0(&alg_obj, &pk, &pk_len, NULL, p8)) {
		goto end;
	}
	if ((NULL == alg_obj) || (NULL == pk) || (pk_len <= 0) || !is_aes_oid(alg_obj)) {
		goto end;
	}
	const unsigned char *key_data = pk;
	int key_len = pk_len;
	const unsigned char *tmp = pk;
	ASN1_OCTET_STRING *octet = d2i_ASN1_OCTET_STRING(NULL, &tmp, pk_len);
	if (NULL != octet) {
		key_data = ASN1_STRING_get0_data(octet);
		key_len = ASN1_STRING_length(octet);
	}
	out = (uint8_t *)LLCRYPTO_calloc(1, (size_t)key_len);
	if (NULL != out) {
		(void)memcpy(out, key_data, (size_t)key_len);
		*out_len = key_len;
	}
	if (NULL != octet) {
		ASN1_OCTET_STRING_free(octet);
	}

end:
	return out;
}

static int load_bag_cb(PKCS12_SAFEBAG *bag, const char *password, int pw_len, void *ctx) {
	struct load_ctx *c = (struct load_ctx *)ctx;
	int bag_nid = PKCS12_SAFEBAG_get_nid(bag);

	if ((NID_pkcs8ShroudedKeyBag == bag_nid) || (NID_keyBag == bag_nid)) {
		if (c->key_count >= LLCRYPTO_EKS_MAX_OBJECTS) {
			goto end;
		}
		PKCS8_PRIV_KEY_INFO *p8_decrypted = NULL;
		const PKCS8_PRIV_KEY_INFO *p8 = NULL;
		if (NID_pkcs8ShroudedKeyBag == bag_nid) {
			p8_decrypted = PKCS12_decrypt_skey(bag, password, pw_len);
			p8 = p8_decrypted;
		} else {
			p8 = PKCS12_SAFEBAG_get0_p8inf(bag);
		}
		if (NULL == p8) {
			ERR_clear_error();
			goto end;
		}

		struct loaded_keybag *k = &c->keys[c->key_count];
		(void)memset(k, 0, sizeof(*k));
		(void)extract_bag_alias(bag, k->alias, sizeof(k->alias));
		(void)extract_local_key_id(bag, k->localkeyid, sizeof(k->localkeyid), &k->localkeyid_len);

		int slen = 0;
		uint8_t *sbytes = extract_secret_bytes_from_p8(p8, &slen);
		if (NULL != sbytes) {
			k->secret_bytes = sbytes;
			k->secret_len = slen;
		} else {
			EVP_PKEY *pkey = EVP_PKCS82PKEY(p8);
			if (NULL == pkey) {
				ERR_clear_error();
				PKCS8_PRIV_KEY_INFO_free(p8_decrypted);
				goto end;
			}
			k->pkey = pkey;
		}
		c->key_count++;
		PKCS8_PRIV_KEY_INFO_free(p8_decrypted);
	} else if (NID_secretBag == bag_nid) {
		if (c->key_count >= LLCRYPTO_EKS_MAX_OBJECTS) {
			goto end;
		}
		const ASN1_TYPE *bag_value = PKCS12_SAFEBAG_get0_bag_obj(bag);
		if (NULL == bag_value) {
			goto end;
		}
		if ((V_ASN1_OCTET_STRING != bag_value->type) && (V_ASN1_SEQUENCE != bag_value->type)) {
			goto end;
		}
		const ASN1_STRING *os = (V_ASN1_OCTET_STRING == bag_value->type)
		    ? bag_value->value.octet_string : bag_value->value.asn1_string;
		if (NULL == os) {
			goto end;
		}
		const unsigned char *enc_data = ASN1_STRING_get0_data(os);
		int enc_len = ASN1_STRING_length(os);
		const unsigned char *tmp = enc_data;
		X509_SIG *epki = d2i_X509_SIG(NULL, &tmp, enc_len);
		if (NULL == epki) {
			ERR_clear_error();
			goto end;
		}
		PKCS8_PRIV_KEY_INFO *p8 = PKCS8_decrypt(epki, password, pw_len);
		X509_SIG_free(epki);
		if (NULL == p8) {
			ERR_clear_error();
			goto end;
		}
		int slen = 0;
		uint8_t *sbytes = extract_secret_bytes_from_p8(p8, &slen);
		PKCS8_PRIV_KEY_INFO_free(p8);
		if (NULL == sbytes) {
			goto end;
		}
		struct loaded_keybag *k = &c->keys[c->key_count];
		(void)memset(k, 0, sizeof(*k));
		(void)extract_bag_alias(bag, k->alias, sizeof(k->alias));
		(void)extract_local_key_id(bag, k->localkeyid, sizeof(k->localkeyid), &k->localkeyid_len);
		k->secret_bytes = sbytes;
		k->secret_len = slen;
		c->key_count++;
	} else if (NID_certBag == bag_nid) {
		size_t max_certs = sizeof(c->certs) / sizeof(c->certs[0]);
		if ((size_t)c->cert_count >= max_certs) {
			goto end;
		}
		X509 *cert = PKCS12_SAFEBAG_get1_cert(bag);
		if (NULL == cert) {
			goto end;
		}
		struct loaded_certbag *cb = &c->certs[c->cert_count];
		(void)memset(cb, 0, sizeof(*cb));
		extract_cert_alias(bag, cert, cb->alias, sizeof(cb->alias));
		(void)extract_local_key_id(bag, cb->localkeyid, sizeof(cb->localkeyid), &cb->localkeyid_len);
		cb->trusted = has_trusted_key_usage_attr(bag);
		cb->cert = cert;
		c->cert_count++;
	} else {
		/* Any other bag type is not collected. */
	}

end:
	return 0;
}

/* The certificate that issued @p cert, or NULL when @p cert is self-signed or when its issuer is
 * absent from @p certs. Both answers end the chain walk, so they share one return value. */
static X509 *find_issuer_in_bag(const X509 *cert, struct loaded_certbag *certs, int cert_count) {
	X509 *issuer = NULL;
	X509_NAME *issuer_name = X509_get_issuer_name(cert);
	X509_NAME *subject_name = X509_get_subject_name(cert);

	if ((NULL != issuer_name) && (NULL != subject_name) &&
	    (0 != X509_NAME_cmp(issuer_name, subject_name))) {
		for (int i = 0; i < cert_count; i++) {
			X509 *cand = certs[i].cert;
			if ((NULL != cand) && (cand != cert) &&
			    (0 == X509_NAME_cmp(X509_get_subject_name(cand), issuer_name))) {
				issuer = cand;
				break;
			}
		}
	}
	return issuer;
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
	if (NULL == chain) {
		goto end;
	}
	if (sk_X509_push(chain, leaf) <= 0) {
		sk_X509_free(chain);
		goto end;
	}
	/* up_ref fails only on a reference count overflow, which this path cannot reach. */
	(void)X509_up_ref(leaf);

	/* Walk up while there is an issuer to add. A self-signed root and an issuer that is absent
	 * from the bag both surface as a NULL parent, which ends the walk with whatever the chain
	 * holds so far. */
	X509 *parent = find_issuer_in_bag(leaf, certs, cert_count);
	while (NULL != parent) {
		if (sk_X509_push(chain, parent) <= 0) {
			break;
		}
		/* up_ref fails only on a reference count overflow, which this path cannot reach. */
		(void)X509_up_ref(parent);
		parent = find_issuer_in_bag(parent, certs, cert_count);
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
	if (0 != access(path, F_OK)) {
		struct p12_entry *empty = (struct p12_entry *)LLCRYPTO_calloc(1, sizeof(*empty));
		*out_entries = empty;
		return (NULL != empty) ? LLCRYPTO_SUCCESS : LLCRYPTO_ERROR;
	}

	if (LLCRYPTO_SUCCESS != iterate_p12_bags(path, password, pw_len, load_bag_cb, &ctx)) {
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
	if (0 == max_entries) {
		max_entries = 1; /* avoid 0-sized alloc */
	}
	struct p12_entry *entries = (struct p12_entry *)LLCRYPTO_calloc((size_t)max_entries, sizeof(*entries));
	if (NULL == entries) {
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
		/* k->alias is itself a LLCRYPTO_EKS_MAX_ALIAS_LEN buffer, so it always fits. */
		(void)p12_entry_set_alias(e, k->alias);
		if (NULL != k->pkey) {
			e->type = P12_ENTRY_PRIVATE_KEY;
			e->pkey = k->pkey;
			k->pkey = NULL;
			/* Find leaf cert matching this key. */
			X509 *leaf = NULL;
			int leaf_idx = -1;
			for (int j = 0; j < ctx.cert_count; j++) {
				struct loaded_certbag *cb = &ctx.certs[j];
				if (NULL == cb->cert) {
					continue;
				}
				bool matches = false;
				if ((k->localkeyid_len > 0) && (cb->localkeyid_len == k->localkeyid_len) &&
				    (memcmp(k->localkeyid, cb->localkeyid, (size_t)k->localkeyid_len) == 0)) {
					matches = true;
				} else if ((0 == cb->localkeyid_len) && (cb->alias[0] != '\0') &&
				           (0 == strcasecmp(cb->alias, k->alias)) && !cb->trusted) {
					matches = true;
				} else {
					/* Neither the localKeyID nor the alias matches this key. */
				}
				if (matches) {
					leaf = cb->cert;
					leaf_idx = j;
					break;
				}
			}
			if (NULL != leaf) {
				e->chain = build_chain_for_leaf(leaf, ctx.certs, ctx.cert_count);
				/* Mark all chain certs as consumed (clear from the cert table)
				 * so they don't end up as separate trusted entries. */
				if (NULL != e->chain) {
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
		if ((NULL == cb->cert) || (cb->alias[0] == '\0')) {
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
		/* cb->alias is itself a LLCRYPTO_EKS_MAX_ALIAS_LEN buffer, so it always fits. */
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
	if (NULL == p8) {
		goto end;
	}
	ASN1_OBJECT *aes_oid = OBJ_txt2obj(LLCRYPTO_EKS_AES_BASE_OID, 1);
	if (NULL == aes_oid) {
		PKCS8_PRIV_KEY_INFO_free(p8);
		goto end;
	}
	ASN1_OCTET_STRING *octet = ASN1_OCTET_STRING_new();
	if ((NULL == octet) || !ASN1_OCTET_STRING_set(octet, bytes, len)) {
		ASN1_OCTET_STRING_free(octet);
		ASN1_OBJECT_free(aes_oid);
		PKCS8_PRIV_KEY_INFO_free(p8);
		goto end;
	}
	int wrapped_len = i2d_ASN1_OCTET_STRING(octet, NULL);
	unsigned char *wrapped = (unsigned char *)OPENSSL_malloc((size_t)wrapped_len);
	if (NULL == wrapped) {
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
                                    unsigned char *local_id, int local_id_len) {
	unsigned char salt[PKCS12_SALT_LEN];
	if (1 != RAND_bytes(salt, sizeof(salt))) {
		return NULL;
	}
	PKCS12_SAFEBAG *bag = PKCS12_SAFEBAG_create_pkcs8_encrypt(
		NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
		password, pw_len,
		salt, sizeof(salt),
		LLCRYPTO_EKS_PBE_ITER, p8);
	if (NULL == bag) {
		return NULL;
	}

	if ((NULL != alias) && (1 != PKCS12_add_friendlyname(bag, alias, -1))) {
		PKCS12_SAFEBAG_free(bag);
		return NULL;
	}
	if ((local_id_len > 0) &&
	    (PKCS12_add_localkeyid(bag, local_id, local_id_len) != 1)) {
		PKCS12_SAFEBAG_free(bag);
		return NULL;
	}

	if (NULL == *key_bags) {
		*key_bags = sk_PKCS12_SAFEBAG_new_null();
		if (NULL == *key_bags) {
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
                                     unsigned char *local_id, int local_id_len,
                                     int trusted) {
	PKCS12_SAFEBAG *bag = PKCS12_add_cert(cert_bags, cert);
	if (NULL == bag) {
		return NULL;
	}
	if ((NULL != alias) && (alias[0] != '\0') &&
	    (PKCS12_add_friendlyname(bag, alias, -1) != 1)) {
		return NULL;
	}

	unsigned char trusted_id[LLCRYPTO_EKS_LOCAL_KEY_ID_LEN];
	unsigned char *key_id = local_id;
	int key_id_len = local_id_len;
	if (trusted && (0 == local_id_len)) {
		if (1 != RAND_bytes(trusted_id, sizeof(trusted_id))) {
			return NULL;
		}
		key_id = trusted_id;
		key_id_len = (int)sizeof(trusted_id);
	}
	if ((key_id_len > 0) &&
	    (PKCS12_add_localkeyid(bag, key_id, key_id_len) != 1)) {
		return NULL;
	}
	return bag;
}

/**
 * Push the safebags of one keystore entry onto @p key_bags and @p cert_bags. A private key also
 * carries its chain: the leaf gets the friendlyName and the localKeyID, the rest are pure chain
 * links. Returns LLCRYPTO_SUCCESS, or LLCRYPTO_ERROR with the bag stacks left to the caller.
 */
static int push_entry_bags(STACK_OF(PKCS12_SAFEBAG) **key_bags, STACK_OF(PKCS12_SAFEBAG) **cert_bags,
                           const char *password, int pw_len, const struct p12_entry *e) {
	if (P12_ENTRY_PRIVATE_KEY == e->type) {
		unsigned char local_id[LLCRYPTO_EKS_LOCAL_KEY_ID_LEN];
		if (1 != RAND_bytes(local_id, sizeof(local_id))) {
			return LLCRYPTO_ERROR;
		}
		PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(e->pkey);
		if (NULL == p8) {
			return LLCRYPTO_ERROR;
		}
		PKCS12_SAFEBAG *kb = push_key_bag(key_bags, p8, password, pw_len,
		                                  e->alias, local_id, sizeof(local_id));
		PKCS8_PRIV_KEY_INFO_free(p8);
		if (NULL == kb) {
			return LLCRYPTO_ERROR;
		}
		if (NULL != e->chain) {
			int n_chain = sk_X509_num(e->chain);
			for (int j = 0; j < n_chain; j++) {
				X509 *cc = sk_X509_value(e->chain, j);
				const char *cert_alias = (0 == j) ? e->alias : NULL;
				unsigned char *cert_local = (0 == j) ? local_id : NULL;
				int cert_local_len = (0 == j) ? (int)sizeof(local_id) : 0;
				if (NULL == push_cert_bag(cert_bags, cc, cert_alias, cert_local, cert_local_len, 0)) {
					return LLCRYPTO_ERROR;
				}
			}
		}
	} else if (P12_ENTRY_SECRET_KEY == e->type) {
		PKCS8_PRIV_KEY_INFO *p8 = aes_secret_to_p8(e->secret_bytes, e->secret_len);
		if (NULL == p8) {
			return LLCRYPTO_ERROR;
		}
		PKCS12_SAFEBAG *kb = push_key_bag(key_bags, p8, password, pw_len, e->alias, NULL, 0);
		PKCS8_PRIV_KEY_INFO_free(p8);
		if (NULL == kb) {
			return LLCRYPTO_ERROR;
		}
	} else { /* P12_ENTRY_TRUSTED_CERT */
		if (NULL == push_cert_bag(cert_bags, e->trusted_cert, e->alias, NULL, 0, 1)) {
			return LLCRYPTO_ERROR;
		}
	}
	return LLCRYPTO_SUCCESS;
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
	if ((tlen < 0) || ((size_t)tlen >= sizeof(tmp_path))) {
		goto end;
	}

	for (int i = 0; i < count; i++) {
		if (LLCRYPTO_SUCCESS != push_entry_bags(&key_bags, &cert_bags, password, pw_len, &entries[i])) {
			goto end;
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
	if ((NULL != cert_bags) && (sk_PKCS12_SAFEBAG_num(cert_bags) > 0)) {
		if (1 != PKCS12_add_safe(&safes, cert_bags, -1, 0, NULL)) {
			goto end;
		}
	}
	if ((NULL != key_bags) && (sk_PKCS12_SAFEBAG_num(key_bags) > 0)) {
		if (1 != PKCS12_add_safe(&safes, key_bags, -1, 0, NULL)) {
			goto end;
		}
	}

	p12 = PKCS12_add_safes(safes, 0);
	if (NULL == p12) {
		goto end;
	}
	/* PKCS12_add_safes consumed the safes stack. */
	safes = NULL;

	if (1 != PKCS12_set_mac(p12, password, pw_len, NULL, 0, LLCRYPTO_EKS_PBE_ITER, NULL)) {
		goto end;
	}

	out = BIO_new_file(tmp_path, "wb");
	if (NULL == out) {
		goto end;
	}
	if (i2d_PKCS12_bio(out, p12) <= 0) {
		/* The BIO is released anyway, so a failure leaves nothing to act on. */
		(void)BIO_free(out);
		out = NULL;
		(void)unlink(tmp_path);
		goto end;
	}
	/* The BIO is released anyway, so a failure leaves nothing to act on. */
	(void)BIO_free(out);
	out = NULL;

	if (0 != rename(tmp_path, path)) {
		(void)unlink(tmp_path);
		goto end;
	}

	result = LLCRYPTO_SUCCESS;

end:
	/* PKCS12_add_safe took ownership of the bag stacks on success. On
	 * failure they may still hold bags we created, so free them. */
	if ((NULL != cert_bags) && (sk_PKCS12_SAFEBAG_num(cert_bags) > 0)) {
		sk_PKCS12_SAFEBAG_pop_free(cert_bags, PKCS12_SAFEBAG_free);
	} else {
		sk_PKCS12_SAFEBAG_free(cert_bags);
	}
	if ((NULL != key_bags) && (sk_PKCS12_SAFEBAG_num(key_bags) > 0)) {
		sk_PKCS12_SAFEBAG_pop_free(key_bags, PKCS12_SAFEBAG_free);
	} else {
		sk_PKCS12_SAFEBAG_free(key_bags);
	}
	sk_PKCS7_pop_free(safes, PKCS7_free);
	PKCS12_free(p12);
	/* The BIO is released anyway, so a failure leaves nothing to act on. */
	(void)BIO_free(out);
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
	if (NULL != p8inf) {
		EVP_PKEY *pkey = EVP_PKCS82PKEY(p8inf);
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		if (NULL != pkey) {
			result = pkey;
			goto end;
		}
	}
	ERR_clear_error();

	p = data;
	X509_SIG *sig = d2i_X509_SIG(NULL, &p, (long)len);
	if (NULL == sig) {
		ERR_clear_error();
		goto end;
	}
	p8inf = PKCS8_decrypt(sig, g_keystore.password, g_keystore.pw_len);
	X509_SIG_free(sig);
	if (NULL == p8inf) {
		ERR_clear_error();
		goto end;
	}
	result = EVP_PKCS82PKEY(p8inf);
	PKCS8_PRIV_KEY_INFO_free(p8inf);

end:
	return result;
}

// -----------------------------------------------------------------------------
// LLAPI entry-type query entry point
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getEntryType(jbyte *alias) {
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	/* A key entry holds a private/secret key (and possibly a chain); a cert
	 * entry holds only a certificate. Probe the key path first — getKeyId
	 * returns LLCRYPTO_ERROR for cert-only aliases. */
	jint key_id = LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyId(alias, NULL);
	if (LLCRYPTO_ERROR != key_id) {
		struct llcrypto_key *key = (struct llcrypto_key *)key_id;
		llcrypto_key_free(key);
		result = (jint)LLCRYPTO_ENTRY_TYPE_KEY;
	} else {
		jint cert_handle = LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateHandle(alias);
		if (LLCRYPTO_ERROR != cert_handle) {
			struct llcrypto_eks_cert *c = (struct llcrypto_eks_cert *)cert_handle;
			llcrypto_eks_cert_free(c);
			result = (jint)LLCRYPTO_ENTRY_TYPE_CERTIFICATE;
		}
	}

end:
	return result;
}

// -----------------------------------------------------------------------------
// LLAPI write entry points
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_deleteEntry(jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;
	struct p12_entry *entries = NULL;
	int count = 0;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	if (p12_load_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len, &entries,
	                     &count) != LLCRYPTO_SUCCESS) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot read keystore");
		goto end;
	}

	int new_count = p12_entries_remove(entries, count, (const char *)alias);
	if (new_count == count) {
		/* Java semantics: deleting a non-existent alias is a silent no-op. Saving anyway would
		 * rewrite the file and draw a fresh PBE salt and localKeyID for every unrelated entry. */
		result = LLCRYPTO_SUCCESS;
		goto end;
	}

	if (p12_save_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     entries, new_count) != LLCRYPTO_SUCCESS) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot write keystore");
		goto end;
	}
	result = LLCRYPTO_SUCCESS;

end:
	p12_entries_free(entries, count);
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_setCertificateEntry(jbyte *alias, jbyte *certificate) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;
	struct p12_entry *entries = NULL;
	int count = 0;
	X509 *cert = NULL;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	jint cert_len = sni_array_get_length((void *)certificate);
	if (cert_len <= 0) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Empty certificate");
		goto end;
	}
	const unsigned char *p = (const unsigned char *)certificate;
	cert = d2i_X509(NULL, &p, (long)cert_len);
	if (NULL == cert) {
		ERR_clear_error();
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot parse X.509 certificate");
		goto end;
	}

	if (p12_load_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len, &entries,
	                     &count) != LLCRYPTO_SUCCESS) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot read keystore");
		goto end;
	}

	count = p12_entries_remove(entries, count, (const char *)alias);

	/* Append the new trusted-cert entry. Reallocate to grow by one if needed. */
	struct p12_entry *grown = (struct p12_entry *)LLCRYPTO_calloc((size_t)count + 1U, sizeof(*grown));
	if (NULL == grown) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Out of memory");
		goto end;
	}
	if (count > 0) {
		(void)memcpy(grown, entries, (size_t)count * sizeof(*grown));
		(void)memset(entries, 0, (size_t)count * sizeof(*entries));
	}
	LLCRYPTO_free(entries);
	entries = grown;
	/* The only alias on this path that comes straight from the caller, so the only one that can
	 * fail to fit. The slot stays zero-initialized on rejection, so freeing `count` entries below
	 * is still correct. */
	if (LLCRYPTO_SUCCESS != p12_entry_set_alias(&entries[count], (const char *)alias)) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Alias too long for the keystore");
		goto end;
	}
	entries[count].type = P12_ENTRY_TRUSTED_CERT;
	entries[count].trusted_cert = cert;
	cert = NULL; /* ownership moved into entry */
	count++;

	if (p12_save_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     entries, count) != LLCRYPTO_SUCCESS) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot write keystore");
		goto end;
	}
	result = LLCRYPTO_SUCCESS;

end:
	X509_free(cert);
	p12_entries_free(entries, count);
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_openKeyEntryWithData(jbyte *alias, jbyte *key, jint chain_len) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s' chain_len=%d", (const char *)alias, (int)chain_len);
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	jint key_len = sni_array_get_length((void *)key);
	if (key_len <= 0) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Empty key data");
		goto end;
	}

	struct llcrypto_eks_key_import *h = llcrypto_eks_key_import_new((const char *)alias, (int)chain_len);
	if (NULL == h) {
		/* llcrypto_eks_key_import_new has already thrown. */
		goto end;
	}
	h->key_evp = p12_parse_protected_key((const uint8_t *)key, key_len);
	if (NULL == h->key_evp) {
		llcrypto_eks_key_import_free(h);
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Cannot parse key data (PKCS#8 plain or PBES2-encrypted)");
		goto end;
	}
	result = (jint)h;

end:
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_openKeyEntryWithNativeId(jbyte *alias, jint key_id, jchar *password,
                                                              jint chain_len) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s' key_id=%d chain_len=%d", (const char *)alias, key_id, chain_len);
	LLCRYPTO_UNUSED_PARAM(password); /* keystore password authenticates writes */
	jint result = LLCRYPTO_ERROR;

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}
	struct llcrypto_eks_key_import *h = llcrypto_eks_key_import_new((const char *)alias, (int)chain_len);
	if (NULL == h) {
		/* llcrypto_eks_key_import_new has already thrown. */
		goto end;
	}
	h->key_native_id = key_id;
	result = (jint)h;

end:
	return result;
}

/* insertCertificateInChain is implemented in LLCRYPTO_EXTERNAL_KEYSTORE_common.c. */

/**
 * Decode chain certificate @p entry and push it onto @p chain, which takes ownership. Throws and
 * returns LLCRYPTO_ERROR when the DER is missing or will not parse. A failed push returns the error
 * without throwing, matching what the caller reported before.
 */
static int attach_chain_cert(STACK_OF(X509) *chain, const struct llcrypto_eks_chain_cert *entry) {
	int result = LLCRYPTO_ERROR;

	if (NULL == entry->der) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Missing chain cert");
	} else {
		const unsigned char *p = entry->der;
		X509 *cc = d2i_X509(NULL, &p, entry->len);
		if (NULL == cc) {
			ERR_clear_error();
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot parse chain cert");
		} else if (sk_X509_push(chain, cc) <= 0) {
			X509_free(cc);
		} else {
			result = LLCRYPTO_SUCCESS;
		}
	}
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_closeKeyEntry(jint handle) {
	VEEPORT_LOGGER_LOG_DBG("handle=%d", handle);
	jint result = LLCRYPTO_ERROR;
	struct p12_entry *entries = NULL;
	int count = 0;
	struct llcrypto_eks_key_import *h = (struct llcrypto_eks_key_import *)handle;
	if (NULL == h) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "NULL key entry handle");
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
		VEEPORT_LOGGER_LOG_ERR("aborting commit: chain_count=%d chain_len=%d", h->chain_count, h->chain_len);
		result = LLCRYPTO_SUCCESS;
		goto end;
	}

	if (!g_keystore.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	if (p12_load_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len, &entries,
	                     &count) != LLCRYPTO_SUCCESS) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot read keystore");
		goto end;
	}

	count = p12_entries_remove(entries, count, h->alias);

	struct p12_entry *grown = (struct p12_entry *)LLCRYPTO_calloc((size_t)count + 1U, sizeof(*grown));
	if (NULL == grown) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Out of memory");
		goto end;
	}
	if (count > 0) {
		(void)memcpy(grown, entries, (size_t)count * sizeof(*grown));
		(void)memset(entries, 0, (size_t)count * sizeof(*entries));
	}
	LLCRYPTO_free(entries);
	entries = grown;

	struct p12_entry *new_entry = &entries[count];
	/* llcrypto_eks_key_import_new already rejected an over-long alias, so this always fits. */
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
	if (NULL != h->key_evp) {
		new_entry->type = P12_ENTRY_PRIVATE_KEY;
		new_entry->pkey = h->key_evp;
		h->key_evp = NULL;
	} else if (0 != h->key_native_id) {
		struct llcrypto_key *src = (struct llcrypto_key *)h->key_native_id;
		if (LLCRYPTO_KEY_TYPE_EVP_PKEY == src->type) {
			new_entry->type = P12_ENTRY_PRIVATE_KEY;
			/* up_ref fails only on a reference count overflow, which this path cannot reach. */
			(void)EVP_PKEY_up_ref(src->evp_key);
			new_entry->pkey = src->evp_key;
		} else if (LLCRYPTO_KEY_TYPE_SECRET_KEY == src->type) {
			new_entry->type = P12_ENTRY_SECRET_KEY;
			new_entry->secret_bytes = (uint8_t *)LLCRYPTO_calloc(1, src->secret_key.length);
			if (NULL == new_entry->secret_bytes) {
				VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Out of memory");
				goto end;
			}
			(void)memcpy(new_entry->secret_bytes, src->secret_key.buffer, src->secret_key.length);
			new_entry->secret_len = (int)src->secret_key.length;
			const char *alg = (NULL != src->secret_key.algorithm) ? src->secret_key.algorithm : "AES";
			size_t alg_len = strlen(alg);
			if (alg_len >= sizeof(new_entry->secret_algorithm)) {
				alg_len = sizeof(new_entry->secret_algorithm) - 1U;
			}
			(void)memcpy(new_entry->secret_algorithm, alg, alg_len);
			new_entry->secret_algorithm[alg_len] = '\0';
		} else {
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Unsupported key type");
			goto end;
		}
	} else {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "No key source for entry");
		goto end;
	}

	/* Attach the chain (only meaningful for asymmetric keys). For secrets we
	 * silently ignore the chain — the LLAPI permits it, but Java's KeyStore
	 * doesn't allow chains on secret keys, so chain_count is always 0. */
	if ((P12_ENTRY_PRIVATE_KEY == new_entry->type) && (h->chain_count > 0)) {
		new_entry->chain = sk_X509_new_null();
		if (NULL == new_entry->chain) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Out of memory");
			goto end;
		}
		for (int i = 0; i < h->chain_count; i++) {
			if (LLCRYPTO_SUCCESS != attach_chain_cert(new_entry->chain, &h->chain_certs[i])) {
				goto end;
			}
		}
	}

	if (p12_save_entries(g_keystore.path, g_keystore.password, g_keystore.pw_len,
	                     entries, count) != LLCRYPTO_SUCCESS) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot write keystore");
		goto end;
	}
	result = LLCRYPTO_SUCCESS;

end:
	p12_entries_free(entries, count);
	llcrypto_eks_key_import_free(h);
	return result;
}
