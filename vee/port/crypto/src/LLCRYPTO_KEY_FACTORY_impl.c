/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <sni.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include <LLCRYPTO_KEY_FACTORY_impl.h>
#include <LLCRYPTO_CONSTANTS.h>

#include "LLCRYPTO_configuration.h"
#include "LLCRYPTO_key.h"

#define MICROEJ_LLCRYPTO_KEY_FACTORY_SUCCESS 1
#define MICROEJ_LLCRYPTO_KEY_FACTORY_ERROR   0

// #define LLCRYPTO_KEY_FACTORY_DEBUG_TRACE

#ifdef LLCRYPTO_KEY_FACTORY_DEBUG_TRACE
#define LLCRYPTO_KEY_FACTORY_PRINTF(...) (void)printf(__VA_ARGS__)
#else
#define LLCRYPTO_KEY_FACTORY_PRINTF(...) ((void)0)
#endif

static const char *pkcs8_format = "PKCS#8";
static const char *x509_format = "X.509";

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_private_key_data(int32_t algorithm_id, uint8_t *format_name, uint8_t *encoded_key,
                                                       int32_t encoded_key_length) {
	LLCRYPTO_KEY_FACTORY_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	int32_t return_code = MICROEJ_LLCRYPTO_KEY_FACTORY_ERROR;
	struct llcrypto_key *key = NULL;

	if (0 != strcmp((const char *)format_name, pkcs8_format)) {
		(void)SNI_throwNativeException(SNI_ERROR, "Unsupported private key format");
		goto end;
	}

	key = llcrypto_key_from_pkcs8_private_key(encoded_key, (size_t)encoded_key_length);
	if (key == NULL) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto end;
	}

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	return_code = (int32_t)key;

end:
	return return_code;
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_public_key_data(int32_t algorithm_id, uint8_t *format_name, uint8_t *encoded_key,
                                                      int32_t encoded_key_length) {
	LLCRYPTO_KEY_FACTORY_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	int32_t return_code = MICROEJ_LLCRYPTO_KEY_FACTORY_ERROR;
	struct llcrypto_key *key = NULL;

	if (0 != strcmp((const char *)format_name, x509_format)) {
		(void)SNI_throwNativeException(SNI_ERROR, "Unsupported public key format");
		goto end;
	}

	key = llcrypto_key_from_x509_public_key(encoded_key, (size_t)encoded_key_length);
	if (key == NULL) {
		int err = ERR_get_error();
		(void)SNI_throwNativeException(err, ERR_error_string(err, NULL));
		goto end;
	}

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	return_code = (int32_t)key;

end:
	return return_code;
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_algorithm_description(uint8_t *algorithm_name) {
	LLCRYPTO_KEY_FACTORY_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(algorithm_name);
	/*
	 * algorithm_id is passed back to get_private/public_key_data but is not used there
	 * (d2i_AutoPrivateKey / d2i_PUBKEY auto-detect the key type from DER content).
	 * Return a non-error sentinel value so the Java layer does not see SNI_ERROR.
	 */
	return 0;
}

int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_private_key_close_id(int32_t algorithm_id) {
	LLCRYPTO_KEY_FACTORY_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)llcrypto_key_free;
}

int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_public_key_close_id(int32_t algorithm_id) {
	LLCRYPTO_KEY_FACTORY_PRINTF("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	// cppcheck-suppress misra-c2012-11.1 // Abstract data type for SNI usage
	return (int32_t)llcrypto_key_free;
}

/** Java curve name alias to OpenSSL NID mapping. */
struct curve_alias {
	const char *name;
	int nid;
};

/** Common Java curve name aliases that OBJ_txt2nid may not recognize. */
static const struct curve_alias curve_aliases[] = {
	{ "secp256r1", NID_X9_62_prime256v1 },
	{ "prime256v1", NID_X9_62_prime256v1 },
	{ "P-256", NID_X9_62_prime256v1 },
	{ "secp384r1", NID_secp384r1 },
	{ "P-384", NID_secp384r1 },
	{ "secp521r1", NID_secp521r1 },
	{ "P-521", NID_secp521r1 },
};

/**
 * Map a Java curve name (e.g. "secp256r1") to an OpenSSL NID.
 */
static int llcrypto_curve_name_to_nid(const char *name) {
	int nid = OBJ_txt2nid(name);
	if (nid == NID_undef) {
		for (size_t i = 0; i < (sizeof(curve_aliases) / sizeof(curve_aliases[0])); i++) {
			if (0 == strcmp(name, curve_aliases[i].name)) {
				nid = curve_aliases[i].nid;
				break;
			}
		}
	}
	return nid;
}

/**
 * Write a two's-complement big-endian integer (from Java BigInteger.toByteArray())
 * into a fixed-size unsigned big-endian buffer, stripping the leading sign byte
 * if present and left-padding with zeros.
 */
static int llcrypto_bn_to_fixed(const uint8_t *src, int32_t src_len, uint8_t *dst, size_t field_size) {
	const uint8_t *p = src;
	int32_t len = src_len;
	int result = 0;

	/* Strip leading 0x00 sign byte from two's-complement */
	if ((len > 0) && (p[0] == 0x00u)) {
		p++;
		len--;
	}

	if ((size_t)len > field_size) {
		/* coordinate too large for curve */
	} else {
		/* Left-pad with zeros */
		size_t pad = field_size - (size_t)len;
		(void)memset(dst, 0, pad);
		(void)memcpy(&dst[pad], p, (size_t)len);
		result = 1;
	}

	return result;
}

// cppcheck-suppress constParameterPointer // SNI type conflict
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_ec_public_key_from_raw(uint8_t *curveName, uint8_t *x, uint8_t *y) {
	LLCRYPTO_KEY_FACTORY_PRINTF("%s \n", __func__);

	int32_t return_code = LLCRYPTO_ERROR;
	uint8_t *point = NULL;
	EVP_PKEY *evp_key = NULL;
	struct llcrypto_key *key = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;

	int32_t x_len = SNI_getArrayLength(x);
	int32_t y_len = SNI_getArrayLength(y);
	if ((x_len <= 0) || (y_len <= 0)) {
		goto end;
	}

	int nid = llcrypto_curve_name_to_nid((const char *)curveName);
	if (nid == NID_undef) {
		goto end;
	}

	/* Determine the field size from the curve */
	EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
	if (NULL == group) {
		goto end;
	}
	size_t field_size = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
	EC_GROUP_free(group);

	/* Build uncompressed EC point: 0x04 || x_padded || y_padded */
	size_t point_len = 1u + (2u * field_size);
	point = LLCRYPTO_calloc(1, point_len);
	if (NULL == point) {
		return_code = LLCRYPTO_ERROR_OOM;
		goto end;
	}
	point[0] = 0x04u;
	if (!llcrypto_bn_to_fixed(x, x_len, &point[1], field_size) ||
	    !llcrypto_bn_to_fixed(y, y_len, &point[1 + field_size], field_size)) {
		goto cleanup;
	}

	/* Use EVP_PKEY_fromdata with OSSL_PARAM */
	const char *group_name = OBJ_nid2sn(nid);
	if (NULL == group_name) {
		goto cleanup;
	}

	bld = OSSL_PARAM_BLD_new();
	if (NULL == bld) {
		return_code = LLCRYPTO_ERROR_OOM;
		goto cleanup;
	}

	if ((OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0) != 1) ||
	    (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point, point_len) != 1)) {
		goto cleanup;
	}

	params = OSSL_PARAM_BLD_to_param(bld);
	OSSL_PARAM_BLD_free(bld);
	bld = NULL;
	LLCRYPTO_free(point);
	point = NULL;

	if (NULL == params) {
		return_code = LLCRYPTO_ERROR_OOM;
		goto end;
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (NULL == pctx) {
		return_code = LLCRYPTO_ERROR_OOM;
		goto cleanup;
	}

	int rc = EVP_PKEY_fromdata_init(pctx);
	if (rc == 1) {
		rc = EVP_PKEY_fromdata(pctx, &evp_key, EVP_PKEY_PUBLIC_KEY, params);
	}
	EVP_PKEY_CTX_free(pctx);
	pctx = NULL;
	OSSL_PARAM_free(params);
	params = NULL;

	if ((rc != 1) || (NULL == evp_key)) {
		EVP_PKEY_free(evp_key);
		evp_key = NULL;
		goto end;
	}

	key = llcrypto_key_from_evp_pkey(evp_key);
	if (NULL == key) {
		return_code = LLCRYPTO_ERROR_OOM;
		goto cleanup;
	}
	/* evp_key ownership transferred to key */
	evp_key = NULL;

	// cppcheck-suppress misra-c2012-11.4 // Abstract data type for SNI usage
	return_code = (int32_t)key;

cleanup:
	LLCRYPTO_free(point);
	EVP_PKEY_free(evp_key);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(pctx);
end:
	return return_code;
}
