/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>
#include <LLCRYPTO_KEY_FACTORY_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_key.h"
#include "LLCRYPTO_utils.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

#define MICROEJ_LLCRYPTO_KEY_FACTORY_SUCCESS 1
#define MICROEJ_LLCRYPTO_KEY_FACTORY_ERROR   0

int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_private_key_data(int32_t algorithm_id, uint8_t *format_name, uint8_t *encoded_key,
                                                       int32_t encoded_key_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	int32_t return_code = MICROEJ_LLCRYPTO_KEY_FACTORY_ERROR;
	struct llcrypto_key *key = NULL;
	int32_t key_rc = LLCRYPTO_ERROR;

	if (0 != strcmp((const char *)format_name, "PKCS#8")) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Unsupported private key format");
		goto end;
	}

	if (!sni_array_contains_range(encoded_key, 0, encoded_key_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		goto end;
	}

	key_rc = llcrypto_key_from_pkcs8_private_key(encoded_key, (size_t)encoded_key_length, &key);
	if (LLCRYPTO_ERROR_OOM == key_rc) {
		/* Returned, not thrown, so that the Crypto library retries after a GC. */
		return_code = LLCRYPTO_ERROR_OOM;
	} else if (LLCRYPTO_SUCCESS != key_rc) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_KEY_FACTORY_INVALID_KEY_MATERIAL, "%s",
		                                               ERR_error_string(ERR_get_error(), NULL));
	} else {
		return_code = (int32_t)key;
	}

end:
	return return_code;
}

int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_public_key_data(int32_t algorithm_id, uint8_t *format_name, uint8_t *encoded_key,
                                                      int32_t encoded_key_length) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	int32_t return_code = MICROEJ_LLCRYPTO_KEY_FACTORY_ERROR;
	struct llcrypto_key *key = NULL;
	int32_t key_rc = LLCRYPTO_ERROR;

	if (0 != strcmp((const char *)format_name, "X.509")) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Unsupported public key format");
		goto end;
	}

	if (!sni_array_contains_range(encoded_key, 0, encoded_key_length)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Invalid buffer offset or length");
		goto end;
	}

	key_rc = llcrypto_key_from_x509_public_key(encoded_key, (size_t)encoded_key_length, &key);
	if (LLCRYPTO_ERROR_OOM == key_rc) {
		/* Returned, not thrown, so that the Crypto library retries after a GC. */
		return_code = LLCRYPTO_ERROR_OOM;
	} else if (LLCRYPTO_SUCCESS != key_rc) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_KEY_FACTORY_INVALID_KEY_MATERIAL, "%s",
		                                               ERR_error_string(ERR_get_error(), NULL));
	} else {
		return_code = (int32_t)key;
	}

end:
	return return_code;
}

int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_algorithm_description(uint8_t *algorithm_name) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(algorithm_name);
	/*
	 * algorithm_id is passed back to get_private/public_key_data but is not used there
	 * (d2i_AutoPrivateKey / d2i_PUBKEY auto-detect the key type from DER content).
	 * Return a non-error sentinel value so the Java layer does not see SNI_ERROR.
	 */
	return 0;
}

int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_private_key_close_id(int32_t algorithm_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	return (int32_t)llcrypto_key_free;
}

int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_public_key_close_id(int32_t algorithm_id) {
	VEEPORT_LOGGER_LOG_DBG("");
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	return (int32_t)llcrypto_key_free;
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
	if ((len > 0) && (0x00u == p[0])) {
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

int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_ec_public_key_from_raw(uint8_t *curveName, uint8_t *x, uint8_t *y) {
	VEEPORT_LOGGER_LOG_DBG("");

	int32_t return_code = LLCRYPTO_ERROR;
	/* The LLAPI reports a rejected argument -- an empty coordinate, an unknown curve, a coordinate
	 * that does not fit the curve -- and an allocation failure through the return code alone. Only
	 * the errors it does not already describe that way set a message here. */
	const char *error_message = NULL;
	uint8_t *point = NULL;
	EVP_PKEY *evp_key = NULL;
	struct llcrypto_key *key = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *pctx = NULL;

	int32_t x_len = sni_array_get_length(x);
	int32_t y_len = sni_array_get_length(y);
	if ((x_len <= 0) || (y_len <= 0)) {
		goto end;
	}

	int nid = llcrypto_curve_name_to_nid((const char *)curveName);
	if (NID_undef == nid) {
		goto end;
	}

	/* Determine the field size from the curve */
	EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
	if (NULL == group) {
		error_message = "Cannot build the EC group of a supported curve";
		goto end;
	}
	size_t field_size = ((size_t)EC_GROUP_get_degree(group) + 7U) / 8U;
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
	    !llcrypto_bn_to_fixed(y, y_len, &point[1U + field_size], field_size)) {
		goto cleanup;
	}

	/* Use EVP_PKEY_fromdata with OSSL_PARAM */
	const char *group_name = OBJ_nid2sn(nid);
	if (NULL == group_name) {
		error_message = "Cannot name the EC group of a supported curve";
		goto cleanup;
	}

	bld = OSSL_PARAM_BLD_new();
	if (NULL == bld) {
		return_code = LLCRYPTO_ERROR_OOM;
		goto cleanup;
	}

	if ((1 != OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0)) ||
	    (1 != OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point, point_len))) {
		error_message = "Cannot describe the EC public key";
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
	if (1 == rc) {
		rc = EVP_PKEY_fromdata(pctx, &evp_key, EVP_PKEY_PUBLIC_KEY, params);
	}
	EVP_PKEY_CTX_free(pctx);
	pctx = NULL;
	OSSL_PARAM_free(params);
	params = NULL;

	if ((1 != rc) || (NULL == evp_key)) {
		EVP_PKEY_free(evp_key);
		evp_key = NULL;
		error_message = "Cannot build the EC public key";
		goto end;
	}

	key = llcrypto_key_from_evp_pkey(evp_key);
	if (NULL == key) {
		return_code = LLCRYPTO_ERROR_OOM;
		goto cleanup;
	}
	/* evp_key ownership transferred to key */
	evp_key = NULL;

	return_code = (int32_t)key;

cleanup:
	LLCRYPTO_free(point);
	EVP_PKEY_free(evp_key);
	OSSL_PARAM_BLD_free(bld);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(pctx);
end:
	if (NULL != error_message) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s", error_message);
	}
	return return_code;
}
