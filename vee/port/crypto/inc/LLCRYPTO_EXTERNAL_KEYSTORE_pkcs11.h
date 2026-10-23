/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

#ifndef LLCRYPTO_EXTERNAL_KEYSTORE_PKCS11_H
#define LLCRYPTO_EXTERNAL_KEYSTORE_PKCS11_H

/**
 * @file
 * @brief External KeyStore API provided by the PKCS#11 backend only.
 *
 * LLCRYPTO_EXTERNAL_KEYSTORE_common.h holds what both keystore backends share.
 * What only the PKCS#11 backend defines belongs here, so a backend-agnostic
 * module that needs it says so explicitly by including this header from inside
 * its own LLCRYPTO_KEYSTORE_PKCS11 guard.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Derive an ECDH shared secret on a PKCS#11 token via the direct C API.
 *
 * Calls C_DeriveKey with CKM_ECDH1_DERIVE and CKD_NULL on the token EC private
 * key labelled @p alias, passing @p peer_point in the raw uncompressed form,
 * and writes the raw shared secret to @p secret_out.
 *
 * @note This bypasses OpenSSL's pkcs11-provider, which sends the peer point as
 * a DER-wrapped OCTET STRING (PKCS#11 v3.0 optional form) that the OP-TEE
 * PKCS#11 TA mis-parses, so EVP_PKEY_derive() against a token-resident key
 * yields a wrong secret. The raw uncompressed form is the v2.40 mandatory
 * encoding every conformant token accepts, so the bypass is taken for every
 * PKCS#11 backend rather than narrowed to OP-TEE.
 *
 * @param alias            CKA_LABEL of the EC private key on the token. Must not be NULL.
 * @param peer_point       Peer EC public point, raw uncompressed (0x04 || X || Y).
 * @param peer_point_len   Length of @p peer_point in bytes.
 * @param secret_out       Output buffer for the raw shared secret.
 * @param secret_out_len   In: capacity of @p secret_out. Out: bytes written.
 * @return LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR on failure (an exception is thrown).
 */
int llcrypto_eks_ecdh_derive(char *alias, const uint8_t *peer_point, size_t peer_point_len,
                             uint8_t *secret_out, size_t *secret_out_len);

#ifdef __cplusplus
}
#endif

#endif /* LLCRYPTO_EXTERNAL_KEYSTORE_PKCS11_H */
