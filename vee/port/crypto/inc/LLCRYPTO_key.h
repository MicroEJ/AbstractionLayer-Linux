/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#ifndef LLCRYPTO_KEY_H
#define LLCRYPTO_KEY_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief This enum defines the type of data that represents a key.
 */
enum llcrypto_key_type {
	LLCRYPTO_KEY_TYPE_EVP_PKEY,   /**< The key is backed by an OpenSSL EVP_PKEY (RSA or EC asymmetric key) */
	LLCRYPTO_KEY_TYPE_SECRET_KEY /**< RAW Secret Key (ex: AES, DESede) */
};

struct llcrypto_secret_key_data {
	unsigned char *buffer; /**< Buffer holding the Secret Key RAW data */
	size_t length;         /**< Length of the buffer, in bytes */
	char *algorithm;       /**< Java algorithm name, e.g. "AES" (heap-allocated, may be NULL) */
};

/**
 * @brief This structure represents a key that can be backed by multiple backends.
 *
 * The Java-side native_id / key_id holds a struct llcrypto_key* as an integer.
 * All lifecycle management is handled through SNI_registerResource / SNI_unregisterResource
 * with llcrypto_key_free as the close function.
 */
struct llcrypto_key {
	enum llcrypto_key_type type; /**< Backend that holds the key */
	/* cppcheck-suppress misra-c2012-19.2 ; intentional tagged union discriminated by `type`; the backends are
	 * mutually exclusive per key, so a struct holding all of them would waste RAM. No type-punning: each member is
	 * read only under its matching `type` value. */
	union {
		EVP_PKEY *evp_key;                       /**< OpenSSL asymmetric key, valid when type is
		                                          * LLCRYPTO_KEY_TYPE_EVP_PKEY
		                                          */
		struct llcrypto_secret_key_data secret_key; /**< RAW Secret Key, valid when type is LLCRYPTO_KEY_TYPE_SECRET_KEY
		                                             */
	};

#if defined(LLCRYPTO_KEYSTORE_PKCS11)
	char *alias; /**< PKCS#11 token alias (CKA_LABEL) for a token-resident private key, NULL otherwise.
	              *   Set by the PKCS#11 External KeyStore backend so operations that the
	              *   pkcs11-provider encodes incompatibly (ECDH peer point) go through the
	              *   direct PKCS#11 C API. Heap-allocated, freed by llcrypto_key_free.
	              *   Compiled in only with that backend: no other backend can ever set it. */
#endif
};

/**
 * @brief Wrap a pre-created EVP_PKEY in an llcrypto_key.
 *
 * Ownership of evp_key is transferred to the returned llcrypto_key.
 *
 * @invariant This function MUST be called from the core engine task.
 *
 * @param evp_key OpenSSL EVP_PKEY to wrap. NOT freed on allocation failure.
 *
 * @return struct llcrypto_key* A heap allocated key, NULL on failure.
 */
struct llcrypto_key *llcrypto_key_from_evp_pkey(EVP_PKEY *evp_key);

/**
 * @brief Instantiate a new key from parsing an encoded public key.
 * Parse a public key encoded as an ASN.1 `SubjectPublicKeyInfo`, DER encoded.
 * @invariant This function MUST be called from the core engine task.
 * @param encoded_key Buffer containing the encoded key.
 * @param key_length Length of the buffer pointed to by `encoded_key`.
 * @param[out] key_out A heap allocated key on success, NULL on failure.
 * @return `LLCRYPTO_SUCCESS`, `LLCRYPTO_ERROR_OOM` when the key cannot be allocated, or `LLCRYPTO_ERROR` when the
 *         encoded key is invalid, with the reason in the OpenSSL error queue.
 */
int32_t llcrypto_key_from_x509_public_key(const uint8_t *encoded_key, size_t key_length,
                                          struct llcrypto_key **key_out);

/**
 * @brief Instantiate a new key from parsing an encoded private key.
 * Parse a private key encoded as a DER PKCS#8 `PrivateKeyInfo`, the encoding of a `PKCS8EncodedKeySpec`. A
 * traditional (PKCS#1 or SEC1) DER key is accepted too.
 * @invariant This function MUST be called from the core engine task.
 * @param encoded_key Buffer containing the encoded key.
 * @param key_length Length of the buffer pointed to by `encoded_key`.
 * @param[out] key_out A heap allocated key on success, NULL on failure.
 * @return `LLCRYPTO_SUCCESS`, `LLCRYPTO_ERROR_OOM` when the key cannot be allocated, or `LLCRYPTO_ERROR` when the
 *         encoded key is invalid, with the reason in the OpenSSL error queue.
 */
int32_t llcrypto_key_from_pkcs8_private_key(const uint8_t *encoded_key, size_t key_length,
                                            struct llcrypto_key **key_out);

/**
 * @brief Instantiate a new secret key from a raw symmetric key.
 *
 * @invariant This function MUST be called from the core engine task.
 *
 * @param secret_key Buffer to the secret key.
 * @param key_length Length of the buffer.
 * @param algorithm String representing the key algorithm in its Java definition (e.g. "AES"). May be NULL.
 *
 * @return struct llcrypto_key* A heap allocated key, NULL on failure.
 */
struct llcrypto_key *llcrypto_key_from_secret_key(const uint8_t *secret_key, size_t key_length,
                                                  const uint8_t *algorithm);

/**
 * @brief Free a key.
 *
 * Free all resources held by the key, unregister the SNI resource, and free the struct itself.
 * Safe to call as an SNI close function (signature-compatible with SNI_closeFunction).
 *
 * @invariant This function MUST be called from the core engine task.
 *
 * @param key Key to be freed.
 */
void llcrypto_key_free(struct llcrypto_key *key);

/**
 * @brief Get the maximum size in bytes of the exported key material.
 *
 * For LLCRYPTO_KEY_TYPE_SECRET_KEY this is the raw key length.
 * Returns 0 for EVP_PKEY types.
 *
 * @param key Key object.
 *
 * @return int32_t Size in bytes, or 0 on failure or unsupported key type.
 */
int32_t llcrypto_key_get_encoded_max_size(const struct llcrypto_key *key);

/**
 * @brief Export the raw key bytes into a caller-supplied buffer.
 *
 * For LLCRYPTO_KEY_TYPE_SECRET_KEY this copies the raw key material.
 *
 * @param key Key object.
 * @param output Output buffer.
 * @param output_length Size of the output buffer in bytes.
 *
 * @return int32_t Number of bytes written on success, 0 on failure.
 */
int32_t llcrypto_key_get_encoded(const struct llcrypto_key *key, uint8_t *output, int32_t output_length);

#ifdef __cplusplus
}
#endif

#endif /* LLCRYPTO_KEY_H */
