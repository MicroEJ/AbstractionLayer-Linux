/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#ifndef LLCRYPTO_UTILS_H
#define LLCRYPTO_UTILS_H

#include <stdint.h>
#include <sni.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The three AES key sizes, in bits.
 *
 * Shared by every module that selects an OpenSSL cipher from the key length the Java layer
 * supplied (CIPHER, AES_KEY_WRAP). These are key sizes, not block sizes -- AES has a single
 * 128-bit block whatever the key size, which the per-transformation *_BLOCK_BITS constants
 * describe.
 */
#define LLCRYPTO_AES_128_KEY_BITS (128u)
#define LLCRYPTO_AES_192_KEY_BITS (192u)
#define LLCRYPTO_AES_256_KEY_BITS (256u)

/**
 * @brief Unregisters an SNI native resource then closes it.
 *
 * On unregister failure (the resource is not in the SNI table — it was already closed or the VM
 * auto-closed it) a NativeException is thrown and @p close_function is NOT invoked, because the resource is
 * no longer owned by this path and freeing it would be a double-free. On success @p close_function
 * is invoked exactly once.
 *
 * This factors out the resource teardown boilerplate shared verbatim by every LLCRYPTO *_IMPL_close
 * native (DIGEST, MAC, CIPHER, RSA_CIPHER, AES_KEY_WRAP).
 *
 * @param[in] resource the native resource handle previously registered with SNI_registerResource.
 * @param[in] close_function the close function registered alongside @p resource.
 */
void llcrypto_unregister_and_close(void *resource, SNI_closeFunction close_function);

/**
 * @brief Maps a Java elliptic-curve name to its OpenSSL NID.
 *
 * Resolves the name through OBJ_txt2nid first, then falls back to a table of the common Java
 * curve names OpenSSL does not register (e.g. "secp256r1", "P-256").
 *
 * @param[in] name the Java curve name, NUL-terminated.
 * @return the OpenSSL NID for @p name, or NID_undef if the name is unknown.
 */
int llcrypto_curve_name_to_nid(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* LLCRYPTO_UTILS_H */
