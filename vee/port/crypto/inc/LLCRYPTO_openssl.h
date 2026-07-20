/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#ifndef LLCRYPTO_OPENSSL_H
#define LLCRYPTO_OPENSSL_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LLCRYPTO_MD_SHA1,
	LLCRYPTO_MD_SHA224,
	LLCRYPTO_MD_SHA256,
	LLCRYPTO_MD_SHA384,
	LLCRYPTO_MD_SHA512
} LLCRYPTO_md_type;

#ifdef __cplusplus
}
#endif

#endif /* LLCRYPTO_OPENSSL_H */
