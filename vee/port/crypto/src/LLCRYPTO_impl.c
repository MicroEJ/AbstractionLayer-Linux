/**
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#include <LLCRYPTO_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include "LLCRYPTO_configuration.h"
#include <sni.h>

#include <openssl/crypto.h>

void LLCRYPTO_IMPL_initialize(void) {
	/* Initialize OpenSSL with OPENSSL_INIT_NO_LOAD_CONFIG so the process never
	 * loads an OpenSSL configuration file. The external keystore backend
	 * configures the pkcs11-provider programmatically, so no config file is
	 * needed; skipping it also prevents an attacker-controlled OPENSSL_CONF in
	 * the environment from loading arbitrary providers or engines. This is the
	 * LLCRYPTO startup hook, so it runs before any other OpenSSL call. */
	if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) != 1) {
		LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeException(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                                   "OpenSSL initialization failed"));
	}
}
