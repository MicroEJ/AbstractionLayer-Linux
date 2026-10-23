/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO_EXTERNAL_KEYSTORE implementation backed by a PKCS#11 token.
 *
 * Reads (alias enumeration, getKey, getCertificate) go through OpenSSL's
 * pkcs11-provider via the OSSL_STORE API with pkcs11: URIs. Keys are returned
 * as provider-backed EVP_PKEY handles inside llcrypto_key structs; certificates
 * are returned as SNI-managed DER blobs.
 *
 * Writes (KeyStore.setKeyEntry / setCertificateEntry / deleteEntry) cannot
 * use OSSL_STORE — OpenSSL 3 has no public store-write API. Instead they use
 * the PKCS#11 C API directly: every compliant module exports exactly one
 * symbol — C_GetFunctionList — which returns a struct of function pointers
 * for everything else. We resolve that symbol once via dlopen()/dlsym() of
 * the path supplied by LLCRYPTO_PKCS11_MODULE, share the C_Initialize state
 * with pkcs11-provider (CKR_CRYPTOKI_ALREADY_INITIALIZED is expected and
 * ignored), and never C_Finalize. This keeps the BSP backend-agnostic
 * (SoftHSM2 on the dev host, OP-TEE PKCS#11 TA on iMX boards, opensc on
 * smartcards, ...).
 *
 * The pkcs11-provider is configured programmatically at login (provider search
 * path + PKCS11_PROVIDER_MODULE + explicit provider load), so no OPENSSL_CONF
 * file and no OPENSSL_MODULES environment variable are required.
 */

#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <pkcs11.h>
#include <LLCRYPTO_EXTERNAL_KEYSTORE_impl.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <sni.h>

#include "LLCRYPTO_configuration.h"
#include "sni_extras.h"
#include "LLCRYPTO_EXTERNAL_KEYSTORE_common.h"
#include "LLCRYPTO_EXTERNAL_KEYSTORE_pkcs11.h"
#include "LLCRYPTO_key.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLCRYPTO_LOG_MODULE_NAME, LLCRYPTO_LOG_LEVEL)

/* CKD_NULL selects "no KDF" (the raw shared value) for CKM_ECDH1_DERIVE. Its
 * OASIS PKCS#11 standard value is 0x00000001; the libckteec (OP-TEE) pkcs11.h
 * declares CK_EC_KDF_TYPE but omits the CKD_* constants, so provide a fallback
 * when the header does not. */
#ifndef CKD_NULL
#define CKD_NULL ((CK_EC_KDF_TYPE)0x00000001UL)
#endif

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/** PKCS#11 module path. Project-specific; set at build time from
 *  project_options.cmake via -DLLCRYPTO_PKCS11_MODULE="...". The module differs
 *  per backend (libsofthsm2, libckteec, opensc-pkcs11, a vendor HSM library),
 *  so there is no default worth guessing. */
#ifndef LLCRYPTO_PKCS11_MODULE
#error "LLCRYPTO_PKCS11_MODULE must be defined: set it in project_options.cmake"
#endif

/** Token label used for slot selection. Project-specific; set at build time
 *  from project_options.cmake via -DLLCRYPTO_PKCS11_TOKEN="...". */
#ifndef LLCRYPTO_PKCS11_TOKEN
#define LLCRYPTO_PKCS11_TOKEN "MicroEJ-Test"
#endif

/** OpenSSL provider modules directory. Project-specific; set at build time from
 *  project_options.cmake via -DLLCRYPTO_OSSL_MODULES_DIR="...". An empty
 *  string leaves OpenSSL's built-in module search path untouched. */
#ifndef LLCRYPTO_OSSL_MODULES_DIR
#define LLCRYPTO_OSSL_MODULES_DIR ""
#endif

/** Environment variable read by pkcs11-provider for the underlying PKCS#11
 *  module path (alternative to the pkcs11-module-path config key). Set in
 *  process by configure_pkcs11_provider() so the launcher needs no env. */
#define LLCRYPTO_PKCS11_PROVIDER_MODULE_ENV "PKCS11_PROVIDER_MODULE"

/** Size of a stack-allocated pkcs11: URI buffer. 1 KiB is comfortably larger
 *  than token_uri (512) + ;object=<alias> (~256) + ;type=<kw> (~16) + a PIN. */
#define LLCRYPTO_PKCS11_URI_MAX 1024

/** PKCS#11 v2.40 caps CK_TOKEN_INFO::label at 32 bytes (space-padded, no NUL). */
#define LLCRYPTO_PKCS11_LABEL_MAX 32U

/** Buffer size to hold @p n input bytes after percent-encoding by
 *  pct_encode_pk11(): worst case every byte expands to "%XX" (3 chars), plus 1
 *  for the NUL terminator. */
#define LLCRYPTO_PCT_ENCODED_SIZE(n) (((n) * 3U) + 1U)

/** Upper bound on the number of PKCS#11 objects a single alias can produce on
 *  the token: 1 private/secret key + 1 leaf certificate + up to 6 chain
 *  certificates (labeled `<alias>-chain-N`). Used to size the `C_FindObjects`
 *  result buffer in `enumerate_aliases_via_pkcs11`, which fetches every object
 *  on the token in one call. Public CA chains are typically 1–3 intermediates
 *  deep, so 8 is comfortable headroom. If this is ever raised, note that the
 *  enumeration buffer is `LLCRYPTO_EKS_MAX_OBJECTS * LLCRYPTO_PKCS11_OBJECTS_PER_ALIAS_MAX`
 *  handles on the stack. */
#define LLCRYPTO_PKCS11_OBJECTS_PER_ALIAS_MAX 8

/* CKA_SENSITIVE / CKA_EXTRACTABLE values for keys created by setKeyEntry.
 * The CMake option LLCRYPTO_PKCS11_NON_EXTRACTABLE_KEYS flips these to HSM-grade
 * non-extractable when set. See CMakeLists.txt for the rationale. */
#ifdef LLCRYPTO_PKCS11_NON_EXTRACTABLE_KEYS
#define LLCRYPTO_PKCS11_KEY_SENSITIVE   CK_TRUE
#define LLCRYPTO_PKCS11_KEY_EXTRACTABLE CK_FALSE
#else
#define LLCRYPTO_PKCS11_KEY_SENSITIVE   CK_FALSE
#define LLCRYPTO_PKCS11_KEY_EXTRACTABLE CK_TRUE
#endif

// -----------------------------------------------------------------------------
// Internal data structures
// -----------------------------------------------------------------------------

/**
 * Global PKCS#11 keystore state.
 * Holds the OpenSSL library context with loaded pkcs11 provider,
 * plus the cached PIN and token URI prefix.
 */
static struct {
	bool loaded;
	char token_uri[512];             /**< Base PKCS#11 URI, e.g. "pkcs11:token=MyToken". */
	char pin[128];                   /**< Cached PIN from login(). */
	size_t pin_len;                  /**< Length of pin, excluding the NUL. */

	/* Alias cache. Populated lazily by get_cached_aliases() and invalidated
	 * by invalidate_alias_cache() whenever the token is mutated by a
	 * setKeyEntry / setCertificateEntry / deleteEntry call. Read-only for
	 * all other callers. LLAPI calls are VM-serialized so no locking is
	 * required. */
	bool aliases_cached;
	int alias_count;
	char aliases[LLCRYPTO_EKS_MAX_OBJECTS][LLCRYPTO_EKS_MAX_ALIAS_LEN];

	/* Direct PKCS#11 C API state — resolved lazily by pkcs11_capi_init() on
	 * the first read or write call that needs it (login() PIN validation,
	 * the secret-key path in getKeyId, the chain walker in
	 * getCertificateChainHandle, and every write entry point). The PKCS#11
	 * module is loaded by pkcs11-provider during OpenSSL initialization;
	 * dlopen() of the same path returns a handle to that existing mapping
	 * (no second copy in memory). C_Initialize then returns
	 * CKR_CRYPTOKI_ALREADY_INITIALIZED, which we ignore so we share the
	 * provider's session-management state. We never C_Finalize. */
	bool capi_loaded;
	void *module_handle;             /**< dlopen() handle. */
	CK_FUNCTION_LIST_PTR funcs;      /**< Function pointer table from C_GetFunctionList. */
	CK_SLOT_ID slot;              /**< Slot we operate on. */
} g_p11;

/**
 * Invalidate the alias cache. Must be called after every successful token
 * mutation (setKeyEntry / setCertificateEntry / deleteEntry) so the next
 * size() / getAlias() / containsAlias() re-enumerates from the token.
 */
static void invalidate_alias_cache(void) {
	g_p11.aliases_cached = false;
	g_p11.alias_count = 0;
}

// -----------------------------------------------------------------------------
// Direct PKCS#11 C API access (used by both read and write paths)
// -----------------------------------------------------------------------------

/** PKCS#11 standard bootstrap — every compliant module exports this one
 *  symbol; the resulting CK_FUNCTION_LIST holds pointers to everything else. */
typedef CK_RV (*C_GetFunctionList_fn_t)(CK_FUNCTION_LIST_PTR_PTR);

/**
 * Resolve the PKCS#11 module's function-pointer table and pick the slot.
 *
 * Idempotent: returns LLCRYPTO_SUCCESS immediately if already initialized. On
 * first call: dlopen()s the module configured in LLCRYPTO_PKCS11_MODULE,
 * dlsym()s C_GetFunctionList, calls C_Initialize (CKR_CRYPTOKI_ALREADY_INITIALIZED
 * is expected and ignored — the provider beat us to it), and resolves the
 * slot by scanning slots whose token label matches LLCRYPTO_PKCS11_TOKEN.
 *
 * @return LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR on failure (a NativeIOException is thrown).
 */
static int pkcs11_capi_init(void) {
	int result = LLCRYPTO_ERROR;

	if (g_p11.capi_loaded) {
		result = LLCRYPTO_SUCCESS;
		goto end;
	}
	if (!g_p11.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	/* RTLD_LAZY|RTLD_GLOBAL — same flags pkcs11-provider used. dlopen of an
	 * already-loaded shared object returns a handle to the existing in-memory
	 * mapping (refcount++), it is NOT a second copy. */
	void *h = dlopen(LLCRYPTO_PKCS11_MODULE, RTLD_LAZY | RTLD_GLOBAL);
	if (NULL == h) {
		VEEPORT_LOGGER_LOG_ERR("dlopen('%s') failed: %s", LLCRYPTO_PKCS11_MODULE, dlerror());
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "PKCS#11 module initialization failed");
		goto end;
	}

	C_GetFunctionList_fn_t getlist = (C_GetFunctionList_fn_t)dlsym(h, "C_GetFunctionList");
	if (NULL == getlist) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "PKCS#11 module missing C_GetFunctionList symbol");
		(void)dlclose(h);
		goto end;
	}

	CK_FUNCTION_LIST_PTR funcs = NULL;
	CK_RV rv = getlist(&funcs);
	if ((CKR_OK != rv) || (NULL == funcs)) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "C_GetFunctionList failed");
		(void)dlclose(h);
		goto end;
	}

	/* C_Initialize is mandatory before any other call. pkcs11-provider has
	 * already initialized this module; CKR_CRYPTOKI_ALREADY_INITIALIZED tells
	 * us we're sharing state with the provider, which is exactly what we
	 * want — no separate session pool, no risk of duplicated init. */
	rv = funcs->C_Initialize(NULL);
	if ((CKR_OK != rv) && (CKR_CRYPTOKI_ALREADY_INITIALIZED != rv)) {
		VEEPORT_LOGGER_LOG_ERR("C_Initialize failed: 0x%lx", (unsigned long)rv);
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "PKCS#11 module initialization failed");
		(void)dlclose(h);
		goto end;
	}

	/* Resolve the slot by matching the configured token label. */
	CK_SLOT_ID slot = 0;
	int slot_resolved = 0;
	const char *token_label = LLCRYPTO_PKCS11_TOKEN;
	/* cppcheck-suppress knownConditionTrueFalse ; project_options.cmake sets the macro, so the analysis folds
	 * this build's value. An empty label must not match a token whose own label is blank. */
	if (token_label[0] != '\0') {
		CK_ULONG nslots = 0;
		rv = funcs->C_GetSlotList(CK_TRUE, NULL, &nslots);
		if ((CKR_OK == rv) && (nslots > 0U)) {
			CK_SLOT_ID *slots = (CK_SLOT_ID *)LLCRYPTO_calloc(nslots, sizeof(CK_SLOT_ID));
			if (NULL != slots) {
				rv = funcs->C_GetSlotList(CK_TRUE, slots, &nslots);
				if (CKR_OK == rv) {
					size_t lbl_len = strlen(token_label);
					if (lbl_len > LLCRYPTO_PKCS11_LABEL_MAX) {
						lbl_len = LLCRYPTO_PKCS11_LABEL_MAX;
					}
					for (CK_ULONG i = 0; i < nslots; i++) {
						CK_TOKEN_INFO ti;
						if (CKR_OK == funcs->C_GetTokenInfo(slots[i], &ti)) {
							if (0 == strncmp((const char *)ti.label, token_label, lbl_len)) {
								bool trailing_ok = true;
								for (size_t j = lbl_len; j < LLCRYPTO_PKCS11_LABEL_MAX; j++) {
									if (ti.label[j] != (CK_UTF8CHAR)' ') {
										trailing_ok = false;
										break;
									}
								}
								if (trailing_ok) {
									slot = slots[i];
									slot_resolved = 1;
									break;
								}
							}
						}
					}
				}
				LLCRYPTO_free(slots);
			}
		}
	}
	if (!slot_resolved) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Could not resolve PKCS#11 slot from token label");
		(void)dlclose(h);
		goto end;
	}

	g_p11.module_handle = h;
	g_p11.funcs = funcs;
	g_p11.slot = slot;
	g_p11.capi_loaded = true;
	VEEPORT_LOGGER_LOG_DBG("writer ready, slot=%lu", (unsigned long)slot);
	result = LLCRYPTO_SUCCESS;

end:
	return result;
}

/**
 * Open a session with the requested @p extra_flags (CKF_RW_SESSION or 0) and
 * log in with the cached PIN. Caller must release with pkcs11_close_session().
 * Returns CK_INVALID_HANDLE on failure (a NativeIOException has been thrown).
 *
 * PKCS#11 login is slot-scoped, not session-scoped: SoftHSM2 and most modules
 * apply the login state to the entire token regardless of which session called
 * C_Login. So a R/O session opened by login() to validate the PIN is enough
 * to leave the token in user-logged-in state for any later R/W session.
 */
static CK_SESSION_HANDLE pkcs11_open_session(CK_FLAGS extra_flags) {
	CK_SESSION_HANDLE result = CK_INVALID_HANDLE;

	if (LLCRYPTO_SUCCESS != pkcs11_capi_init()) {
		goto end;
	}
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_RV rv = g_p11.funcs->C_OpenSession(g_p11.slot,
	                                      CKF_SERIAL_SESSION | extra_flags,
	                                      NULL, NULL, &session);
	if (CKR_OK != rv) {
		VEEPORT_LOGGER_LOG_ERR("C_OpenSession failed: 0x%lx", (unsigned long)rv);
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "PKCS#11 session creation failed");
		goto end;
	}

	/* Login as user. CKR_USER_ALREADY_LOGGED_IN is fine — pkcs11-provider may
	 * have already logged in on this slot from another session, or login() may
	 * have done it during PIN validation. The redundant call is cheap and
	 * keeps each flow self-contained.
	 *
	 * Any other result aborts the caller, the read paths included: they all run
	 * after login() has already succeeded, so a failure here means the token
	 * changed underneath. Reading on with an unauthenticated session would
	 * report a missing or partial entry, which a caller cannot tell apart from
	 * a token that genuinely holds none. */
	rv = g_p11.funcs->C_Login(session, CKU_USER,
	                          (CK_UTF8CHAR_PTR)g_p11.pin,
	                          (CK_ULONG)strlen(g_p11.pin));
	if ((CKR_OK != rv) && (CKR_USER_ALREADY_LOGGED_IN != rv)) {
		/* Constant message: the CK_RV distinguishes PIN incorrect / expired /
		 * locked, which paces a PIN-guessing attack around the lockout policy. */
		VEEPORT_LOGGER_LOG_ERR("C_Login failed: 0x%lx", (unsigned long)rv);
		(void)g_p11.funcs->C_CloseSession(session);
		/* Only a PIN the token rejects is a wrong password. A locked or expired PIN, or a token that is gone,
		 * is not something a caller fixes by asking for the password again. */
		bool pin_rejected = (CKR_PIN_INCORRECT == rv) || (CKR_PIN_INVALID == rv) || (CKR_PIN_LEN_RANGE == rv);
		int32_t exception_code =
			pin_rejected ? LLCRYPTO_EXTERNAL_KEYSTORE_BAD_PASSWORD : LLCRYPTO_UNSPECIFIED_EXCEPTION;
		VEEPORT_ERRORS_throw_caught_exception_message(exception_code, "PKCS#11 authentication failed");
		goto end;
	}
	result = session;

end:
	return result;
}

/** Open a R/W session and log in with the cached PIN. */
static CK_SESSION_HANDLE pkcs11_open_session_rw(void) {
	return pkcs11_open_session(CKF_RW_SESSION);
}

/** Open a R/O session and log in with the cached PIN. Used by login() to
 *  validate the PIN, by the ECDH derivation, and by the four read paths: alias
 *  enumeration, getKeyId's secret-key fallback, getCertificateChainHandle and
 *  getEntryType. The resulting login state is slot-scoped, so subsequent R/W
 *  sessions opened by the writer inherit the auth. */
static CK_SESSION_HANDLE pkcs11_open_session_ro(void) {
	return pkcs11_open_session(0);
}

/** Close a session opened by pkcs11_open_session_{rw,ro}(). Best-effort. */
static void pkcs11_close_session(CK_SESSION_HANDLE session) {
	if ((CK_INVALID_HANDLE != session) && (NULL != g_p11.funcs)) {
		(void)g_p11.funcs->C_CloseSession(session);
	}
}

/**
 * Find every object on the token whose CKA_LABEL equals @p alias, regardless
 * of class. Writes up to @p max handles into @p out and returns the count.
 *
 * Used by deleteEntry (destroy all matching objects) and by setKeyEntry's
 * "delete the previous binding before installing the new one" step.
 */
static int pkcs11_find_objects_by_label(CK_SESSION_HANDLE session, char *alias,
                                        CK_OBJECT_HANDLE *out, int max) {
	CK_ATTRIBUTE templ[1];
	templ[0].type = CKA_LABEL;
	templ[0].pValue = alias;
	templ[0].ulValueLen = (CK_ULONG)strlen(alias);

	CK_RV rv = g_p11.funcs->C_FindObjectsInit(session, templ, sizeof(templ) / sizeof(templ[0]));
	if (CKR_OK != rv) {
		return -1;
	}
	CK_ULONG found = 0;
	rv = g_p11.funcs->C_FindObjects(session, out, (CK_ULONG)max, &found);
	(void)g_p11.funcs->C_FindObjectsFinal(session);
	if (CKR_OK != rv) {
		return -1;
	}
	return (int)found;
}

/** Destroy each object handle in @p handles. Returns LLCRYPTO_SUCCESS if every destroy
 *  succeeded, LLCRYPTO_ERROR otherwise (continues on errors so partial cleanup is done). */
static int writer_destroy_objects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *handles, int handle_count) {
	int result = LLCRYPTO_SUCCESS;
	for (int i = 0; i < handle_count; i++) {
		CK_RV rv = g_p11.funcs->C_DestroyObject(session, handles[i]);
		if (CKR_OK != rv) {
			VEEPORT_LOGGER_LOG_ERR("C_DestroyObject(%lu) failed: 0x%lx", (unsigned long)handles[i], (unsigned long)rv);
			result = LLCRYPTO_ERROR;
		}
	}
	return result;
}

/**
 * Percent-encode @p in into @p out per RFC 7512 path-attribute-value rules
 * (unreserved = ALPHA / DIGIT / '-' / '.' / '_' / '~'; everything else,
 * notably ';', '?', '=', '/', '#', is percent-encoded). Output is always
 * NUL-terminated.
 *
 * @return LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR if @p out_size is too small.
 */
static int pct_encode_pk11(char *out, size_t out_size, const char *in) {
	static const char hex[] = "0123456789ABCDEF";
	int result = LLCRYPTO_ERROR;
	size_t out_len = 0;
	for (const char *p = in; '\0' != *p; p++) {
		char c = *p;
		bool unreserved = (((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) ||
		                   ((c >= '0') && (c <= '9')) || ('-' == c) || ('.' == c) ||
		                   ('_' == c) || ('~' == c));
		size_t needed = unreserved ? 1U : 3U;
		if ((out_len + needed) >= out_size) {
			goto end;
		}
		if (unreserved) {
			out[out_len] = c;
		} else {
			/* The nibbles must come from the unsigned value: c may be negative. */
			unsigned char u = (unsigned char)c;
			out[out_len] = '%';
			out[out_len + 1U] = hex[(u >> 4) & 0x0FU];
			out[out_len + 2U] = hex[u & 0x0FU];
		}
		out_len += needed;
	}
	if (out_len >= out_size) {
		goto end;
	}
	out[out_len] = '\0';
	result = LLCRYPTO_SUCCESS;

end:
	return result;
}

/**
 * Build a PKCS#11 URI for a specific object type.
 *
 * @p object and the cached PIN are percent-encoded (per RFC 7512) before
 * being inlined into the URI so values containing reserved characters
 * (';', '=', '?', etc.) cannot inject extra URI attributes. The token-URI
 * prefix is composed in login() and is already encoded there.
 *
 * Every snprintf is checked for truncation; on overflow the function returns
 * -1 without propagating a partial URI. A truncated URI would silently drop
 * the alias/type filter or the cached PIN, which can cause OSSL_STORE to
 * authenticate with a partial PIN (risking HSM lockout) or to return an
 * unintended object class.
 *
 * @param uri      Output buffer.
 * @param uri_size Size of the output buffer.
 * @param object   Object label (alias), or NULL for enumeration.
 * @param type     Object type filter ("private", "public", "cert", "secret"), or NULL.
 * @return LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR if @p uri_size is too small for the full URI.
 */
static int build_pkcs11_uri(char *uri, size_t uri_size, const char *object, const char *type) {
	int result = LLCRYPTO_ERROR;
	int ret = snprintf(uri, uri_size, "%s", g_p11.token_uri);
	if ((ret < 0) || ((size_t)ret >= uri_size)) {
		goto end;
	}
	size_t len = (size_t)ret;

	if (NULL != object) {
		char encoded[LLCRYPTO_PCT_ENCODED_SIZE(LLCRYPTO_EKS_MAX_ALIAS_LEN)];
		if (LLCRYPTO_SUCCESS != pct_encode_pk11(encoded, sizeof(encoded), object)) {
			goto end;
		}
		ret = snprintf(&uri[len], uri_size - len, ";object=%s", encoded);
		if ((ret < 0) || ((size_t)ret >= (uri_size - len))) {
			goto end;
		}
		len += (size_t)ret;
	}
	if (NULL != type) {
		ret = snprintf(&uri[len], uri_size - len, ";type=%s", type);
		if ((ret < 0) || ((size_t)ret >= (uri_size - len))) {
			goto end;
		}
		len += (size_t)ret;
	}
	/* Append PIN to the URI so OSSL_STORE can authenticate without UI_METHOD.
	 * The PIN is percent-encoded so it can contain any character. */
	if (g_p11.pin[0] != '\0') {
		char encoded_pin[LLCRYPTO_PCT_ENCODED_SIZE(sizeof(g_p11.pin))];
		if (LLCRYPTO_SUCCESS != pct_encode_pk11(encoded_pin, sizeof(encoded_pin), g_p11.pin)) {
			goto end;
		}
		ret = snprintf(&uri[len], uri_size - len, ";pin-value=%s", encoded_pin);
		if ((ret < 0) || ((size_t)ret >= (uri_size - len))) {
			goto end;
		}
	}
	result = LLCRYPTO_SUCCESS;

end:
	return result;
}

// -----------------------------------------------------------------------------
// PKCS#11 enumeration helpers
// -----------------------------------------------------------------------------

/**
 * Enumerate object labels via the PKCS#11 C API (C_FindObjects with no
 * template = match every object). dlopen() of an already-loaded module gives
 * us a handle to the same in-memory mapping pkcs11-provider has, and our
 * C_Initialize call returns CKR_CRYPTOKI_ALREADY_INITIALIZED — which we
 * handle in pkcs11_capi_init() — so we share state with the provider rather than
 * fighting it.
 *
 * Filters out chain-cert objects (label suffix "-chain-N") so the Java side
 * only sees the user-visible aliases, not the bookkeeping certificates we
 * create for chain links.
 *
 * Every failure throws exactly once and returns -1, so a caller must not throw
 * again on -1. This matters because LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_size() has
 * no error return value in its LLAPI contract: an enumeration failure can only
 * reach the Java side as an exception, and it has to be this one.
 *
 * @return Number of unique aliases found, or -1 with a native exception already
 *         thrown.
 */
static int enumerate_aliases_via_pkcs11(char aliases[][LLCRYPTO_EKS_MAX_ALIAS_LEN], int max_aliases) {
	int result = -1;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	if (LLCRYPTO_SUCCESS != pkcs11_capi_init()) {
		/* Clears the OpenSSL error queue only: pkcs11_capi_init has already
		 * thrown, and that exception is what the caller reports. */
		ERR_clear_error();
		goto end;
	}

	session = pkcs11_open_session_ro();
	if (CK_INVALID_HANDLE == session) {
		goto end; /* exception already thrown */
	}

	int alias_count = 0;
	CK_RV rv = g_p11.funcs->C_FindObjectsInit(session, NULL, 0);
	if (CKR_OK != rv) {
		VEEPORT_LOGGER_LOG_ERR("C_FindObjectsInit failed: 0x%lx", (unsigned long)rv);
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Cannot enumerate PKCS#11 objects");
		goto end;
	}

	/* Each alias may produce several PKCS#11 objects (key + leaf + chain
	 * certs); see LLCRYPTO_PKCS11_OBJECTS_PER_ALIAS_MAX. Dedupe by label below. */
	CK_OBJECT_HANDLE handles[LLCRYPTO_EKS_MAX_OBJECTS * LLCRYPTO_PKCS11_OBJECTS_PER_ALIAS_MAX];
	CK_ULONG found = 0;
	rv = g_p11.funcs->C_FindObjects(session, handles,
	                                (CK_ULONG)(sizeof(handles) / sizeof(handles[0])),
	                                &found);
	(void)g_p11.funcs->C_FindObjectsFinal(session);

	if (CKR_OK != rv) {
		/* Report it rather than returning the zero aliases collected so far,
		 * which the caller cannot tell apart from an empty keystore. */
		VEEPORT_LOGGER_LOG_ERR("C_FindObjects failed: 0x%lx", (unsigned long)rv);
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Cannot enumerate PKCS#11 objects");
	} else {
		for (CK_ULONG i = 0; (i < found) && (alias_count < max_aliases); i++) {
			char label[LLCRYPTO_EKS_MAX_ALIAS_LEN];
			CK_ATTRIBUTE label_attr = { CKA_LABEL, label, sizeof(label) - 1U };
			if (CKR_OK != g_p11.funcs->C_GetAttributeValue(session, handles[i], &label_attr, 1)) {
				continue;
			}
			CK_ULONG llen = label_attr.ulValueLen;
			if ((0U == llen) || (llen >= sizeof(label))) {
				continue;
			}
			label[llen] = '\0';

			/* Skip chain-cert bookkeeping objects — they share the leaf's
			 * CKA_ID and our chain walker finds them via that link, so
			 * they don't appear as separate user-facing aliases. */
			if (strstr(label, "-chain-") != NULL) {
				continue;
			}

			int duplicate = 0;
			for (int j = 0; j < alias_count; j++) {
				if (0 == strcasecmp(aliases[j], label)) {
					duplicate = 1;
					break;
				}
			}
			if (!duplicate) {
				(void)memcpy(aliases[alias_count], label, (size_t)llen + 1U);
				alias_count++;
			}
		}
		result = alias_count;
	}

end:
	pkcs11_close_session(session);
	return result;
}

/**
 * Return the cached alias count, populating the cache on first use.
 *
 * The alias set is static after login() until a setKeyEntry / setCertificateEntry
 * / deleteEntry mutation invalidates the cache, so the next caller re-enumerates.
 *
 * @return Alias count on success, -1 on enumeration failure (cache left empty).
 */
static int get_cached_aliases(void) {
	int result = -1;
	if (!g_p11.aliases_cached) {
		int n = enumerate_aliases_via_pkcs11(g_p11.aliases, LLCRYPTO_EKS_MAX_OBJECTS);
		if (n < 0) {
			goto end;
		}
		g_p11.alias_count = n;
		g_p11.aliases_cached = true;
	}
	result = g_p11.alias_count;

end:
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Common
// -----------------------------------------------------------------------------

/**
 * Configure and load the OpenSSL pkcs11-provider programmatically:
 *
 *  - OSSL_PROVIDER_set_default_search_path() points OpenSSL at the directory
 *    holding pkcs11.so (replaces OPENSSL_MODULES);
 *  - PKCS11_PROVIDER_MODULE is set in process to tell pkcs11-provider which
 *    PKCS#11 module to load (alternative to the pkcs11-module-path config key),
 *    so the launcher needs no environment;
 *  - the default and pkcs11 providers are loaded and activated explicitly.
 *
 * @param module_path path to the underlying PKCS#11 module .so.
 * @return LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR on failure (a NativeIOException is thrown).
 */
static int configure_pkcs11_provider(const char *module_path) {
	int result = LLCRYPTO_ERROR;

	/* Point OpenSSL at the directory holding pkcs11.so. An empty default means
	 * "leave OpenSSL's built-in search path untouched". */
	const char *modules_dir = LLCRYPTO_OSSL_MODULES_DIR;
	/* cppcheck-suppress knownConditionTrueFalse ; project_options.cmake sets the macro, so the analysis folds
	 * this build's value. An empty dir leaves the OpenSSL search path untouched. */
	if (modules_dir[0] != '\0') {
		if (1 != OSSL_PROVIDER_set_default_search_path(NULL, modules_dir)) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                              "Failed to set the OpenSSL provider search path");
			goto end;
		}
	}

	if (0 != setenv(LLCRYPTO_PKCS11_PROVIDER_MODULE_ENV, module_path, 1)) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Failed to set PKCS11_PROVIDER_MODULE");
		goto end;
	}

	if (NULL == OSSL_PROVIDER_load(NULL, "default")) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Failed to load the OpenSSL default provider");
		goto end;
	}

	if (NULL == OSSL_PROVIDER_load(NULL, "pkcs11")) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Failed to load the OpenSSL pkcs11 provider. Check the "
		                                              "provider search path and the PKCS#11 module path.");
		goto end;
	}

	/* Confirm the provider is really active: OSSL_PROVIDER_load can succeed
	 * while a later self-test or module dlopen leaves it unavailable. */
	if (1 != OSSL_PROVIDER_available(NULL, "pkcs11")) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "pkcs11-provider is not available after load");
		goto end;
	}

	result = LLCRYPTO_SUCCESS;

end:
	return result;
}

void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_login(jchar *password) {
	VEEPORT_LOGGER_LOG_DBG("");

	/* Convert password to C string (this is the PKCS#11 PIN). */
	char *pw = NULL;
	size_t pw_len = 0;
	int conv_rc = llcrypto_eks_jchar_to_ascii_cstring(password, &pw, &pw_len);
	if (LLCRYPTO_SUCCESS != conv_rc) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s",
		                                              (LLCRYPTO_ERROR_OOM == conv_rc) ? "Out of memory" :
		                                              "PKCS#11 PIN must be ASCII");
		goto end;
	}

	if (g_p11.loaded) {
		/* Re-check instead of short-circuiting: the contract requires login()
		 * to throw when the password check fails, on every call. A second
		 * C_Login cannot do it -- login state is slot-scoped, so the token
		 * answers CKR_USER_ALREADY_LOGGED_IN whatever PIN is supplied, and a
		 * wrong PIN would count toward its lockout policy. */
		bool same = (pw_len == g_p11.pin_len) && (0 == CRYPTO_memcmp(pw, g_p11.pin, pw_len));
		if (!same) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_EXTERNAL_KEYSTORE_BAD_PASSWORD,
			                                              "PKCS#11 authentication failed");
		}
		goto end;
	}

	const char *token_label = LLCRYPTO_PKCS11_TOKEN;

	/* Cache PIN. Reject overlong PINs rather than silently truncating:
	 * a truncated PIN would fail the subsequent PKCS#11 login with an
	 * opaque "wrong PIN" error that gives no hint about the real cause. */
	if (pw_len >= sizeof(g_p11.pin)) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "PKCS#11 PIN is too long");
		goto end;
	}
	(void)memcpy(g_p11.pin, pw, pw_len);
	g_p11.pin[pw_len] = '\0';
	g_p11.pin_len = pw_len;
	/* The PIN now lives in g_p11.pin; scrub the copy here rather than at end:
	 * so it is not held across the provider setup below. */
	OPENSSL_cleanse(pw, pw_len);
	LLCRYPTO_free(pw);
	pw = NULL;

	/* Build base token URI. The token label can contain any UTF-8 character,
	 * so percent-encode per RFC 7512 to avoid attribute injection if the label
	 * happens to contain ';', '=' or other reserved chars. PKCS#11 v2.40 caps
	 * CKA_LABEL at 32 bytes; allow 3x for encoding plus NUL → 97 bytes is the
	 * worst case. */
	char encoded_label[LLCRYPTO_PCT_ENCODED_SIZE(LLCRYPTO_PKCS11_LABEL_MAX)];
	if (strlen(token_label) > LLCRYPTO_PKCS11_LABEL_MAX) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "PKCS#11 token label exceeds 32 bytes");
		goto end;
	}
	if (LLCRYPTO_SUCCESS != pct_encode_pk11(encoded_label, sizeof(encoded_label), token_label)) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "PKCS#11 token label too long");
		goto end;
	}
	(void)snprintf(g_p11.token_uri, sizeof(g_p11.token_uri),
	               "pkcs11:token=%s", encoded_label);

	VEEPORT_LOGGER_LOG_DBG("module=%s uri=%s", LLCRYPTO_PKCS11_MODULE, g_p11.token_uri);

	/* Configure the pkcs11-provider programmatically — no OPENSSL_CONF file and
	 * no inherited OPENSSL_MODULES are required. */
	if (LLCRYPTO_SUCCESS != configure_pkcs11_provider(LLCRYPTO_PKCS11_MODULE)) {
		goto end;
	}

	g_p11.loaded = true;

	/* Validate the PIN now via a real C_Login round-trip, per the LLAPI
	 * contract that login() must throw on a wrong password. Without this a
	 * bad PIN would only surface later from a confusing place (writer
	 * C_Login on the first setKeyEntry, or OSSL_STORE deep inside a
	 * getCertificateHandle), and could count toward the HSM's lockout
	 * counter at unpredictable points. We use a R/O session — login state
	 * is slot-scoped, so any later R/W session inherits the auth. */
	CK_SESSION_HANDLE validation_session = pkcs11_open_session_ro();
	if (CK_INVALID_HANDLE == validation_session) {
		/* pkcs11_open_session_ro has already thrown the NativeIOException.
		* Clear g_p11.loaded so the Java side can call login() again with a
		* different password; that also makes the shared scrub at end: reset
		* the cached PIN. g_p11.capi_loaded stays set: dlopen / C_Initialize /
		* slot resolution succeeded, no point redoing them on the retry. */
		g_p11.loaded = false;
		goto end;
	}
	pkcs11_close_session(validation_session);

	VEEPORT_LOGGER_LOG_DBG("PKCS#11 keystore initialized, uri=%s", g_p11.token_uri);

end:
	/* Single scrub point: every failure path before the PIN is cached reaches
	 * here with pw still owned, so a new one cannot forget to wipe it. */
	if (NULL != pw) {
		OPENSSL_cleanse(pw, pw_len);
		LLCRYPTO_free(pw);
	}
	/* Same for the cached PIN, which outlives this call only on a completed
	 * login: any path that leaves with g_p11.loaded still 0 either never
	 * cached it (scrubbing an already-empty buffer is harmless) or cached it
	 * and then failed, which must not leave the secret in global memory. */
	if (!g_p11.loaded) {
		OPENSSL_cleanse(g_p11.pin, sizeof(g_p11.pin));
		g_p11.pin_len = 0;
	}
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_size(void) {
	VEEPORT_LOGGER_LOG_DBG("");
	jint result = SNI_IGNORED_RETURNED_VALUE;

	if (!g_p11.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	int alias_count = get_cached_aliases();
	if (alias_count < 0) {
		goto end; /* enumerate_aliases_via_pkcs11 has already thrown */
	}

	VEEPORT_LOGGER_LOG_DBG("%d entries", alias_count);
	result = (jint)alias_count;

end:
	return result;
}

/*
 * The alias is copied out only once it is known to fit. enumerate_aliases_via_pkcs11 accepts a
 * CKA_LABEL of up to LLCRYPTO_EKS_MAX_ALIAS_LEN - 1 bytes, while the Java side sizes this array
 * from the ej.crypto.externalks.alias.max.length constant — a far smaller value by default — so
 * the two are not interchangeable and only the array's own length can bound the copy.
 */
jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getAlias(jint alias_index, jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("index=%d", (int)alias_index);
	jint result = LLCRYPTO_ERROR;

	if (!g_p11.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	int alias_count = get_cached_aliases();
	if ((alias_count < 0) || (alias_index < 0) || (alias_index >= alias_count)) {
		goto end;
	}

	/* One past the alias for the terminator the Java side scans for. */
	size_t alias_size = strlen(g_p11.aliases[alias_index]) + 1U;
	if (!sni_array_contains_range(alias, 0, (int32_t)alias_size)) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "Alias too long for the caller's buffer");
		goto end;
	}

	(void)strcpy((char *)alias, g_p11.aliases[alias_index]);
	result = LLCRYPTO_SUCCESS;
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);

end:
	return result;
}

jboolean LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_containsAlias(jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jboolean result = (jboolean)JFALSE;

	if (!g_p11.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	int alias_count = get_cached_aliases();

	for (int i = 0; i < alias_count; i++) {
		if (0 == strcasecmp(g_p11.aliases[i], (const char *)alias)) {
			result = (jboolean)JTRUE;
			goto end;
		}
	}

end:
	return result;
}

// -----------------------------------------------------------------------------
// ECDH key agreement (direct C API)
// -----------------------------------------------------------------------------

int llcrypto_eks_ecdh_derive(char *alias, const uint8_t *peer_point, size_t peer_point_len,
                             uint8_t *secret_out, size_t *secret_out_len) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", alias);
	int result = LLCRYPTO_ERROR;

	CK_SESSION_HANDLE session = pkcs11_open_session_ro();
	if (CK_INVALID_HANDLE == session) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end; /* exception already thrown */
	}

	/* Locate the EC private key by label. The token also holds a certificate
	 * under the same label, so filter on CKA_CLASS to avoid matching it. */
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE find_templ[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_LABEL, alias, (CK_ULONG)strlen(alias) },
	};
	CK_OBJECT_HANDLE priv_handle = CK_INVALID_HANDLE;
	CK_ULONG found = 0;
	CK_RV rv = g_p11.funcs->C_FindObjectsInit(session, find_templ,
	                                          (CK_ULONG)(sizeof(find_templ) / sizeof(find_templ[0])));
	if (CKR_OK == rv) {
		rv = g_p11.funcs->C_FindObjects(session, &priv_handle, 1, &found);
		(void)g_p11.funcs->C_FindObjectsFinal(session);
	}
	if ((CKR_OK != rv) || (1U != found)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "ECDH private key not found on token");
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'out_close' */
		goto out_close;
	}

	/* CKD_NULL returns the raw x-coordinate. The peer point is passed raw
	 * uncompressed (0x04 || X || Y), the PKCS#11 v2.40 mandatory form every
	 * conformant token accepts; it also sidesteps the DER-wrapper mis-parse
	 * that is specific to the OP-TEE TA. */
	CK_ECDH1_DERIVE_PARAMS ecdh_params = {
		.kdf = CKD_NULL,
		.ulSharedDataLen = 0,
		.pSharedData = NULL,
		.ulPublicDataLen = (CK_ULONG)peer_point_len,
		/* cppcheck-suppress misra-c2012-11.8 ; ck_ecdh1_derive_params.public_data is a non-const
		 * unsigned char*, and the PKCS#11 header is third-party. The token only reads the point. */
		.pPublicData = (CK_BYTE_PTR)peer_point,
	};
	CK_MECHANISM mech = { CKM_ECDH1_DERIVE, &ecdh_params, sizeof(ecdh_params) };

	/* Derive a session-scoped, extractable generic-secret so CKA_VALUE can be
	 * read back into the caller's buffer. CKA_VALUE_LEN (the curve field size)
	 * is what PKCS#11 requires for a variable-length key type: a token cannot
	 * infer a generic-secret's length, and one that will not default it rejects
	 * the derive outright — the OP-TEE TA answers with a vendor error. */
	CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
	CK_KEY_TYPE secret_type = CKK_GENERIC_SECRET;
	CK_ULONG ck_value_len = (CK_ULONG)*secret_out_len;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;
	CK_ATTRIBUTE derived_templ[] = {
		{ CKA_CLASS, &secret_class, sizeof(secret_class) },
		{ CKA_KEY_TYPE, &secret_type, sizeof(secret_type) },
		{ CKA_VALUE_LEN, &ck_value_len, sizeof(ck_value_len) },
		{ CKA_TOKEN, &ck_false, sizeof(ck_false) },
		{ CKA_SENSITIVE, &ck_false, sizeof(ck_false) },
		{ CKA_EXTRACTABLE, &ck_true, sizeof(ck_true) },
	};
	CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
	rv = g_p11.funcs->C_DeriveKey(session, &mech, priv_handle, derived_templ,
	                              (CK_ULONG)(sizeof(derived_templ) / sizeof(derived_templ[0])), &derived);
	if (CKR_OK != rv) {
		VEEPORT_LOGGER_LOG_ERR("C_DeriveKey failed: 0x%lx", (unsigned long)rv);
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "ECDH key derivation failed");
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'out_close' */
		goto out_close;
	}

	/* Size CKA_VALUE first, bounds-check against the caller buffer, then copy. */
	CK_ATTRIBUTE value_attr = { CKA_VALUE, NULL, 0 };
	rv = g_p11.funcs->C_GetAttributeValue(session, derived, &value_attr, 1);
	if ((CKR_OK != rv) || (0U == value_attr.ulValueLen) || (value_attr.ulValueLen > (CK_ULONG)*secret_out_len)) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Cannot size derived ECDH secret");
		goto out_destroy;
	}
	value_attr.pValue = secret_out;
	rv = g_p11.funcs->C_GetAttributeValue(session, derived, &value_attr, 1);
	if (CKR_OK != rv) {
		VEEPORT_ERRORS_throw_runtime_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                               "Cannot read derived ECDH secret");
		goto out_destroy;
	}
	*secret_out_len = (size_t)value_attr.ulValueLen;
	result = LLCRYPTO_SUCCESS;

out_destroy:
	(void)g_p11.funcs->C_DestroyObject(session, derived);
out_close:
	pkcs11_close_session(session);
end:
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Key
// -----------------------------------------------------------------------------

/**
 * Look for an asymmetric private key under @p alias, through OSSL_STORE.
 *
 * pkcs11-provider exposes only EVP_PKEY-shaped objects, so this finds an RSA,
 * EC or Ed* private key, but never a CKO_SECRET_KEY.
 *
 * @param[in] alias the entry name to look for.
 * @param[out] decided set when this path reached a conclusion, so the caller
 *             must not look for a secret key. It is set when a key is returned
 *             and when the attempt fails with an exception.
 * @return the key handle, or LLCRYPTO_ERROR.
 */
static jint eks_private_key_from_store(jbyte *alias, bool *decided) {
	jint result = LLCRYPTO_ERROR;
	*decided = false;

	char uri[LLCRYPTO_PKCS11_URI_MAX];
	if (LLCRYPTO_SUCCESS != build_pkcs11_uri(uri, sizeof(uri), (const char *)alias, "private")) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Alias too long for PKCS#11 URI");
		*decided = true;
		goto end;
	}

	/* Do not log the URI — it contains ;pin-value=<PIN>. */
	OSSL_STORE_CTX *sctx = OSSL_STORE_open_ex(uri, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (NULL == sctx) {
		/* No asymmetric store for this alias. The secret-key path still applies. */
		ERR_clear_error();
		goto end;
	}

	/* The walk only looks for the key. Its condition states when the search is
	 * over, so it needs no exit of its own. */
	EVP_PKEY *pkey = NULL;
	while ((NULL == pkey) && !OSSL_STORE_eof(sctx)) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);
		if (NULL == info) {
			/* OSSL_STORE_load gives NULL on an error and at the end of the data.
			 * OSSL_STORE_eof reports 1 for both, so the condition above ends the walk. */
			unsigned long err = ERR_peek_last_error();
			if (0U != err) {
				char err_buf[256];
				ERR_error_string_n(err, err_buf, sizeof(err_buf));
				VEEPORT_LOGGER_LOG_DBG("OSSL_STORE_load returned NULL, err=%s", err_buf);
			}
			ERR_clear_error();
		} else {
			if (OSSL_STORE_INFO_PKEY == OSSL_STORE_INFO_get_type(info)) {
				pkey = OSSL_STORE_INFO_get1_PKEY(info);
			}
			OSSL_STORE_INFO_free(info);
		}
	}

	if (NULL != pkey) {
		/* pkcs11-provider pushes an error when it fails to cache the key in the session
		 * (CKR_SESSION_READ_ONLY on OP-TEE), and still returns the key. */
		ERR_clear_error();
		VEEPORT_LOGGER_LOG_DBG("got EVP_PKEY base_id=%d", EVP_PKEY_base_id(pkey));
		*decided = true;
		struct llcrypto_key *key = llcrypto_key_from_evp_pkey(pkey);
		if (NULL == key) {
			EVP_PKEY_free(pkey);
		} else {
			/* Cache the alias so key agreement can derive via the direct PKCS#11 C
			 * API instead of the pkcs11-provider, whose DER-wrapped ECDH peer point
			 * the OP-TEE TA mis-parses. */
			key->alias = LLCRYPTO_strdup((const char *)alias);
			if (NULL == key->alias) {
				llcrypto_key_free(key);
				VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
				                                              "Out of memory caching key alias");
			} else {
				VEEPORT_LOGGER_LOG_DBG("returning key_id=%p", (void *)key);
				result = (jint)key;
			}
		}
	}
	(void)OSSL_STORE_close(sctx);

end:
	return result;
}

/**
 * Look for a symmetric key under @p alias, through the PKCS#11 C API.
 *
 * A CKO_SECRET_KEY cannot come through OSSL_STORE, because OSSL_STORE_INFO has
 * no SECRET or SYMKEY type. This uses the same module and the same session
 * pool as the store, only a different API surface.
 *
 * @param[in] alias the entry name to look for.
 * @return the key handle, or LLCRYPTO_ERROR.
 */
static jint eks_secret_key_from_token(jbyte *alias) {
	jint result = LLCRYPTO_ERROR;
	/* Declared before the first goto: the end label releases both. */
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	uint8_t *val = NULL;
	CK_ULONG val_length = 0;

	if (LLCRYPTO_SUCCESS != pkcs11_capi_init()) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end;
	}

	session = pkcs11_open_session_ro();
	if (CK_INVALID_HANDLE == session) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end;
	}

	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_ATTRIBUTE templ[] = {
		{ CKA_CLASS, &class, sizeof(class) },
		{ CKA_LABEL, alias, (CK_ULONG)strlen((const char *)alias) },
	};
	if (CKR_OK != g_p11.funcs->C_FindObjectsInit(session, templ, sizeof(templ) / sizeof(templ[0]))) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end;
	}

	CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
	CK_ULONG found = 0;
	(void)g_p11.funcs->C_FindObjects(session, &obj, 1, &found);
	(void)g_p11.funcs->C_FindObjectsFinal(session);
	if (1U != found) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end;
	}

	/* Probe the value length first, then read the bytes — sizing up-front keeps
	 * us from allocating worst-case buffers. */
	CK_ATTRIBUTE size_attr = { CKA_VALUE, NULL, 0 };
	if ((CKR_OK != g_p11.funcs->C_GetAttributeValue(session, obj, &size_attr, 1))
	    || (0U == size_attr.ulValueLen)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end;
	}

	val = (uint8_t *)LLCRYPTO_calloc(1, size_attr.ulValueLen);
	if (NULL == val) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end;
	}
	val_length = size_attr.ulValueLen;

	CK_KEY_TYPE ktype = 0;
	CK_ATTRIBUTE read[] = {
		{ CKA_VALUE, val, val_length },
		{ CKA_KEY_TYPE, &ktype, sizeof(ktype) },
	};
	if (CKR_OK == g_p11.funcs->C_GetAttributeValue(session, obj, read, 2)) {
		const uint8_t *algo = (CKK_AES == ktype) ? (const uint8_t *)"AES" : (const uint8_t *)"RAW";
		struct llcrypto_key *key = llcrypto_key_from_secret_key(val, (size_t)val_length, algo);
		if (NULL != key) {
			result = (jint)key;
		}
	}

end:
	if (NULL != val) {
		/* Raw CKA_VALUE read off the token. */
		OPENSSL_cleanse(val, (size_t)val_length);
		LLCRYPTO_free(val);
	}
	if (CK_INVALID_HANDLE != session) {
		pkcs11_close_session(session);
	}
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyId(jbyte *alias, jchar *password) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;

	LLCRYPTO_UNUSED_PARAM(password);

	if (!g_p11.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
	} else {
		/* Asymmetric first. Only when that path draws no conclusion does the
		 * alias still possibly name a secret key. */
		bool decided = false;
		result = eks_private_key_from_store(alias, &decided);
		if (!decided) {
			result = eks_secret_key_from_token(alias);
		}
	}

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
			/* Provider-backed keys may not support private_check/public_check.
			 * For PKCS#11 private keys loaded via type=private, assume private. */
			ERR_clear_error();
			result = (jint)LLCRYPTO_KEY_TYPE_PRIVATE;
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

/* getKeyAlgorithm, getCertificateSize, getCertificateData, getCertificateChainLength,
 * getCertificateFromChain are all backend-agnostic — implemented in
 * LLCRYPTO_EXTERNAL_KEYSTORE_common.c. */

// -----------------------------------------------------------------------------
// Key Store Certificate
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateHandle(jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;

	if (!g_p11.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		goto end;
	}

	char uri[LLCRYPTO_PKCS11_URI_MAX];
	if (LLCRYPTO_SUCCESS != build_pkcs11_uri(uri, sizeof(uri), (const char *)alias, "cert")) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Alias too long for PKCS#11 URI");
		goto end;
	}

	/* Do not log the URI — it contains ;pin-value=<PIN>. */
	OSSL_STORE_CTX *sctx = OSSL_STORE_open_ex(uri, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (NULL == sctx) {
		ERR_clear_error();
		goto end;
	}

	/* Same shape as eks_private_key_from_store: the walk only looks for the
	 * certificate, so its condition is the only way out. */
	X509 *cert = NULL;
	while ((NULL == cert) && !OSSL_STORE_eof(sctx)) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(sctx);
		if (NULL == info) {
			/* NULL means an error or the end of the data, and OSSL_STORE_eof
			 * reports 1 for both. */
			ERR_clear_error();
		} else {
			if (OSSL_STORE_INFO_CERT == OSSL_STORE_INFO_get_type(info)) {
				cert = OSSL_STORE_INFO_get1_CERT(info);
			}
			OSSL_STORE_INFO_free(info);
		}
	}

	if (NULL != cert) {
		struct llcrypto_eks_cert *h = llcrypto_eks_x509_to_cert(cert);
		X509_free(cert);
		if (NULL != h) {
			if (SNI_OK == SNI_registerResource(h, (SNI_closeFunction)llcrypto_eks_cert_free, NULL)) {
				VEEPORT_LOGGER_LOG_DBG("handle=%p size=%d", (void *)h, h->der_length);
				result = (jint)h;
			} else {
				LLCRYPTO_free(h->der_data);
				LLCRYPTO_free(h);
			}
		}
	}
	(void)OSSL_STORE_close(sctx);

end:
	return result;
}

// -----------------------------------------------------------------------------
// Key Store Certificate Chain
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainHandle(jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;
	X509 *all_certs[LLCRYPTO_EKS_MAX_OBJECTS];
	char cert_labels[LLCRYPTO_EKS_MAX_OBJECTS][LLCRYPTO_EKS_MAX_ALIAS_LEN];
	int total_certs = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	if (!g_p11.loaded) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Keystore not loaded");
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end;
	}
	if (LLCRYPTO_SUCCESS != pkcs11_capi_init()) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end;
	}

	/* Collect every CKO_CERTIFICATE on the token via a single C_FindObjects
	 * call. Querying by alias is wrong here: setKeyEntry stores chain certs
	 * with `<alias>-chain-N` labels and the alias enumerator hides those
	 * from the user-facing alias list, so a per-alias collection misses
	 * them and llcrypto_eks_build_chain finds no parents to walk. Reading
	 * CKA_VALUE directly avoids OSSL_STORE entirely and trivially picks up
	 * every cert regardless of label shape. */
	/* Certs are typically PKCS#11-public, but a token may be configured to
	 * require a session login before any read at all, so the session is opened
	 * logged in. That login must succeed: see pkcs11_open_session(). */
	session = pkcs11_open_session_ro();
	if (CK_INVALID_HANDLE == session) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'end' */
		goto end;
	}

	CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE find_templ[] = {
		{ CKA_CLASS, &cert_class, sizeof(cert_class) },
	};
	if (g_p11.funcs->C_FindObjectsInit(session, find_templ,
	                                   (CK_ULONG)(sizeof(find_templ) / sizeof(find_templ[0]))) != CKR_OK) {
		goto end;
	}
	CK_OBJECT_HANDLE handles[LLCRYPTO_EKS_MAX_OBJECTS];
	CK_ULONG found = 0;
	CK_RV rv = g_p11.funcs->C_FindObjects(session, handles, LLCRYPTO_EKS_MAX_OBJECTS, &found);
	(void)g_p11.funcs->C_FindObjectsFinal(session);
	if (CKR_OK != rv) {
		goto end;
	}

	for (CK_ULONG i = 0; (i < found) && (total_certs < LLCRYPTO_EKS_MAX_OBJECTS); i++) {
		/* Probe label and value sizes first so we can skip oversized labels
		 * cleanly and size the value buffer exactly. */
		char label[LLCRYPTO_EKS_MAX_ALIAS_LEN];
		CK_ATTRIBUTE size_attrs[] = {
			{ CKA_LABEL, label, sizeof(label) - 1U },
			{ CKA_VALUE, NULL, 0 },
		};
		if (CKR_OK != g_p11.funcs->C_GetAttributeValue(session, handles[i], size_attrs, 2)) {
			continue;
		}
		if ((0U == size_attrs[0].ulValueLen) || (size_attrs[0].ulValueLen >= sizeof(label))
		    || (0U == size_attrs[1].ulValueLen)) {
			continue;
		}
		label[size_attrs[0].ulValueLen] = '\0';

		uint8_t *der = (uint8_t *)LLCRYPTO_calloc(1, size_attrs[1].ulValueLen);
		if (NULL == der) {
			continue;
		}
		CK_ATTRIBUTE val_attr = { CKA_VALUE, der, size_attrs[1].ulValueLen };
		if (CKR_OK != g_p11.funcs->C_GetAttributeValue(session, handles[i], &val_attr, 1)) {
			LLCRYPTO_free(der);
			continue;
		}
		const unsigned char *p = der;
		X509 *cert = d2i_X509(NULL, &p, (long)val_attr.ulValueLen);
		LLCRYPTO_free(der);
		if (NULL == cert) {
			ERR_clear_error();
			continue;
		}
		all_certs[total_certs] = cert;
		(void)memcpy(cert_labels[total_certs], label, size_attrs[0].ulValueLen + 1U);
		total_certs++;
	}

	VEEPORT_LOGGER_LOG_DBG("collected %d certs (CKO_CERTIFICATE walk)", total_certs);

	struct llcrypto_eks_chain *chain = llcrypto_eks_build_chain(
		(const char *)alias, all_certs, cert_labels, total_certs);

	for (int i = 0; i < total_certs; i++) {
		X509_free(all_certs[i]);
	}

	if (NULL != chain) {
		VEEPORT_LOGGER_LOG_DBG("chain handle=%p count=%d", (void *)chain, chain->cert_count);
		result = (jint)chain;
	}

end:
	pkcs11_close_session(session);
	return result;
}

// -----------------------------------------------------------------------------
// Write path: object-creation helpers
// -----------------------------------------------------------------------------

/** SHA-1 of @p alias used as the object's CKA_ID. PKCS#11 conventionally links
 *  a key and its certificate by sharing one CKA_ID; deriving it deterministically
 *  from the alias means setKeyEntry / setCertificateEntry on the same alias
 *  always produce matched key/cert pairs without us having to track IDs. */
static int derive_cka_id(const char *alias, unsigned char *out_id, unsigned int *out_len) {
	int result = LLCRYPTO_ERROR;
	unsigned int len = 0;
	if (1 != EVP_Digest(alias, strlen(alias), out_id, &len, EVP_sha1(), NULL)) {
		goto end;
	}
	*out_len = len;
	result = LLCRYPTO_SUCCESS;

end:
	return result;
}

/**
 * Create one X.509 certificate object on the token. Pulls subject/issuer/serial
 * out of @p cert (PKCS#11 expects them present even though @c CKA_VALUE alone
 * carries the full DER; some modules reject the create otherwise).
 */
static int writer_create_certificate(CK_SESSION_HANDLE session, char *alias,
                                     unsigned char *id, unsigned int id_len,
                                     X509 *cert, CK_OBJECT_HANDLE *out_handle) {
	int result = LLCRYPTO_ERROR;
	unsigned char *der = NULL;
	int der_len = i2d_X509(cert, &der);
	if (der_len <= 0) {
		return LLCRYPTO_ERROR;
	}

	unsigned char *subj_der = NULL;
	int subj_len = i2d_X509_NAME(X509_get_subject_name(cert), &subj_der);
	unsigned char *iss_der = NULL;
	int iss_len = i2d_X509_NAME(X509_get_issuer_name(cert), &iss_der);
	unsigned char *serial_der = NULL;
	int serial_len = i2d_ASN1_INTEGER(X509_get_serialNumber(cert), &serial_der);

	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE ctype = CKC_X_509;
	CK_BBOOL ck_true = CK_TRUE;

	CK_ATTRIBUTE templ[] = {
		{ CKA_CLASS, &class, sizeof(class) },
		{ CKA_CERTIFICATE_TYPE, &ctype, sizeof(ctype) },
		{ CKA_TOKEN, &ck_true, sizeof(ck_true) },
		{ CKA_LABEL, alias, (CK_ULONG)strlen(alias) },
		{ CKA_ID, id, id_len },
		{ CKA_SUBJECT, subj_der, (CK_ULONG)((subj_len > 0) ? subj_len : 0) },
		{ CKA_ISSUER, iss_der, (CK_ULONG)((iss_len > 0) ? iss_len : 0) },
		{ CKA_SERIAL_NUMBER, serial_der, (CK_ULONG)((serial_len > 0) ? serial_len : 0) },
		{ CKA_VALUE, der, (CK_ULONG)der_len },
	};

	CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
	CK_RV rv = g_p11.funcs->C_CreateObject(session, templ,
	                                       (CK_ULONG)(sizeof(templ) / sizeof(templ[0])),
	                                       &obj);
	if (CKR_OK == rv) {
		VEEPORT_LOGGER_LOG_DBG("cert '%s' created, handle=%lu", alias, (unsigned long)obj);
		if (NULL != out_handle) {
			*out_handle = obj;
		}
		result = LLCRYPTO_SUCCESS;
	} else {
		VEEPORT_LOGGER_LOG_ERR("C_CreateObject(cert '%s') failed: 0x%lx", alias, (unsigned long)rv);
	}

	OPENSSL_free(der);
	OPENSSL_free(subj_der);
	OPENSSL_free(iss_der);
	OPENSSL_free(serial_der);
	return result;
}

/** A heap buffer holding one key component, with its length so it can be wiped. */
struct bn_buf {
	unsigned char *data;
	size_t length;
};

/** Push a BIGNUM as a fresh CKA_* attribute. The buffer is owned by the
 *  caller's allocation list (@p heap_buf set on success) so it can be freed
 *  after C_CreateObject. */
static int push_bn_attr(CK_ATTRIBUTE *attr, CK_ATTRIBUTE_TYPE type, const BIGNUM *bn,
                        struct bn_buf *heap_buf) {
	int len = BN_num_bytes(bn);
	unsigned char *buf = (unsigned char *)LLCRYPTO_calloc(1, ((size_t)len > 0U) ? (size_t)len : 1U);
	if (NULL == buf) {
		return LLCRYPTO_ERROR;
	}
	(void)BN_bn2bin(bn, buf);
	attr->type = type;
	attr->pValue = buf;
	attr->ulValueLen = (CK_ULONG)len;
	heap_buf->data = buf;
	heap_buf->length = (size_t)len;
	return LLCRYPTO_SUCCESS;
}

/** Cleanse and free an array of heap buffers built by push_bn_attr. Most of them hold
 *  an RSA private component in plaintext, so all are wiped before being freed. */
static void free_bn_bufs(struct bn_buf *bufs, int buf_count) {
	for (int i = 0; i < buf_count; i++) {
		if (NULL != bufs[i].data) {
			OPENSSL_cleanse(bufs[i].data, bufs[i].length);
			LLCRYPTO_free(bufs[i].data);
		}
	}
}

/**
 * Decompose an RSA EVP_PKEY and create the matching CKO_PRIVATE_KEY object on
 * the token. Returns 0 on success, -1 on any failure (no exception thrown).
 */
static int writer_create_rsa_private_key(CK_SESSION_HANDLE session, char *alias,
                                         unsigned char *id, unsigned int id_len,
                                         EVP_PKEY *pkey, CK_OBJECT_HANDLE *out_handle) {
	int result = LLCRYPTO_ERROR;
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	BIGNUM *d = NULL;
	BIGNUM *p = NULL;
	BIGNUM *q = NULL;
	BIGNUM *dmp1 = NULL;
	BIGNUM *dmq1 = NULL;
	BIGNUM *iqmp = NULL;
	struct bn_buf bufs[8] = { 0 };

	if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}

	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE ktype = CKK_RSA;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_sensitive = LLCRYPTO_PKCS11_KEY_SENSITIVE;
	CK_BBOOL ck_extractable = LLCRYPTO_PKCS11_KEY_EXTRACTABLE;

	/* CKA_SENSITIVE / CKA_EXTRACTABLE come from the build flag
	 * LLCRYPTO_PKCS11_NON_EXTRACTABLE_KEYS (default: extractable, for testsuite
	 * round-trip; flip ON for HSM-grade deployments). */
	CK_ATTRIBUTE templ[19] = {
		{ CKA_CLASS, &class, sizeof(class) },
		{ CKA_KEY_TYPE, &ktype, sizeof(ktype) },
		{ CKA_TOKEN, &ck_true, sizeof(ck_true) },
		{ CKA_PRIVATE, &ck_true, sizeof(ck_true) },
		{ CKA_SENSITIVE, &ck_sensitive, sizeof(ck_sensitive) },
		{ CKA_EXTRACTABLE, &ck_extractable, sizeof(ck_extractable) },
		{ CKA_DECRYPT, &ck_true, sizeof(ck_true) },
		{ CKA_SIGN, &ck_true, sizeof(ck_true) },
		{ CKA_UNWRAP, &ck_true, sizeof(ck_true) },
		{ CKA_LABEL, alias, (CK_ULONG)strlen(alias) },
		{ CKA_ID, id, id_len },
		/* The last 8 slots hold the RSA components. push_bn_attr allocates, so each
		 * one is filled on its own below and can fail. They are initialized here
		 * because rule 9.3 does not permit a partial array initializer. */
		{ 0, NULL, 0 }, { 0, NULL, 0 }, { 0, NULL, 0 }, { 0, NULL, 0 },
		{ 0, NULL, 0 }, { 0, NULL, 0 }, { 0, NULL, 0 }, { 0, NULL, 0 },
	};

	if (LLCRYPTO_SUCCESS != push_bn_attr(&templ[11], CKA_MODULUS, n, &bufs[0])) {
		goto cleanup;
	}
	if (LLCRYPTO_SUCCESS != push_bn_attr(&templ[12], CKA_PUBLIC_EXPONENT, e, &bufs[1])) {
		goto cleanup;
	}
	if (LLCRYPTO_SUCCESS != push_bn_attr(&templ[13], CKA_PRIVATE_EXPONENT, d, &bufs[2])) {
		goto cleanup;
	}
	if (LLCRYPTO_SUCCESS != push_bn_attr(&templ[14], CKA_PRIME_1, p, &bufs[3])) {
		goto cleanup;
	}
	if (LLCRYPTO_SUCCESS != push_bn_attr(&templ[15], CKA_PRIME_2, q, &bufs[4])) {
		goto cleanup;
	}
	if (LLCRYPTO_SUCCESS != push_bn_attr(&templ[16], CKA_EXPONENT_1, dmp1, &bufs[5])) {
		goto cleanup;
	}
	if (LLCRYPTO_SUCCESS != push_bn_attr(&templ[17], CKA_EXPONENT_2, dmq1, &bufs[6])) {
		goto cleanup;
	}
	if (LLCRYPTO_SUCCESS != push_bn_attr(&templ[18], CKA_COEFFICIENT, iqmp, &bufs[7])) {
		goto cleanup;
	}

	CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
	CK_RV rv = g_p11.funcs->C_CreateObject(session, templ,
	                                       (CK_ULONG)(sizeof(templ) / sizeof(templ[0])),
	                                       &obj);
	if (CKR_OK == rv) {
		VEEPORT_LOGGER_LOG_DBG("RSA private key '%s' created, handle=%lu", alias, (unsigned long)obj);
		if (NULL != out_handle) {
			*out_handle = obj;
		}
		result = LLCRYPTO_SUCCESS;
	} else {
		VEEPORT_LOGGER_LOG_ERR("C_CreateObject(RSA priv '%s') failed: 0x%lx", alias, (unsigned long)rv);
	}

cleanup:
	/* Everything but the modulus and the public exponent is private key material, so it
	 * is wiped rather than just released. */
	free_bn_bufs(bufs, 8);
	BN_free(n);
	BN_free(e);
	BN_clear_free(d);
	BN_clear_free(p);
	BN_clear_free(q);
	BN_clear_free(dmp1);
	BN_clear_free(dmq1);
	BN_clear_free(iqmp);
	return result;
}

/**
 * Decompose an EC EVP_PKEY and create the matching CKO_PRIVATE_KEY object.
 * CKA_EC_PARAMS is the DER-encoded named-curve OID; CKA_VALUE is the private
 * scalar.
 */
static int writer_create_ec_private_key(CK_SESSION_HANDLE session, char *alias,
                                        unsigned char *id, unsigned int id_len,
                                        EVP_PKEY *pkey, CK_OBJECT_HANDLE *out_handle) {
	int result = LLCRYPTO_ERROR;
	BIGNUM *priv_bn = NULL;
	unsigned char *priv_buf = NULL;
	int priv_len = 0;
	unsigned char *params_der = NULL;

	char curve_name[64] = { 0 };
	size_t curve_name_len = 0;
	if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
	                                   curve_name, sizeof(curve_name), &curve_name_len) != 1) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	int nid = OBJ_txt2nid(curve_name);
	if (NID_undef == nid) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	ASN1_OBJECT *obj_oid = OBJ_nid2obj(nid);
	int params_len = i2d_ASN1_OBJECT(obj_oid, &params_der);
	if (params_len <= 0) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}

	if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn)) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	priv_len = BN_num_bytes(priv_bn);
	priv_buf = (unsigned char *)LLCRYPTO_calloc(1, ((size_t)priv_len > 0U) ? (size_t)priv_len : 1U);
	if (NULL == priv_buf) {
		/* cppcheck-suppress misra-c2012-15.2 ; cppcheck 2.21 false positive: goto jumps forward to 'cleanup' */
		goto cleanup;
	}
	(void)BN_bn2bin(priv_bn, priv_buf);

	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE ktype = CKK_EC;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_sensitive = LLCRYPTO_PKCS11_KEY_SENSITIVE;
	CK_BBOOL ck_extractable = LLCRYPTO_PKCS11_KEY_EXTRACTABLE;

	CK_ATTRIBUTE templ[] = {
		{ CKA_CLASS, &class, sizeof(class) },
		{ CKA_KEY_TYPE, &ktype, sizeof(ktype) },
		{ CKA_TOKEN, &ck_true, sizeof(ck_true) },
		{ CKA_PRIVATE, &ck_true, sizeof(ck_true) },
		/* See RSA writer for the SENSITIVE/EXTRACTABLE rationale. */
		{ CKA_SENSITIVE, &ck_sensitive, sizeof(ck_sensitive) },
		{ CKA_EXTRACTABLE, &ck_extractable, sizeof(ck_extractable) },
		{ CKA_SIGN, &ck_true, sizeof(ck_true) },
		{ CKA_DERIVE, &ck_true, sizeof(ck_true) },
		{ CKA_LABEL, alias, (CK_ULONG)strlen(alias) },
		{ CKA_ID, id, id_len },
		{ CKA_EC_PARAMS, params_der, (CK_ULONG)params_len },
		{ CKA_VALUE, priv_buf, (CK_ULONG)priv_len },
	};

	CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
	CK_RV rv = g_p11.funcs->C_CreateObject(session, templ,
	                                       (CK_ULONG)(sizeof(templ) / sizeof(templ[0])),
	                                       &handle);
	if (CKR_OK == rv) {
		VEEPORT_LOGGER_LOG_DBG("EC private key '%s' created (curve=%s)", alias, curve_name);
		if (NULL != out_handle) {
			*out_handle = handle;
		}
		result = LLCRYPTO_SUCCESS;
	} else {
		VEEPORT_LOGGER_LOG_ERR("C_CreateObject(EC priv '%s') failed: 0x%lx", alias, (unsigned long)rv);
	}

cleanup:
	OPENSSL_free(params_der);
	if (NULL != priv_buf) {
		/* The EC private scalar, in plaintext. */
		OPENSSL_cleanse(priv_buf, (size_t)priv_len);
		LLCRYPTO_free(priv_buf);
	}
	BN_clear_free(priv_bn);
	return result;
}

/** Create a CKO_SECRET_KEY object (AES). */
static int writer_create_secret_key(CK_SESSION_HANDLE session, char *alias,
                                    unsigned char *id, unsigned int id_len,
                                    uint8_t *key_bytes, size_t key_len,
                                    const char *algorithm, CK_OBJECT_HANDLE *out_handle) {
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_KEY_TYPE ktype = CKK_GENERIC_SECRET;
	if ((NULL != algorithm) && (0 == strcasecmp(algorithm, "AES"))) {
		ktype = CKK_AES;
	}
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_sensitive = LLCRYPTO_PKCS11_KEY_SENSITIVE;
	CK_BBOOL ck_extractable = LLCRYPTO_PKCS11_KEY_EXTRACTABLE;

	CK_ATTRIBUTE templ[] = {
		{ CKA_CLASS, &class, sizeof(class) },
		{ CKA_KEY_TYPE, &ktype, sizeof(ktype) },
		{ CKA_TOKEN, &ck_true, sizeof(ck_true) },
		{ CKA_PRIVATE, &ck_true, sizeof(ck_true) },
		/* See RSA writer for the SENSITIVE/EXTRACTABLE rationale. */
		{ CKA_SENSITIVE, &ck_sensitive, sizeof(ck_sensitive) },
		{ CKA_EXTRACTABLE, &ck_extractable, sizeof(ck_extractable) },
		{ CKA_ENCRYPT, &ck_true, sizeof(ck_true) },
		{ CKA_DECRYPT, &ck_true, sizeof(ck_true) },
		{ CKA_LABEL, alias, (CK_ULONG)strlen(alias) },
		{ CKA_ID, id, id_len },
		{ CKA_VALUE, key_bytes, (CK_ULONG)key_len },
	};

	CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
	CK_RV rv = g_p11.funcs->C_CreateObject(session, templ,
	                                       (CK_ULONG)(sizeof(templ) / sizeof(templ[0])),
	                                       &handle);
	if (CKR_OK != rv) {
		VEEPORT_LOGGER_LOG_ERR("C_CreateObject(secret '%s') failed: 0x%lx", alias, (unsigned long)rv);
		return LLCRYPTO_ERROR;
	}
	VEEPORT_LOGGER_LOG_DBG("secret key '%s' created", alias);
	if (NULL != out_handle) {
		*out_handle = handle;
	}
	return LLCRYPTO_SUCCESS;
}

/**
 * Decompose an EVP_PKEY private key and create the right kind of PKCS#11 object.
 * Currently supports RSA and EC (the algorithms exercised by the testsuite); EdDSA
 * could be added by extending writer_create_ec_private_key with curve handling.
 */
static int writer_create_private_key_from_pkey(CK_SESSION_HANDLE session, char *alias,
                                               unsigned char *id, unsigned int id_len,
                                               EVP_PKEY *pkey, CK_OBJECT_HANDLE *out_handle) {
	int base_id = EVP_PKEY_base_id(pkey);
	if (EVP_PKEY_RSA == base_id) {
		return writer_create_rsa_private_key(session, alias, id, id_len, pkey, out_handle);
	}
	if (EVP_PKEY_EC == base_id) {
		return writer_create_ec_private_key(session, alias, id, id_len, pkey, out_handle);
	}
	VEEPORT_LOGGER_LOG_ERR("unsupported EVP_PKEY base_id=%d", base_id);
	return LLCRYPTO_ERROR;
}

/**
 * Parse a "key in protected format" blob and return an EVP_PKEY private key.
 * The data is either:
 *   * An unencrypted PKCS#8 PrivateKeyInfo, or
 *   * A PBES2-encrypted PKCS#8 (EncryptedPrivateKeyInfo) — we try the cached
 *     keystore PIN as the PBES2 password.
 *
 * Caller frees with EVP_PKEY_free.
 */
static EVP_PKEY *parse_protected_key(const uint8_t *data, int32_t len) {
	EVP_PKEY *result = NULL;
	const unsigned char *p = data;
	/* Try unencrypted PKCS#8 first (cheaper, and PRIVATE_KEY_DATA in the
	 * testsuite is unencrypted). */
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

	/* Encrypted: parse as X509_SIG and decrypt with the keystore PIN. */
	p = data;
	X509_SIG *sig = d2i_X509_SIG(NULL, &p, (long)len);
	if (NULL == sig) {
		ERR_clear_error();
		goto end;
	}
	p8inf = PKCS8_decrypt(sig, g_p11.pin, (int)strlen(g_p11.pin));
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
// Write path: setKeyEntry import-state machine
// -----------------------------------------------------------------------------

/** Destroy every object bearing @p label EXCEPT the handles in @p keep. Used
 *  by setKeyEntry / setCertificateEntry to retire the previous binding once
 *  the new objects have been successfully created — PKCS#11 happily lets
 *  multiple objects share a CKA_LABEL, but Java KeyStore expects an alias to
 *  hold at most one entry. Pass keep_count == 0 to purge everything (e.g. to
 *  drop a stale binding before reusing the label).
 *
 *  Best-effort: any per-object destroy failure is swallowed (matches the prior
 *  writer_purge_alias contract). */
static void writer_purge_label_except(CK_SESSION_HANDLE session, char *label,
                                      const CK_OBJECT_HANDLE *keep, int keep_count) {
	CK_OBJECT_HANDLE existing[LLCRYPTO_EKS_MAX_OBJECTS];
	int n = pkcs11_find_objects_by_label(session, label, existing, LLCRYPTO_EKS_MAX_OBJECTS);
	if (n <= 0) {
		return;
	}
	CK_OBJECT_HANDLE to_destroy[LLCRYPTO_EKS_MAX_OBJECTS];
	int to_destroy_count = 0;
	for (int i = 0; i < n; i++) {
		int is_kept = 0;
		for (int j = 0; j < keep_count; j++) {
			if (existing[i] == keep[j]) {
				is_kept = 1;
				break;
			}
		}
		if (!is_kept) {
			to_destroy[to_destroy_count] = existing[i];
			to_destroy_count++;
		}
	}
	if (to_destroy_count > 0) {
		(void)writer_destroy_objects(session, to_destroy, to_destroy_count);
	}
}

// -----------------------------------------------------------------------------
// LLAPI entry-type query entry point
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getEntryType(jbyte *alias) {
	jint result = LLCRYPTO_ERROR;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	if (LLCRYPTO_SUCCESS != pkcs11_capi_init()) {
		goto end;
	}
	session = pkcs11_open_session_ro();
	if (CK_INVALID_HANDLE == session) {
		goto end;
	}

	CK_OBJECT_HANDLE handles[LLCRYPTO_EKS_MAX_OBJECTS];
	int n = pkcs11_find_objects_by_label(session, (char *)alias, handles, LLCRYPTO_EKS_MAX_OBJECTS);
	if (n > 0) {
		/* If any object on the alias is a private or secret key it's a key
		 * entry; otherwise it's a cert entry. PKCS#11 lets a key entry hold
		 * both a key and its leaf cert under one label, hence the bias. */
		bool has_key = false;
		bool has_cert = false;
		for (int i = 0; i < n; i++) {
			CK_OBJECT_CLASS class = 0;
			CK_ATTRIBUTE class_attr = { CKA_CLASS, &class, sizeof(class) };
			if (CKR_OK != g_p11.funcs->C_GetAttributeValue(session, handles[i], &class_attr, 1)) {
				continue;
			}
			if ((CKO_PRIVATE_KEY == class) || (CKO_SECRET_KEY == class)) {
				has_key = true;
			} else if (CKO_CERTIFICATE == class) {
				has_cert = true;
			} else {
				/* Any other object class does not decide the entry type. */
			}
		}
		if (has_key) {
			result = (jint)LLCRYPTO_ENTRY_TYPE_KEY;
		} else if (has_cert) {
			result = (jint)LLCRYPTO_ENTRY_TYPE_CERTIFICATE;
		} else {
			/* The alias holds neither a key nor a certificate. The LLAPI has no
			 * entry type for that, so result keeps LLCRYPTO_ERROR. */
		}
	}

end:
	pkcs11_close_session(session);
	return result;
}

// -----------------------------------------------------------------------------
// LLAPI write entry points
// -----------------------------------------------------------------------------

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_deleteEntry(jbyte *alias) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;
	CK_SESSION_HANDLE session = pkcs11_open_session_rw();
	if (CK_INVALID_HANDLE == session) {
		goto end;
	}
	CK_OBJECT_HANDLE existing[LLCRYPTO_EKS_MAX_OBJECTS];
	int n = pkcs11_find_objects_by_label(session, (char *)alias, existing, LLCRYPTO_EKS_MAX_OBJECTS);
	if (n < 0) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "C_FindObjects failed");
		goto end;
	}
	/* Java semantics: delete on a non-existent alias is a silent no-op. */
	if (n > 0) {
		/* writer_destroy_objects continues on per-object errors, so partial
		 * destruction is possible. Invalidate the cache up front: the
		 * worst case is an unnecessary re-enumeration on the next read. */
		invalidate_alias_cache();
		if (LLCRYPTO_SUCCESS != writer_destroy_objects(session, existing, n)) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "C_DestroyObject failed");
			goto end;
		}
	}
	result = LLCRYPTO_SUCCESS;
end:
	pkcs11_close_session(session);
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_setCertificateEntry(jbyte *alias, jbyte *certificate) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s'", (const char *)alias);
	jint result = LLCRYPTO_ERROR;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

	jint cert_len = sni_array_get_length((void *)certificate);
	if (cert_len <= 0) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Empty certificate");
		goto end;
	}
	const unsigned char *p = (const unsigned char *)certificate;
	X509 *cert = d2i_X509(NULL, &p, (long)cert_len);
	if (NULL == cert) {
		ERR_clear_error();
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Cannot parse X.509 certificate");
		goto end;
	}

	session = pkcs11_open_session_rw();
	if (CK_INVALID_HANDLE == session) {
		X509_free(cert);
		goto end;
	}

	unsigned char id[LLCRYPTO_EKS_LOCAL_KEY_ID_LEN];
	unsigned int id_len = 0;
	if (LLCRYPTO_SUCCESS != derive_cka_id((const char *)alias, id, &id_len)) {
		X509_free(cert);
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Failed to derive CKA_ID");
		goto end;
	}

	/* Create the new cert first so a C_CreateObject failure leaves the
	 * prior binding intact. The cache must be invalidated before the
	 * create (the new object would otherwise be invisible to readers
	 * relying on a still-valid alias snapshot). */
	invalidate_alias_cache();
	CK_OBJECT_HANDLE new_cert = CK_INVALID_HANDLE;
	if (LLCRYPTO_SUCCESS != writer_create_certificate(session, (char *)alias, id, id_len, cert, &new_cert)) {
		X509_free(cert);
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
		                                              "C_CreateObject(certificate) failed");
		goto end;
	}
	X509_free(cert);
	/* Drop any prior objects bearing this alias (a previous cert or key
	 * entry — Java treats the alias as the single key into the keystore). */
	writer_purge_label_except(session, (char *)alias, &new_cert, 1);
	result = LLCRYPTO_SUCCESS;
end:
	pkcs11_close_session(session);
	return result;
}

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_openKeyEntryWithData(jbyte *alias, jbyte *key, jint chain_len) {
	VEEPORT_LOGGER_LOG_DBG("alias='%s' chain_len=%d", (const char *)alias, (int)chain_len);
	jint result = LLCRYPTO_ERROR;

	jint key_len = sni_array_get_length((void *)key);
	if (key_len <= 0) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Empty key data");
		goto end;
	}
	if (LLCRYPTO_SUCCESS != pkcs11_capi_init()) {
		goto end;
	}

	struct llcrypto_eks_key_import *h = llcrypto_eks_key_import_new((const char *)alias, (int)chain_len);
	if (NULL == h) {
		/* llcrypto_eks_key_import_new has already thrown. */
		goto end;
	}

	/* Decode the key now so we can fail fast — leaving a partially-built
	 * import handle around would surface much later as a confusing
	 * closeKeyEntry failure. */
	h->key_evp = parse_protected_key((const uint8_t *)key, key_len);
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
	LLCRYPTO_UNUSED_PARAM(password); /* keystore PIN is what authenticates writes */
	jint result = LLCRYPTO_ERROR;
	if (LLCRYPTO_SUCCESS != pkcs11_capi_init()) {
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

jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_closeKeyEntry(jint handle) {
	VEEPORT_LOGGER_LOG_DBG("handle=%d", handle);
	jint result = LLCRYPTO_ERROR;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	/* In-call rollback log: every C_CreateObject we issue lands here so we
	 * can C_DestroyObject the lot on any later failure. Sized for the key
	 * plus the full chain (chain_count is fixed by Java before we touch
	 * the token). NULL until allocated, freed on the way out. */
	CK_OBJECT_HANDLE *created = NULL;
	int created_count = 0;
	struct llcrypto_eks_key_import *h = (struct llcrypto_eks_key_import *)handle;
	if (NULL == h) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "NULL key entry handle");
		goto end;
	}
	/* Java calls closeKeyEntry from a `finally` block whether or not the
	 * preceding insertCertificateInChain loop completed. If chain_count is
	 * short of chain_len, the Java side aborted (an insert failed and the
	 * loop broke out before filling every slot). Releasing the staged state
	 * without touching the token is the only safe action — committing a
	 * truncated chain would corrupt the alias and destroy any prior entry. */
	if (h->chain_count < h->chain_len) {
		VEEPORT_LOGGER_LOG_ERR("aborting commit: chain_count=%d chain_len=%d", h->chain_count, h->chain_len);
		result = LLCRYPTO_SUCCESS;
		goto end;
	}
	session = pkcs11_open_session_rw();
	if (CK_INVALID_HANDLE == session) {
		goto end;
	}

	created = (CK_OBJECT_HANDLE *)LLCRYPTO_calloc((size_t)h->chain_count + 1U, sizeof(*created));
	if (NULL == created) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Out of memory");
		goto end;
	}

	unsigned char id[LLCRYPTO_EKS_LOCAL_KEY_ID_LEN];
	unsigned int id_len = 0;
	if (LLCRYPTO_SUCCESS != derive_cka_id(h->alias, id, &id_len)) {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "Failed to derive CKA_ID");
		goto end;
	}

	/* From here on we mutate the token. Invalidate the cache before the
	 * first writer_create_* so readers can't see stale state. The
	 * previous binding (if any) is left in place until the new objects
	 * are committed below — that way a create or rollback failure leaves
	 * the token holding the prior valid entry instead of nothing. */
	invalidate_alias_cache();

	/* 1) Install the key. Two possible sources:
	 *    a) key_evp parsed in openKeyEntryWithData (private key, PKCS#8/PBES2)
	 *    b) key_native_id pointing to a llcrypto_key (private or secret) */
	if (NULL != h->key_evp) {
		if (writer_create_private_key_from_pkey(session, h->alias, id, id_len, h->key_evp,
		                                        &created[created_count]) != LLCRYPTO_SUCCESS) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION,
			                                              "C_CreateObject(private key) failed");
			goto end;
		}
		created_count++;
	} else if (0 != h->key_native_id) {
		struct llcrypto_key *src = (struct llcrypto_key *)h->key_native_id;
		int rc = LLCRYPTO_ERROR;
		switch (src->type) {
		case LLCRYPTO_KEY_TYPE_EVP_PKEY:
			rc = writer_create_private_key_from_pkey(session, h->alias, id, id_len, src->evp_key,
			                                         &created[created_count]);
			break;
		case LLCRYPTO_KEY_TYPE_SECRET_KEY:
			rc = writer_create_secret_key(session, h->alias, id, id_len,
			                              src->secret_key.buffer, src->secret_key.length,
			                              src->secret_key.algorithm, &created[created_count]);
			break;
		default:
			break;
		}
		if (LLCRYPTO_SUCCESS != rc) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "C_CreateObject(key) failed");
			goto end;
		}
		created_count++;
	} else {
		VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "No key source for entry");
		goto end;
	}

	/* 2) Install the certificate chain. The leaf cert (index 0) shares the
	 *    alias and CKA_ID with the key; chain certs after the leaf get a
	 *    label suffix so PKCS#11 can hold them as distinct objects but our
	 *    chain walker still finds them via getCertificateChainHandle. */
	for (int i = 0; i < h->chain_count; i++) {
		const unsigned char *der = h->chain_certs[i].der;
		X509 *cert = d2i_X509(NULL, &der, (long)h->chain_certs[i].len);
		const char *failure = NULL;

		if (NULL == cert) {
			ERR_clear_error();
			failure = "Cannot parse chain certificate";
		} else {
			char *cert_label = h->alias;
			char chain_label[LLCRYPTO_EKS_MAX_ALIAS_LEN];
			if (i > 0) {
				(void)snprintf(chain_label, sizeof(chain_label), "%s-chain-%d", h->alias, i);
				cert_label = chain_label;
			}
			int rc = writer_create_certificate(session, cert_label, id, id_len, cert, &created[created_count]);
			X509_free(cert);
			if (LLCRYPTO_SUCCESS != rc) {
				failure = "C_CreateObject(chain cert) failed";
			}
		}
		if (NULL != failure) {
			VEEPORT_ERRORS_throw_caught_exception_message(LLCRYPTO_UNSPECIFIED_EXCEPTION, "%s", failure);
			goto end;
		}
		created_count++;
	}

	/* 3) Retire the previous binding now that the new objects are in place.
	 *    The key and the leaf cert (if any) both wear `alias` as their
	 *    label, so exclude both from the purge. Also purge any prior
	 *    `alias-chain-N` objects at the indices we just wrote (collisions
	 *    on the same N) plus the remaining N up to the supported max so a
	 *    shallower-new-than-old chain doesn't leave orphan chain-N certs
	 *    behind. */
	int alias_label_keep = (h->chain_count >= 1) ? 2 : 1;
	writer_purge_label_except(session, h->alias, created, alias_label_keep);
	for (int i = 1; i < LLCRYPTO_PKCS11_OBJECTS_PER_ALIAS_MAX; i++) {
		char chain_label[LLCRYPTO_EKS_MAX_ALIAS_LEN];
		(void)snprintf(chain_label, sizeof(chain_label), "%s-chain-%d", h->alias, i);
		if (i < h->chain_count) {
			writer_purge_label_except(session, chain_label, &created[1 + i], 1);
		} else {
			writer_purge_label_except(session, chain_label, NULL, 0);
		}
	}

	result = LLCRYPTO_SUCCESS;
end:
	/* PKCS#11 has no transactions, so rollback is best-effort: destroy the
	 * objects this call created so the token keeps no partial entry. */
	if ((LLCRYPTO_SUCCESS != result) && (NULL != created) && (CK_INVALID_HANDLE != session)) {
		(void)writer_destroy_objects(session, created, created_count);
	}
	LLCRYPTO_free(created);
	pkcs11_close_session(session);
	llcrypto_eks_key_import_free(h);
	return result;
}
