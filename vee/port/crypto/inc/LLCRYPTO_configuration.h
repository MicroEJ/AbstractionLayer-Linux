/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 *
 */

#ifndef LLCRYPTO_CONFIGURATION_H
#define LLCRYPTO_CONFIGURATION_H

#include <assert.h>
#include <stdlib.h>

/* Include VEE Port User configuration file */
#if defined __has_include
#if __has_include("veeport_configuration.h")
#include "veeport_configuration.h"
#endif // __has_include("veeport_configuration.h")
#else
#include "veeport_configuration.h"
#endif // defined __has_include

#include "veeport_logger.h"
#include "veeport_errors.h"

/**
 * @brief Name of the log module shared by every source file of the Crypto Abstraction Layer.
 *
 * Each source file that logs registers the module with VEEPORT_LOGGER_DEFINE_MODULE().
 */
#define LLCRYPTO_LOG_MODULE_NAME "crypto"

/**
 * @brief Verbosity of the Crypto Abstraction Layer.
 *
 * It replaces the per-source LLCRYPTO_<FEATURE>_DEBUG_TRACE flags, which were all off and
 * overridden nowhere. Override it in veeport_configuration.h with one of
 * VEEPORT_LOGGER_LEVEL_NONE, _ERR, _WRN, _INF or _DBG.
 */
#ifndef LLCRYPTO_LOG_LEVEL
#define LLCRYPTO_LOG_LEVEL (VEEPORT_LOGGER_LEVEL_ERR)
#endif

#define LLCRYPTO_UNUSED_PARAM(x)                     ((void)(x))

/* Consumes x under NDEBUG so an asserted return value is never reported as unused. */
#ifdef NDEBUG
#define LLCRYPTO_ASSERT(x)                           ((void)(x))
#else
#define LLCRYPTO_ASSERT(x)                           assert(x)
#endif

#define LLCRYPTO_calloc                              llcrypto_calloc
#define LLCRYPTO_free                                llcrypto_free
#define LLCRYPTO_strdup                              strdup

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocates @p nmemb elements of @p size bytes each, zero-initialized.
 *
 * The single allocation site of the module. A VEE Port that must not allocate from the standard
 * library replaces this definition rather than the call sites.
 *
 * @param[in] nmemb the element count.
 * @param[in] size the size of one element, in bytes.
 * @return the allocated block, or NULL if the allocation failed.
 */
void *llcrypto_calloc(size_t nmemb, size_t size);

/**
 * @brief Releases a block returned by llcrypto_calloc().
 *
 * @param[in] ptr the block to release. NULL is accepted and does nothing.
 */
void llcrypto_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* LLCRYPTO_CONFIGURATION_H */
