/*
 * C
 *
 * Copyright 2019-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
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

#define LLCRYPTO_UNUSED_PARAM(x)                     ((void)(x))

#define LLCRYPTO_ASSERT(x)                           assert(x)

#define LLCRYPTO_calloc                              calloc
/* LLCRYPTO_free must accept NULL pointers (no-op). */
#define LLCRYPTO_free                                free
#define LLCRYPTO_strdup                              strdup

#endif /* LLCRYPTO_CONFIGURATION_H */
