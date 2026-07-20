# Copyright 2024-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# Build: 7E4D1F7C
#
# BSP options
#

# Select which Abstraction Layer to build
option(BUILD_AUDIO               "Build Audio Abstraction Layer"                  ON)
option(BUILD_CORE                "Build Core Abstraction Layer"                   ON)
option(BUILD_DEVICE              "Build Device Abstraction Layer"                 ON)
option(BUILD_ECOM_NETWORK        "Build Embedded COMmunication Abstraction Layer" ON)
option(BUILD_EVENT_QUEUE         "Build Event Queue Abstraction Layer"            ON)
option(BUILD_FS                  "Build File System Abstraction Layer"            ON)
option(BUILD_KF                  "Build Kernel Feature Abstraction Layer"         ON)
option(BUILD_NET                 "Build Network Abstraction Layer"                ON)
option(BUILD_RIO                 "Build rio Event-Driven I/O Abstraction Layer"   ON)
# Readiness-wait backend for the net (and SSL) layer.  When rio is built it is
# the default wait backend: the LLNET_*_OPERATION seams route to rio_wait_ready
# (LLNET_rio.h / LLNET_SSL_rio.h).  Set this ON to keep rio built for direct
# ej.rio use but force net/SSL back to the async_select wait.  No effect when
# BUILD_RIO is OFF — async_select is then the only available wait path.
option(NET_WAIT_WITH_ASYNC_SELECT "Use async_select (not rio) for the net/SSL readiness wait" OFF)
option(BUILD_CRYPTO              "Build Crypto Abstraction Layer"                 ON)
option(BUILD_SERIAL              "Build Serial Abstraction Layer"                 ON)
option(BUILD_SSL                 "Build SSL Abstraction Layer"                    ON)
option(BUILD_UI                  "Build UI Abstraction Layer"                     ON)
option(BUILD_UTIL                "Build Util Abstraction Layer"                   ON)
option(BUILD_VALIDATION          "Build validation utilities"                     OFF)
option(BUILD_VALIDATION_KERNEL   "Build validation kernel"                        OFF)
option(BUILD_VALIDATION_VEE_MOCK "Build validation with vee mock"                 OFF)

# Set specific features
if (BUILD_UI)
	option(BUILD_UI_TOUCHSCREEN "Build UI Touchscreen feature" ON)
	option(BUILD_UI_FRAMERATE "Build UI Framerate debug feature" OFF)
	option(BUILD_UI_FBDEV "Build UI Framebuffer device support" ON)
	option(BUILD_UI_DRM "Build UI DRM Framebuffer support" OFF)
	option(BUILD_UI_VSYNC "Build UI vertical sync (vsync) support" ON)
	option(BUILD_UI_CONVERT_32_TO_16_BPP "Build UI 32bpp to 16bpp conversion" OFF)
endif()

if (BUILD_UTIL)
	option(BUILD_UTIL_FD_MONITOR "Build File Descriptor monitor" OFF)
	if (BUILD_SERIAL)
		set(BUILD_UTIL_FD_MONITOR ON CACHE BOOL "Build File Descriptor monitor" FORCE)
	endif()
endif()

if (BUILD_SERIAL)
	# Enforce exclusive serial port access with a userspace per-process open count
	# (keyed by device identity) instead of the kernel TIOCEXCL flag. Enables running
	# the serial validation suite against virtual ports (e.g. socat/PTY pairs), where a
	# persistent broker holds the slave open and prevents TIOCEXCL from clearing on
	# close. Leave OFF for real hardware / production, which relies on kernel TIOCEXCL.
	option(BUILD_SERIAL_SOFT_EXCLUSIVE "Enforce exclusive serial access in userspace instead of TIOCEXCL (virtual-port emulation)" OFF)
endif()

if (BUILD_CRYPTO)
	# Derive the keystore backend from the LLCRYPTO_KEYSTORE_TYPE env var set in set_project_env.sh.
	# This env var is the single source of truth: it selects the compiled backend here at build
	# time and is also required at runtime by the native code and OpenSSL pkcs11-provider.
	# PKCS11 → PKCS#11 token via OpenSSL pkcs11-provider; anything else → PKCS#12 file backend.
	if("$ENV{LLCRYPTO_KEYSTORE_TYPE}" STREQUAL "PKCS11")
		set(LLCRYPTO_KEYSTORE_PKCS11 ON)
	else()
		set(LLCRYPTO_KEYSTORE_PKCS11 OFF)
	endif()
endif()

if (BUILD_NET)
	option(ENABLE_NET_AF_IPV4_SUPPORT "IPv4 support" ON)
	option(ENABLE_NET_AF_IPV6_SUPPORT "IPv6 support" OFF)
endif()

if (BUILD_RIO)
	# I/O selector backend (only one active at a time).
	# The selected backend .c file is compiled; others are skipped.
	set(RIO_SELECTOR "poll" CACHE STRING "rio I/O selector backend (poll, select)")
	set_property(CACHE RIO_SELECTOR PROPERTY STRINGS poll select)
endif()

# Debug features
option(ADVANCED_TRACE "Enable MJVM Advanced trace" OFF)
