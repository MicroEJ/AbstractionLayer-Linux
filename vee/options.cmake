# Copyright 2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# BSP options
#

# Select which Abstraction Layer to build
option(BUILD_CORE         "Build Core Abstraction Layer"                   ON)
option(BUILD_ECOM_NETWORK "Build Embedded COMmunication Abstraction Layer" ON)
option(BUILD_FS           "Build File System Abstraction Layer"            ON)
option(BUILD_KF           "Build Kernel Feature Abstraction Layer"         ON)
option(BUILD_NET          "Build Network Abstraction Layer"                ON)
option(BUILD_SECURITY     "Build Security Abstraction Layer"               ON)
option(BUILD_SSL          "Build SSL Abstraction Layer"                    ON)
option(BUILD_UI           "Build UI Abstraction Layer"                     ON)
option(BUILD_UTIL         "Build Util Abstraction Layer"                   ON)
option(BUILD_VALIDATION   "Build validation utilities"                     OFF)

# Set specific features
if (BUILD_UI)
	option(BUILD_UI_TOUCHSCREEN "Build UI Touchscreen feature" ON)
	option(BUILD_UI_FRAMERATE "Build UI Framerate debug feature" OFF)
	option(BUILD_UI_FBDEV "Build UI Framebuffer device support" ON)
	option(BUILD_UI_DRM "Build UI DRM Framebuffer support" OFF)
endif()

if (BUILD_NET)
	option(ENABLE_NET_AF_IPV4_SUPPORT "IPv4 support" ON)
	option(ENABLE_NET_AF_IPV6_SUPPORT "IPv6 support" OFF)
endif()

# Debug features
option(ADVANCED_TRACE "Enable MJVM Advanced trace" OFF)
