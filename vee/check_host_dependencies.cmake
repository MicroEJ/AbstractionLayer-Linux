# Copyright 2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# Build: 7E4D1F7C
#
# Verify the host development files required by the enabled Abstraction Layers are
# installed before the build links against them. Each probe is gated by the same
# BUILD_* option that decides whether the library is linked, so only the selected
# features are required. All missing packages are collected and reported together
# so they can be installed in a single command.
#
# The probes use check_include_file (compiler-driven) rather than find_library or
# pkg-config: the toolchain sets CMAKE_FIND_ROOT_PATH_MODE_{LIBRARY,INCLUDE} ONLY
# with no sysroot, so find_* cannot locate the host's multiarch packages, whereas
# the compiler resolves the i386 dev files through its own search paths.

include(CheckIncludeFile)

set(_MISSING_HOST_PKGS "")

# Probe one development header; on failure record the apt package that provides it.
function(_require_host_header header pkg)
	string(MAKE_C_IDENTIFIER "HAVE_${header}" var)
	unset(${var} CACHE)  # clear the cache so the probe re-runs on every configure
	check_include_file("${header}" ${var})
	if(NOT ${var})
		list(APPEND _MISSING_HOST_PKGS "${pkg}")
		set(_MISSING_HOST_PKGS "${_MISSING_HOST_PKGS}" PARENT_SCOPE)
	endif()
endfunction()

if(BUILD_AUDIO)
	_require_host_header("SDL2/SDL.h" "libsdl2-dev:i386")
endif()
if(BUILD_SSL OR BUILD_CRYPTO OR BUILD_DEVICE)
	_require_host_header("openssl/ssl.h" "libssl-dev:i386")
endif()
if(BUILD_UI AND BUILD_UI_TOUCHSCREEN)
	_require_host_header("tslib.h" "libts-dev:i386")
endif()
if(BUILD_UI AND BUILD_UI_FBDRM)
	_require_host_header("libdrm/drm.h" "libdrm-dev:i386")
endif()

if(_MISSING_HOST_PKGS)
	list(REMOVE_DUPLICATES _MISSING_HOST_PKGS)
	list(JOIN _MISSING_HOST_PKGS " " pkg_line)
	message(FATAL_ERROR
		"Missing host development files for the enabled build options.\n"
		"On Ubuntu/Debian install:\n"
		"    sudo apt install ${pkg_line}")
endif()
