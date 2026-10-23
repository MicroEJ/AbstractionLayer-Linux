# CMake
#
# Copyright 2025-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# Build: 7E4D1F7C

if(NOT BUILD_ESSENTIALS)
    message(FATAL_ERROR "BUILD_DEVICE requires BUILD_ESSENTIALS (port/essentials provides veeport_errors.h).")
endif()

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDEVICE_id_util.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDEVICE_linux.c
)
