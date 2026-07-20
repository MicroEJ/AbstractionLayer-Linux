# CMake
#
# Copyright 2025-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLSERIAL_CONNECTION_impl.c
)

if (BUILD_SERIAL_SOFT_EXCLUSIVE)
    target_compile_definitions(${target} PRIVATE LLSERIAL_SOFT_EXCLUSIVE)
endif()
