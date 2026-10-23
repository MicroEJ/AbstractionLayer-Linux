# CMake
#
# Copyright 2012-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
# Build: 7E4D1F7C

if(NOT BUILD_ESSENTIALS)
    message(FATAL_ERROR "BUILD_CORE requires BUILD_ESSENTIALS (port/essentials provides veeport_errors.h).")
endif()

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLMJVM_posix.c
    ${CMAKE_CURRENT_LIST_DIR}/src/veeport_main_linux.c
    ${CMAKE_CURRENT_LIST_DIR}/src/posix_time.c
    ${CMAKE_CURRENT_LIST_DIR}/src/posix_timer.c
    ${CMAKE_CURRENT_LIST_DIR}/src/sighandler.c
)

# Necessary for Java Core PQT
# if (BUILD_VALIDATION)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/tests/core_test_natives.c
)
# endif()
