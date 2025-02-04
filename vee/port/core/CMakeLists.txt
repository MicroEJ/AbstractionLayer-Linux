# CMake
#
# Copyright 2012-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLBSP_generic.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDEVICE_linux.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLMJVM_posix.c
    ${CMAKE_CURRENT_LIST_DIR}/src/microej_main.c
    ${CMAKE_CURRENT_LIST_DIR}/src/microej_main_linux.c
    ${CMAKE_CURRENT_LIST_DIR}/src/posix_time.c
    ${CMAKE_CURRENT_LIST_DIR}/src/posix_timer.c
    ${CMAKE_CURRENT_LIST_DIR}/src/sighandler.c
)

# Necessary for Java Core PQT
# if (BUILD_VALIDATION)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/core_validation.c
)
# endif()
