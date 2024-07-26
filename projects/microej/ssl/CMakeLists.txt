# CMake
#
# Copyright 2012-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_SSL_CONTEXT_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_SSL_ERRORS.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_SSL_SOCKET_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_SSL_cookie.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_SSL_util.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_SSL_verifyCallback.c
)
