# CMake
#
# Copyright 2012-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_CHANNEL_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_Common.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_DATAGRAMSOCKETCHANNEL_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_DNS_native_linux.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_MULTICASTSOCKETCHANNEL_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_NETWORKADDRESS_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_NETWORKINTERFACE_linux.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_SOCKETCHANNEL_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_STREAMSOCKETCHANNEL_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/async_select.c
    ${CMAKE_CURRENT_LIST_DIR}/src/async_select_cache.c
    ${CMAKE_CURRENT_LIST_DIR}/src/async_select_osal.c
)
