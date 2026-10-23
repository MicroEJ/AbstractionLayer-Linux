# CMake
#
# Copyright 2012-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# Build: 7E4D1F7C

if(NOT BUILD_UTIL)
    message(FATAL_ERROR "BUILD_NET requires BUILD_UTIL (port/util provides sni_extras.h).")
endif()

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)

target_sources(${target}
    PRIVATE
    # Shared sources (DNS, network address, network interface).
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_Common.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_DNS_native_linux.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_NETWORKADDRESS_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_NETWORKINTERFACE_linux.c
    # Canonical bsp-net-bsd LLNET socket implementations. The readiness
    # mechanism is routed via the LLNET_*_OPERATION seams: to rio (LLNET_rio.h)
    # by default when rio is built, or to async_select when rio is absent or
    # NET_WAIT_WITH_ASYNC_SELECT forces it.
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_CHANNEL_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_SOCKETCHANNEL_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_STREAMSOCKETCHANNEL_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_DATAGRAMSOCKETCHANNEL_bsd.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLNET_MULTICASTSOCKETCHANNEL_bsd.c
)

# The net/SSL readiness wait falls back to async_select whenever the rio wait
# seam is not active — either rio is not built, or NET_WAIT_WITH_ASYNC_SELECT
# forces async_select with rio built in.  Compile its implementation (+ OSAL) then.
if (NOT BUILD_RIO OR NET_WAIT_WITH_ASYNC_SELECT)
    target_sources(${target} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/async_select.c
        ${CMAKE_CURRENT_LIST_DIR}/src/async_select_osal.c)
endif()
