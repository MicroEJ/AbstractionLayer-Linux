# CMake
#
# Copyright 2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)

# rio-core: always compiled.
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/rio.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLRIO_impl.c
)

# I/O selector backend: compile only the selected one.
# The backend is chosen via RIO_SELECTOR in options.cmake.
if (RIO_SELECTOR STREQUAL "poll")
    target_sources(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/rio_poll.c)
elseif (RIO_SELECTOR STREQUAL "select")
    target_sources(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/rio_select.c)
else()
    message(FATAL_ERROR "Unknown RIO_SELECTOR: ${RIO_SELECTOR}")
endif()

# rio-net-bsd: BSD/POSIX socket operations.
target_sources(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/LLRIO_NET_impl.c)

# rio-pipe-posix: POSIX pipe() backend.
target_sources(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/LLRIO_PIPE_impl.c)
