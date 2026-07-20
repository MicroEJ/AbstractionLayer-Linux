# CMake
#
# Copyright 2026 MicroEJ Corp.
# Use of this source code is governed by a BSD-style license that can be found with this software.

cmake_policy(SET CMP0079 NEW)

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
file(GLOB CSources "src/*.c")
target_sources(${target} PRIVATE ${CSources})
target_link_libraries(${target} PRIVATE -lSDL2 -lm)
