# CMake
#
# Copyright 2012-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target}
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/embUnit
)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/AssertImpl.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/RepeatedTest.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/stdImpl.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestCaller.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestCase.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestResult.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestRunner.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestSuite.c
)

