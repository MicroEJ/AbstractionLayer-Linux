# CMake
#
# Copyright 2012-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target}
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/embUnit
)

set(EMBUNIT_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/AssertImpl.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/RepeatedTest.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/stdImpl.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestCaller.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestCase.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestResult.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestRunner.c
    ${CMAKE_CURRENT_LIST_DIR}/embUnit/TestSuite.c
)

target_sources(${target}
    PRIVATE
    ${EMBUNIT_SOURCES}
)

# embUnit is unpatched third-party code: its warnings must not stop the build.
# TARGET_DIRECTORY is mandatory. A source property set in this scope does not reach the scope
# that creates application.out.
set_source_files_properties(${EMBUNIT_SOURCES}
    TARGET_DIRECTORY ${target}
    PROPERTIES COMPILE_OPTIONS -Wno-error
)
