# CMake
#
# Copyright 2012-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
# Build: 7E4D1F7C

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLEVENT.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLEVENT_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/EventQueueTestsuiteNatives_impl.c
)
# The POSIX OSAL ignores the task priority: the Linux threads are preemptive, so the offer task
# of the test suite can race the Event Queue thread with any value.
target_compile_definitions(${target} PRIVATE TESTEVENT_OFFER_TASK_PRIORITY=0)
