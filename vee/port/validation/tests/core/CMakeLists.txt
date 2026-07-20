# CMake
#
# Copyright 2025-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/async_wakeup_vm.c
    ${CMAKE_CURRENT_LIST_DIR}/src/microejruntime_mock.c
    ${CMAKE_CURRENT_LIST_DIR}/src/t_core_core_benchmark.c
    ${CMAKE_CURRENT_LIST_DIR}/src/t_core_main.c
    ${CMAKE_CURRENT_LIST_DIR}/src/t_core_print.c
    ${CMAKE_CURRENT_LIST_DIR}/src/t_core_ram.c
    ${CMAKE_CURRENT_LIST_DIR}/src/t_core_time_base.c
    ${CMAKE_CURRENT_LIST_DIR}/src/x_impl_core_benchmark.c
    ${CMAKE_CURRENT_LIST_DIR}/src/x_impl_ram_checks.c
    ${CMAKE_CURRENT_LIST_DIR}/src/x_impl_ram_speed.c
    ${CMAKE_CURRENT_LIST_DIR}/src/x_ram_checks.c
    ${CMAKE_CURRENT_LIST_DIR}/src/x_ram_speed.c
)
