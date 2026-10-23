# CMake
#
# Copyright 2025-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
)

if (BUILD_ESSENTIALS)
	# Standard output backend of the VEE Port Essentials logger, registered by the VEE Port main function.
	target_sources(${target}
	    PRIVATE
	    ${CMAKE_CURRENT_LIST_DIR}/src/veeport_logger_backend_stdout.c
	    ${CMAKE_CURRENT_LIST_DIR}/src/veeport_critical_section.c
	)
endif()
