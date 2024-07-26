# Copyright 2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

cmake_minimum_required(VERSION 3.11)
project(linux-bsp)

set(target application.out)

add_executable(${target})
set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/scripts)

# load default options
include(${CMAKE_CURRENT_LIST_DIR}/options.cmake)
# load project specific overrides
include(${CMAKE_CURRENT_LIST_DIR}/scripts/project_options.cmake)

# add sources
target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/platform/inc)

if (BUILD_CORE)
	add_subdirectory(core)
endif()
if (BUILD_ECOM_NETWORK)
	add_subdirectory(ecom-network)
endif()
if (BUILD_FS)
	add_subdirectory(fs)
endif()
if (BUILD_KF)
	add_subdirectory(kf)
endif()
if (BUILD_NET)
	add_subdirectory(net)
endif()
if (BUILD_SECURITY)
	add_subdirectory(security)
endif()
if (BUILD_SSL)
	add_subdirectory(ssl)
endif()
if (BUILD_UI)
	add_subdirectory(ui)
endif()
if (BUILD_UTIL)
	add_subdirectory(util)
endif()

# Tests
if (BUILD_VALIDATION)
	add_subdirectory(validation/tests/llkernel/c)
	add_subdirectory(validation/framework/c)
endif()

# Debug features
if (ADVANCED_TRACE)
	add_subdirectory(trace)
endif()

# append CFLAGS environment variable set by Yocto or custom script set_project_env.sh
target_compile_options(${target} PRIVATE ${CFLAGS})
target_compile_options(${target} PRIVATE -Winline -fwrapv -Werror-implicit-function-declaration -ffunction-sections -fdata-sections -std=c99 -fno-strict-aliasing -fdollars-in-identifiers -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -fno-stack-protector -no-pie -O2 -g -D__iceTea__RELEASE -DNDEBUG)
if (ADVANCED_TRACE)
	target_compile_options(${target} PRIVATE -DMICROEJ_VEE_METHOD_TRACE=2)
else()
	target_compile_options(${target} PRIVATE -DMICROEJ_VEE_METHOD_TRACE=0)
endif()

# for DRM mmap() => requires 64bit support
target_compile_options(${target} PRIVATE -D_FILE_OFFSET_BITS=64)

if (BUILD_UI_TOUCHSCREEN)
	target_compile_options(${target} PRIVATE -DTOUCHMANAGER_ENABLED)
endif()
if (BUILD_UI_FRAMERATE)
	target_compile_options(${target} PRIVATE -DFRAMERATE_ENABLED)
endif()
if (BUILD_UI_FBDEV)
	target_compile_options(${target} PRIVATE -DLLDISPLAY_FBDEV)
endif()
if (BUILD_UI_FBDRM)
	target_compile_options(${target} PRIVATE -DLLDISPLAY_FBDRM)
endif()
if (BUILD_VALIDATION)
	target_compile_options(${target} PRIVATE -DLLKERNEL_VALIDATION)
endif()

# This block allows to configure the IP Address Family support, as in LLNET_configuration.h,
# where LLNET_AF is defined as one of these values:
# #define LLNET_AF_IPV4	(0x1)
# #define LLNET_AF_IPV6	(0x2)
# #define LLNET_AF_DUAL	((LLNET_AF_IPV4) | (LLNET_AF_IPV6))
if (ENABLE_NET_AF_IPV4_SUPPORT)
	set(LLNET_AF "1")
else()
	set(LLNET_AF "0")
endif()
if (ENABLE_NET_AF_IPV6_SUPPORT)
	math(EXPR LLNET_AF "${LLNET_AF} | 2")
endif()
target_compile_options(${target} PRIVATE "-DLLNET_AF=${LLNET_AF}")

# link
target_link_options(${target} PRIVATE -Wl,-Map,${CMAKE_CURRENT_LIST_DIR}/build/microej_gcc.map)
target_link_options(${target} PRIVATE -Wl,--gc-sections)
target_link_options(${target} PRIVATE -Wl,--start-group)
target_link_options(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/platform/lib/microejapp.o)
target_link_libraries(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/platform/lib/microejruntime.a)
target_link_libraries(${target} PRIVATE m)
target_link_options(${target} PRIVATE -Wl,--end-group)
target_link_options(${target} PRIVATE -pthread -lrt -ldl)
if (ADVANCED_TRACE)
target_link_options(
    ${target}
    PRIVATE
    -Wl,--require-defined=LLMJVM_invoke_method_with_trace
    -Wl,--defsym=LLMJVM_invoke_method=LLMJVM_invoke_method_with_trace
    -Wl,--require-defined=LLMJVM_return_method_with_trace
    -Wl,--defsym=LLMJVM_return_method=LLMJVM_return_method_with_trace
)
endif()
if (BUILD_UI_FBDRM)
	target_include_directories(${target} PUBLIC ${CMAKE_SYSROOT}/usr/include/libdrm)
	target_link_libraries(${target} PRIVATE -ldrm)
endif()
if (BUILD_UI AND BUILD_UI_TOUCHSCREEN)
	target_link_libraries(${target} PRIVATE -lts)
endif()
if (BUILD_SSL OR BUILD_SECURITY)
	target_link_libraries(${target} PRIVATE -lssl -lcrypto)
endif()
target_link_options(${target} PRIVATE -fno-stack-protector -no-pie -D_GNU_SOURCE)
