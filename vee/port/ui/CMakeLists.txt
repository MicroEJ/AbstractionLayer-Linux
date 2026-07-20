# CMake
#
# Copyright 2012-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLINPUT.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLUI_LED_stub.c
    ${CMAKE_CURRENT_LIST_DIR}/src/event_generator.c
)

if (BUILD_UI_FBDEV)
target_compile_definitions(${target} PRIVATE LLDISPLAY_FBDEV)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDISPLAY_FB.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDISPLAY_FB_fbdev.c
)
elseif (BUILD_UI_FBDRM)
target_compile_definitions(${target} PRIVATE LLDISPLAY_FBDRM)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDISPLAY_FB.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDISPLAY_FB_drm.c
)
endif()
if (BUILD_UI_TOUCHSCREEN)
target_compile_definitions(${target} PRIVATE TOUCHMANAGER_ENABLED)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/touch_helper.c
    ${CMAKE_CURRENT_LIST_DIR}/src/touch_manager.c
)
endif()
if (BUILD_UI_FRAMERATE)
target_compile_definitions(${target} PRIVATE FRAMERATE_ENABLED)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/framerate.c
    ${CMAKE_CURRENT_LIST_DIR}/src/framerate_impl_osal.c
)
endif()
if (BUILD_UI_VSYNC)
target_compile_definitions(${target} PRIVATE LLDISPLAY_USE_VSYNC)
endif()
if (BUILD_UI_CONVERT_32_TO_16_BPP)
target_compile_definitions(${target} PRIVATE LLDISPLAY_CONVERT_32_TO_16_BPP)
endif()

# Compiled-in device path defaults so the framebuffer and touchscreen devices
# run with no runtime environment. A project sets these from
# project_options.cmake; when unset the C #ifndef/#ifdef fallbacks apply.
if(DEFINED LLDISPLAY_FBDEVICE)
    target_compile_definitions(${target} PRIVATE LLDISPLAY_FBDEVICE="${LLDISPLAY_FBDEVICE}")
endif()
if(DEFINED LLTOUCH_TSDEVICE)
    target_compile_definitions(${target} PRIVATE LLTOUCH_TSDEVICE="${LLTOUCH_TSDEVICE}")
endif()
