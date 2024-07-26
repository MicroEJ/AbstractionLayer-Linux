# CMake
#
# Copyright 2012-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDW_PAINTER_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLINPUT.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLUI_DISPLAY_HEAP_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLUI_INPUT_LOG_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLUI_LED_stub.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLUI_PAINTER_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/event_generator.c
    ${CMAKE_CURRENT_LIST_DIR}/src/microui_event_decoder.c

)

if (BUILD_UI_FBDEV)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDISPLAY_FB.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDISPLAY_FB_fbdev.c
)
elseif (BUILD_UI_FBDRM)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDISPLAY_FB.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDISPLAY_FB_drm.c
)
endif()
if (BUILD_UI_TOUCHSCREEN)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/touch_helper.c
    ${CMAKE_CURRENT_LIST_DIR}/src/touch_manager.c
)
endif()
if (BUILD_UI_FRAMERATE)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/framerate.c
    ${CMAKE_CURRENT_LIST_DIR}/src/framerate_impl_osal.c
)
endif()
