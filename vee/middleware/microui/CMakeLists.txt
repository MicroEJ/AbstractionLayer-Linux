# CMake
#
# Copyright 2026 MicroEJ Corp. All rights reserved.
# MicroEJ Corp. PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
#
# Build: 7E4D1F7C

include_guard()
message("middleware/microui component is included.")

target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLDW_PAINTER_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLUI_DISPLAY_HEAP_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLUI_INPUT_LOG_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLUI_PAINTER_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/microui_event_decoder.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ui_display_brs.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ui_display_brs_legacy.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ui_display_brs_predraw.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ui_display_brs_single.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ui_drawing.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ui_drawing_stub.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ui_font_drawing.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ui_image_drawing.c
    ${CMAKE_CURRENT_LIST_DIR}/src/ui_rect_util.c
)
