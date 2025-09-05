/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

#if !defined UI_LOG_H
#define UI_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief Provides elements that allow to log some external events in the MicroUI event
 * group.
 *
 * The MicroUI event group is identified by the global LLUI_EVENT_group.
 *
 * Notes:
 * - The first event index is the event 40 (events [0,39] are reserved for MicroUI).
 * - The number of events is 100 (fixed by MicroUI): [40,139].
 * - The events [50,59] are reserved to log the buffer refresh strategies (BRS) events.
 *
 * Example:
 *
 * 		#include "ui_log.h"
 * 		LLTRACE_record_event_u32(LLUI_EVENT_group, MY_EVENT_OFFSET, my_event_data);
 *
 * @author MicroEJ Developer Team
 * @version 14.4.2
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

/*
 * @brief Includes right header file according the Architecture.
 * - Architecture 7: include "trace.h"
 * - Architecture 8: include "LLTRACE.h"
 */
#if !defined UI_LOG_LLTRACE
#if !defined __has_include
#error "Set manually UI_LOG_LLTRACE: 0 for MicroEJ Architecture 7.x or 1 for MicroEJ Architecture 8.x"
#else
#define UI_LOG_LLTRACE __has_include("LLTRACE.h")
#endif // #if !defined __has_include
#endif // #if !defined UI_LOG_LLTRACE
#if UI_LOG_LLTRACE == (0u)
#include <trace.h>
#else
#include <LLTRACE.h>
#endif

// --------------------------------------------------------------------------------
// Defines
// --------------------------------------------------------------------------------

/*
 * @brief Useful macros to concatenate easily some strings and defines.
 */
#ifndef CONCAT
#define CONCAT0(p, s) p ## s
#define CONCAT(p, s) CONCAT0(p, s)
#endif

/*
 * @brief Macros to count the number of arguments of a log (maximum 10)
 */
#define UI_LOG_COUNT_ARGS0(P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, Pn, ...) Pn
#define UI_LOG_COUNT_ARGS(...) UI_LOG_COUNT_ARGS0(-1, ## __VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

/*
 * @brief Identifies the logs for the Buffer Refresh Strategies (BRS).
 */
#define UI_LOG_BRS_FlushSingle   51
#define UI_LOG_BRS_FlushMulti    52
#define UI_LOG_BRS_RestoreRegion 57

/*
 * @brief Identifies the logs related to the clip and drawings
 */
#define UI_LOG_OutOfClip        67
#define UI_LOG_DrawnRegion      68

/*
 *  @brief Identifies the logs used by LLUI_PAINTER_impl.c
 */
#define UI_LOG_stringWidth 62
#define UI_LOG_writePixel 80
#define UI_LOG_drawLine 81
#define UI_LOG_drawHorizontalLine 82
#define UI_LOG_drawVerticalLine 83
#define UI_LOG_drawRectangle 84
#define UI_LOG_fillRectangle 85
#define UI_LOG_drawRoundedRectangle 86
#define UI_LOG_fillRoundedRectangle 87
#define UI_LOG_drawCircleArc 88
#define UI_LOG_fillCircleArc 89
#define UI_LOG_drawEllipseArc 90
#define UI_LOG_fillEllipseArc 91
#define UI_LOG_drawEllipse 92
#define UI_LOG_fillEllipse 93
#define UI_LOG_drawCircle 94
#define UI_LOG_fillCircle 95
#define UI_LOG_drawImage 96
#define UI_LOG_drawString 97
#define UI_LOG_drawRenderableString 98

/*
 *  @brief Identifies the logs used by LLDW_PAINTER_impl.c
 */
#define UI_LOG_Bilinear 0
#define UI_LOG_NearestNeighbor 1
#define UI_LOG_drawThickFadedPoint 70
#define UI_LOG_drawThickFadedLine 71
#define UI_LOG_drawThickFadedCircle 72
#define UI_LOG_drawThickFadedCircleArc 73
#define UI_LOG_drawThickFadedEllipse 74
#define UI_LOG_drawThickLine 75
#define UI_LOG_drawThickCircle 76
#define UI_LOG_drawThickEllipse 77
#define UI_LOG_drawThickCircleArc 78
#define UI_LOG_drawFlippedImage 90
#define UI_LOG_drawRotatedImage 91
#define UI_LOG_drawScaledImage 92
#define UI_LOG_drawScaledString 93
#define UI_LOG_drawScaledRenderableString 94
#define UI_LOG_drawRotatedCharacter 95

/*
 * @brief Compatibility of Architecture 7 with Architecture 8: use the prototypes
 * of LLTRACE.h (Architecture 8).
 */
#if UI_LOG_LLTRACE == (0u)
#define LLTRACE_record_event_void TRACE_record_event_void
#define LLTRACE_record_event_u32 TRACE_record_event_u32
#define LLTRACE_record_event_u32x2 TRACE_record_event_u32x2
#define LLTRACE_record_event_u32x3 TRACE_record_event_u32x3
#define LLTRACE_record_event_u32x4 TRACE_record_event_u32x4
#define LLTRACE_record_event_u32x5 TRACE_record_event_u32x5
#define LLTRACE_record_event_u32x6 TRACE_record_event_u32x6
#define LLTRACE_record_event_u32x7 TRACE_record_event_u32x7
#define LLTRACE_record_event_u32x8 TRACE_record_event_u32x8
#define LLTRACE_record_event_u32x9 TRACE_record_event_u32x9
#define LLTRACE_record_event_u32x10 TRACE_record_event_u32x10
#define LLTRACE_record_event_end TRACE_record_event_end
#define LLTRACE_record_event_end_u32 TRACE_record_event_end_u32
#endif // if UI_LOG_LLTRACE == (0u)

/*
 * @brief Macros to call the log functions
 */
#define LLTRACE_record_event_u32x1 LLTRACE_record_event_u32
#define UI_LOG_FUNCTION(...) CONCAT(LLTRACE_record_event_u32x, UI_LOG_COUNT_ARGS(__VA_ARGS__))
#define UI_LOG_OFFSET(fn) CONCAT(UI_LOG_, fn)
#define UI_LOG_PARAMS(fn, ...) LLUI_EVENT_group, UI_LOG_OFFSET(fn), __VA_ARGS__

/*
 * @brief Add the image's buffer address as a log
 */
#define UI_LOG_BUFFER(img) (uint32_t)LLUI_DISPLAY_getBufferAddress(img)

/*
 * @brief Starts a UI log (at least one parameter is required)
 */
#define UI_LOG_START(fn, ...) UI_LOG_FUNCTION(__VA_ARGS__)(UI_LOG_PARAMS(fn, __VA_ARGS__))

/*
 * @brief Ends a UI log (one parameter is required)
 */
#define UI_LOG_END(fn, v) LLTRACE_record_event_end_u32(UI_LOG_PARAMS(fn, v))

/*
 * @brief Starts a UI log that denotes a drawing (destination "gc" is required)
 */
#define UI_LOG_DRAW_START(fn, gc, ...) UI_LOG_START(fn, UI_LOG_BUFFER(&gc->image), __VA_ARGS__)

/*
 * @brief Ends a UI log that denotes a drawing
 */
#define UI_LOG_DRAW_END UI_LOG_END

// --------------------------------------------------------------------------------
// Fields
// --------------------------------------------------------------------------------

/*
 * @brief Identifies the MicroUI group to log an event.
 */
extern int32_t LLUI_EVENT_group;

// --------------------------------------------------------------------------------
// EOF
// --------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif // UI_LOG_H
