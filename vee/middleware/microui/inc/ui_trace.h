/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * MicroEJ Corp. PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

#if !defined UI_TRACE_H
#define UI_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief Provides elements that allow to trace some external events in the MicroUI trace
 * group.
 *
 * The MicroUI trace group is identified by the global LLUI_TRACE_group.
 *
 * Notes:
 * - The first event index is the event 40 (events [0,39] are reserved for MicroUI).
 * - The number of events is 100 (fixed by MicroUI): [40,139].
 * - The events [50,59] are reserved to trace the buffer refresh strategies (BRS) events.
 *
 * Example:
 *
 * 		#include "ui_trace.h"
 * 		LLTRACE_record_event_u32(LLUI_TRACE_group, MY_EVENT_OFFSET, my_event_data);
 *
 * @author MicroEJ Developer Team
 * @version 14.5.2
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

/*
 * @brief Includes right header file according the Architecture.
 * - Architecture 7: include "trace.h"
 * - Architecture 8: include "LLTRACE.h"
 */
#if !defined UI_LLTRACE
#if !defined __has_include
#error "Set manually UI_LLTRACE: 0 for MicroEJ Architecture 7.x or 1 for MicroEJ Architecture 8.x"
#else
#define UI_LLTRACE __has_include("LLTRACE.h")
#endif // #if !defined __has_include
#endif // #if !defined UI_LLTRACE
#if UI_LLTRACE == (0u)
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
 * @brief Macros to count the number of arguments of a trace (maximum 10)
 */
#define UI_TRACE_COUNT_ARGS0(P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, Pn, ...) Pn
#define UI_TRACE_COUNT_ARGS(...) UI_TRACE_COUNT_ARGS0(-1, ## __VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

/*
 * @brief Identifies the traces for the Buffer Refresh Strategies (BRS).
 */
#define UI_TRACE_BRS_FlushSingle   51
#define UI_TRACE_BRS_FlushMulti    52
#define UI_TRACE_BRS_RestoreRegion 57

/*
 * @brief Identifies the traces related to the clip and drawings
 */
#define UI_TRACE_OutOfClip        67
#define UI_TRACE_DrawnRegion      68

/*
 *  @brief Identifies the traces used by LLUI_PAINTER_impl.c
 */
#define UI_TRACE_stringWidth 62
#define UI_TRACE_writePixel 80
#define UI_TRACE_drawLine 81
#define UI_TRACE_drawHorizontalLine 82
#define UI_TRACE_drawVerticalLine 83
#define UI_TRACE_drawRectangle 84
#define UI_TRACE_fillRectangle 85
#define UI_TRACE_drawRoundedRectangle 86
#define UI_TRACE_fillRoundedRectangle 87
#define UI_TRACE_drawCircleArc 88
#define UI_TRACE_fillCircleArc 89
#define UI_TRACE_drawEllipseArc 90
#define UI_TRACE_fillEllipseArc 91
#define UI_TRACE_drawEllipse 92
#define UI_TRACE_fillEllipse 93
#define UI_TRACE_drawCircle 94
#define UI_TRACE_fillCircle 95
#define UI_TRACE_drawImage 96
#define UI_TRACE_drawString 97
#define UI_TRACE_drawRenderableString 98

/*
 *  @brief Identifies the traces used by LLDW_PAINTER_impl.c
 */
#define UI_TRACE_Bilinear 0
#define UI_TRACE_NearestNeighbor 1
#define UI_TRACE_drawThickFadedPoint 110
#define UI_TRACE_drawThickFadedLine 111
#define UI_TRACE_drawThickFadedCircle 112
#define UI_TRACE_drawThickFadedCircleArc 113
#define UI_TRACE_drawThickFadedEllipse 114
#define UI_TRACE_drawThickLine 115
#define UI_TRACE_drawThickCircle 116
#define UI_TRACE_drawThickEllipse 117
#define UI_TRACE_drawThickCircleArc 118
#define UI_TRACE_drawFlippedImage 130
#define UI_TRACE_drawRotatedImage 131
#define UI_TRACE_drawScaledImage 132
#define UI_TRACE_drawScaledString 133
#define UI_TRACE_drawScaledRenderableString 134
#define UI_TRACE_drawRotatedCharacter 135

/*
 * @brief Compatibility of Architecture 7 with Architecture 8: use the prototypes
 * of LLTRACE.h (Architecture 8).
 */
#if UI_LLTRACE == (0u)
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
#endif // if UI_LLTRACE == (0u)

/*
 * @brief Macros to call the trace functions
 */
#define LLTRACE_record_event_u32x1 LLTRACE_record_event_u32
#define UI_TRACE_FUNCTION(...) CONCAT(LLTRACE_record_event_u32x, UI_TRACE_COUNT_ARGS(__VA_ARGS__))
#define UI_TRACE_OFFSET(fn) CONCAT(UI_TRACE_, fn)
#define UI_TRACE_PARAMS(fn, ...) LLUI_TRACE_group, UI_TRACE_OFFSET(fn), __VA_ARGS__

/*
 * @brief Add the image's address as a trace
 */
#define UI_TRACE_IMAGE(img) (uint32_t)LLUI_DISPLAY_getAddress(img)

/*
 * @brief Add the image's buffer address as a trace
 */
#define UI_TRACE_BUFFER(img) (uint32_t)LLUI_DISPLAY_getBufferAddress(img)

/*
 * @brief Starts a UI trace (at least one parameter is required)
 */
#define UI_TRACE_START(fn, ...) UI_TRACE_FUNCTION(__VA_ARGS__)(UI_TRACE_PARAMS(fn, __VA_ARGS__))

/*
 * @brief Ends a UI trace (one parameter is required)
 */
#define UI_TRACE_END(fn, v) LLTRACE_record_event_end_u32(UI_TRACE_PARAMS(fn, v))

/*
 * @brief Starts a UI trace that denotes a drawing (destination "gc" is required)
 */
#define UI_TRACE_DRAW_START(fn, gc, ...) UI_TRACE_START(fn, UI_TRACE_IMAGE(&gc->image), __VA_ARGS__)

/*
 * @brief Ends a UI trace that denotes a drawing
 */
#define UI_TRACE_DRAW_END UI_TRACE_END

// --------------------------------------------------------------------------------
// Fields
// --------------------------------------------------------------------------------

/*
 * @brief Identifies the MicroUI group to trace an event.
 */
extern int32_t LLUI_TRACE_group;

// --------------------------------------------------------------------------------
// EOF
// --------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif // UI_TRACE_H
