/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * MicroEJ Corp. PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

#if !defined UI_LOG_H
#define UI_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief Deprecated, use ui_trace.h
 *
 * This file is kept for the backward compatibility (since the version 1.8.0, the
 * VG Pack is compatible with the UI Pack 14.4.0 and higher).
 *
 * @author MicroEJ Developer Team
 * @version 14.5.2
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include "ui_trace.h"

// --------------------------------------------------------------------------------
// Defines
// --------------------------------------------------------------------------------

#define UI_LOG_COUNT_ARGS UI_TRACE_COUNT_ARGS
#define UI_LOG_FUNCTION UI_TRACE_FUNCTION
#define UI_LOG_OFFSET UI_TRACE_OFFSET
#define UI_LOG_PARAMS UI_TRACE_PARAMS
#define UI_LOG_IMAGE UI_TRACE_IMAGE
#define UI_LOG_BUFFER UI_TRACE_BUFFER
#define UI_LOG_START UI_TRACE_START
#define UI_LOG_END UI_TRACE_END
#define UI_LOG_DRAW_START UI_TRACE_DRAW_START
#define UI_LOG_DRAW_END UI_TRACE_DRAW_END

// --------------------------------------------------------------------------------
// EOF
// --------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif // UI_LOG_H
