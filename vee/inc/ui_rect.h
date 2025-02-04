/*
 * C
 *
 * Copyright 2023-2024 MicroEJ Corp. All rights reserved.
 * This library is provided in source code for use, modification and test, subject to license terms.
 * Any modification of the source code will break MicroEJ Corp. warranties on the whole library.
 */

#ifndef UI_RECT_H
#define UI_RECT_H
#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief Exposes the ui_rect_t type that handles rectangular regions
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include "sni.h"

// --------------------------------------------------------------------------------
// Typedefs
// --------------------------------------------------------------------------------

/*
 * @brief A rectangle holds the top-left and the bottom-right points.
 */
typedef struct {
	jshort x1;
	jshort y1;
	jshort x2;
	jshort y2;
} ui_rect_t;

// --------------------------------------------------------------------------------
// Public functions
// --------------------------------------------------------------------------------

/*
 * @brief Creates a new rectangle from the top-left and the bottom-right points.
 *
 * @param[in] left the left coordinate
 * @param[in] top the top coordinate
 * @param[in] right the right coordinate
 * @param[in] bottom the bottom coordinate
 *
 * @return a new rectangle
 */
static inline ui_rect_t UI_RECT_new_xyxy(jshort left, jshort top, jshort right, jshort bottom) {
	return (ui_rect_t) { left, top, right, bottom };
}

/*
 * @brief Creates a new rectangle from the top-left point and size.
 *
 * @param[in] left the left coordinate
 * @param[in] top the top coordinate
 * @param[in] w the rectangle width
 * @param[in] h the rectangle height
 *
 * @return a new rectangle
 */
static inline ui_rect_t UI_RECT_new_xywh(jshort x, jshort y, jshort w, jshort h) {
	return (ui_rect_t) { x, y, x+w-1, y+h-1 };
}

/*
 * @brief Gets the rectangle's width. The width is negative (-1) when the rectangle is empty.
 *
 * @param[in] rect the rectangle to check
 *
 * @return the rectangle width
 */
static inline jshort UI_RECT_get_width(const ui_rect_t* rect) {
	return rect->x2 - rect->x1 + 1u;
}

/*
 * @brief Gets the rectangle's height. The height is negative (-1) when the rectangle is empty.
 *
 * @param[in] rect the rectangle to check
 *
 * @return the rectangle height
 */
static inline jshort UI_RECT_get_height(const ui_rect_t* rect) {
	return rect->y2 - rect->y1 + 1u;
}

/*
 * @brief Tells if the first rectangle (outer) fully contains the second rectangle (inner).
 *
 * @param[in] outer the rectangle that may contain the inner rectangle
 * @param[in] inner the rectangle that may be contained the outer rectangle
 *
 * @return true when the outer rectangle fully contains the inner rectangle
 */
static inline bool UI_RECT_contains_rect(const ui_rect_t* outer, const ui_rect_t* inner) {
	return (outer->x1 <= inner->x1) && (outer->y1 <= inner->y1) && (outer->x2 >= inner->x2) && (outer->y2 >= inner->y2);
}

/*
 * @brief Tells if the first rectangle (a) intersects the second rectangle (b).
 *
 * @param[in] a a rectangle
 * @param[in] b a rectangle
 *
 * @return true when there is an intersection between both rectangles
 */
static inline bool UI_RECT_intersects_rect(const ui_rect_t* a, const ui_rect_t* b) {
	return !((a->x1 > b->x2) || (a->y1 > b->y2) || (a->x2 < b->x1) || (a->y2 < b->y1));
}

/*
 * @brief Tells if the rectangle is empty.
 *
 * @param[in] rect the rectangle to check
 *
 * @return true if the rectangle has been marked as empty
 */
static inline bool UI_RECT_is_empty(const ui_rect_t* r) {
	return r->x2 < r->x1 || r->y2 < r->y1;
}

/*
 * @brief Marks the rectangle as empty.
 *
 * @param[in] rect the rectangle to mark
 */
static inline void UI_RECT_mark_empty(ui_rect_t* r) {
	r->x1 = 1u;
	r->x2 = 0u;
}

// --------------------------------------------------------------------------------
// EOF
// --------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif
#endif // UI_RECT_H
