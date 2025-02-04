/* 
 * Copyright 2023-2024 MicroEJ Corp. All rights reserved.
 * This library is provided in source code for use, modification and test, subject to license terms.
 * Any modification of the source code will break MicroEJ Corp. warranties on the whole library.
 */

#ifndef _LLUI_DISPLAY_TYPES
#define _LLUI_DISPLAY_TYPES
#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief Provides the types to use the Graphics Engine from the adaptation layer.
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include "sni.h"
#include "ui_rect.h"

// --------------------------------------------------------------------------------
// Typedefs and Structures
// --------------------------------------------------------------------------------

/*
 * @brief LLUI_DISPLAY error and status codes.
 *
 * These values are used by several functions. See each function comment to know
 * which are the available codes.
 */
typedef enum {
	/*
	 * @brief Value when everything has been correctly executed.
	 */
	LLUI_DISPLAY_OK = 0,

	/*
	 * @brief Value when a function cannot be executed due to an out of memory error.
	 */
	LLUI_DISPLAY_OUT_OF_MEMORY = -2,

	/*
	 * @brief Value when an error has occurred or when a function is not able to
	 * implement the expected behavior.
	 */
	LLUI_DISPLAY_NOK = -9

} LLUI_DISPLAY_Status;

/*
 * @brief Drawing functions' return status.
 *
 * A function has to return DRAWING_DONE when the drawing has been fully done during
 * the function call (synchronous drawing). When the drawing is performed by an
 * asynchronous third party process (software or hardware), the function has to
 * return DRAWING_RUNNING to notify to the Graphics Engine the drawing is not fully
 * done yet.
 */
typedef enum {

	/*
	 * @brief Value to return when the drawing has been synchronously performed.
	 */
	DRAWING_DONE = 0,

	/*
	 * @brief Value to return when the drawing will be asynchronously performed.
	 */
	DRAWING_RUNNING = 1

} DRAWING_Status;

/*
 * @brief Flags describing incidents occurring during drawings.
 */
typedef enum DRAWING_Incident {

	/*
	 * @brief Value used when no incident occurred.
	 */
	DRAWING_SUCCESS = 0,

	/*
	 * @brief Flag stating that an error occurred during a drawing.
	 *
	 * This flag will cause an exception to be thrown when checking the flags in the application.
	 * No exception will be thrown if this flag is not set, although other flags will keep their state and be readable in the application.
	 * This flag is to be combined with other flags describing the error.
	 */
	DRAWING_LOG_ERROR = 1 << 31,

	/*
	 * @brief Flag stating that a drawing function is lacking an implementation.
	 */
	DRAWING_LOG_NOT_IMPLEMENTED = 1 << 0,

	/*
	 * @brief Flag stating that a function was called in a context that does not allow that operation.
	 */
	DRAWING_LOG_FORBIDDEN = 1 << 1,

	/*
	 * @brief Flag stating that the system ran out of memory while attempting to perform a drawing.
	 */
	DRAWING_LOG_OUT_OF_MEMORY = 1 << 2,

	/*
	 * @brief Flag stating that the clip area of a graphics context was modified by LLUI_DISPLAY_setClip or
	 * LLUI_DISPLAY_intersectClip.
	 *
	 * If this flag is set, the caller is responsible for saving the previous clip area and restore it afterwards.
	 *
	 * This flag merely warns the user that the clip values returned by <code>GraphicsContext.getClipX</code>,
	 * <code>GraphicsContext.getClipY</code>, <code>GraphicsContext.getClipWidth</code> and
	 * <code>GraphicsContext.getClipHeight</code> may not be identical to the clip values used in the low-level side. It
	 * is meant to be used as a debugging hint if a drawing seems incorrect.
	 *
	 * @see LLUI_DISPLAY_setClip
	 * @see LLUI_DISPLAY_intersectClip
	 */
	DRAWING_LOG_CLIP_MODIFIED = 1 << 3,

	/*
	 * @brief Flag stating that an undefined character was drawn.
	 *
	 * This happens when drawing a string that contains a character that is not included in the font used.
	 */
	DRAWING_LOG_MISSING_CHARACTER = 1 << 4,

	/*
	 * @brief Flag describing incidents occurring in a drawing library.
	 *
	 * Refer to the MicroUI implementation in the VEE port for more information about this incident.
	 */
	DRAWING_LOG_LIBRARY_INCIDENT = 1 << 29,

	/*
	 * @brief Flag describing incidents that do not match other values.
	 */
	DRAWING_LOG_UNKNOWN_INCIDENT = 1 << 30

} DRAWING_Incident;

/*
 * @brief Enumerates all MicroUI Image RAW formats.
 *
 * The type of the formats used by MicroUI and by the Graphics Engine is encoded on a jbyte (see sni.h).
 * This format can be cast with this enumeration:
 * - typedef MICROUI_Image: the image format
 * - all functions that use a jbyte format: LLUI_DISPLAY_IMPL_getDrawerIdentifier(), LLUI_DISPLAY_isDisplayFormat(), etc.
 * - the format returned by Format.getSNIContext() and OutputFormat.getSNIContext().
 */
typedef enum {
	/*
	 * @brief Defines an image with the same pixel representation and layout as
	 * the LCD memory.
	 */
	MICROUI_IMAGE_FORMAT_DISPLAY = 0x00,

	/*
	 * @brief Defines an image whose pixel format is ARGB8888.
	 */
	MICROUI_IMAGE_FORMAT_ARGB8888 = 0x02,

	/*
	 * @brief Defines an image whose pixel format is ARGB1555.
	 */
	MICROUI_IMAGE_FORMAT_ARGB1555 = 0x05,

	/*
	 * @brief Defines an image whose pixel format is ARGB4444.
	 */
	MICROUI_IMAGE_FORMAT_ARGB4444 = 0x06,

	/*
	 * @brief Defines an image whose pixel format is ARGB8888 pre-multiplied: each color component is multiplied by the
	 * opacity.
	 */
	MICROUI_IMAGE_FORMAT_ARGB8888_PRE = 0x18,

	/*
	 * @brief Defines an image whose pixel format is ARGB1555 pre-multiplied: each color component is multiplied by the
	 * opacity.
	 */
	MICROUI_IMAGE_FORMAT_ARGB1555_PRE = 0x19,

	/*
	 * @brief Defines an image whose pixel format is ARGB4444 pre-multiplied: each color component is multiplied by the
	 * opacity.
	 */
	MICROUI_IMAGE_FORMAT_ARGB4444_PRE = 0x1A,

	/*
	 * @brief Defines an image whose pixel format is RGB888.
	 */
	MICROUI_IMAGE_FORMAT_RGB888 = 0x03,

	/*
	 * @brief Defines an image whose pixel format is RGB565.
	 */
	MICROUI_IMAGE_FORMAT_RGB565 = 0x04,

	/*
	 * @brief Defines an image whose pixel format is Alpha1.
	 */
	MICROUI_IMAGE_FORMAT_A1 = 0x0C,

	/*
	 * @brief Defines an image whose pixel format is Alpha2.
	 */
	MICROUI_IMAGE_FORMAT_A2 = 0x0B,

	/*
	 * @brief Defines an image whose pixel format is Alpha4.
	 */
	MICROUI_IMAGE_FORMAT_A4 = 0x07,

	/*
	 * @brief Defines an image whose pixel format is Alpha8.
	 */
	MICROUI_IMAGE_FORMAT_A8 = 0x08,

	/*
	 * @brief Defines an image whose pixel format is Color1.
	 */
	MICROUI_IMAGE_FORMAT_C1 = 0x0F,

	/*
	 * @brief Defines an image whose pixel format is Color2.
	 */
	MICROUI_IMAGE_FORMAT_C2 = 0x0E,

	/*
	 * @brief Defines an image whose pixel format is Color4.
	 */
	MICROUI_IMAGE_FORMAT_C4 = 0x0D,

	/*
	 * @brief Defines an image whose pixel format is Alpha1-Color1.
	 */
	MICROUI_IMAGE_FORMAT_AC11 = 0x12,

	/*
	 * @brief Defines an image whose pixel format is Alpha2-Color2.
	 */
	MICROUI_IMAGE_FORMAT_AC22 = 0x11,

	/*
	 * @brief Defines an image whose pixel format is Alpha4-Color4.
	 */
	MICROUI_IMAGE_FORMAT_AC44 = 0x10,

	/*
	 * @brief Defines an image whose pixel format is a LUT entry on 8 bits and target
	 * an ARGB8888 color.
	 */
	MICROUI_IMAGE_FORMAT_LARGB8888 = 0x0A,

	/*
	 * @brief Defines an undefined format. Used by LLUI_DISPLAY_IMPL_decodeImage() to
	 * not specify a specific format.
	 */
	MICROUI_IMAGE_FORMAT_UNDEFINED = 0x80,

	/*
	 * @brief Defines the custom format 7.
	 */
	MICROUI_IMAGE_FORMAT_CUSTOM_7 = 0xF8,

	/*
	 * @brief Defines the custom format 6.
	 */
	MICROUI_IMAGE_FORMAT_CUSTOM_6 = 0xF9,

	/*
	 * @brief Defines the custom format 5.
	 */
	MICROUI_IMAGE_FORMAT_CUSTOM_5 = 0xFA,

	/*
	 * @brief Defines the custom format 4.
	 */
	MICROUI_IMAGE_FORMAT_CUSTOM_4 = 0xFB,

	/*
	 * @brief Defines the custom format 3.
	 */
	MICROUI_IMAGE_FORMAT_CUSTOM_3 = 0xFC,

	/*
	 * @brief Defines the custom format 2.
	 */
	MICROUI_IMAGE_FORMAT_CUSTOM_2 = 0xFD,

	/*
	 * @brief Defines the custom format 1.
	 */
	MICROUI_IMAGE_FORMAT_CUSTOM_1 = 0xFE,

	/*
	 * @brief Defines the custom format 0 (0xff).
	 */
	MICROUI_IMAGE_FORMAT_CUSTOM_0 = 0xFF,

} MICROUI_ImageFormat;

/*
 * @brief Represents a MicroUI Image.
 *
 * This structure is used by several drawing functions which use an image as source
 * image. It can be mapped on jbyte array given as parameter in some MicroUI natives.
 * This jbyte array is retrieved in MicroEJ application using the method Image.getData().
 *
 * Only the image size and format are available in this structure. Implementation
 * has to use some LLUI_DISPLAY.h functions to retrieve the image pixel's address and
 * some image characteristics.
 */
typedef struct {
	/*
	 * @brief Graphics Engine reserved field.
	 */
	jint reserved0;

	/*
	 * @brief MicroUI Image width in pixels.
	 */
	jchar width;

	/*
	 * @brief MicroUI Image height in pixels.
	 */
	jchar height;

	/*
	 * @brief Graphics Engine reserved field.
	 */
	jchar reserved1;

	/*
	 * @brief MicroUI Image pixel representation.
	 *
	 * The format is one value from the MICROUI_ImageFormat enumeration.
	 */
	jbyte format;

	/*
	 * @brief Graphics Engine reserved field.
	 */
	jbyte reserved2;

} MICROUI_Image;

/*
 * @brief Represents a MicroUI Graphics Context.
 *
 * This structure is used by all drawing functions to target the destination. It
 * can be mapped on jbyte array given as parameter in MicroUI natives. This jbyte
 * array is retrieved in MicroEJ application using the method GraphicsContext.getData().
 *
 * Only the graphics context size, format, color and clip are available in this
 * structure. Implementation has to use some LLUI_DISPLAY.h functions to retrieve the
 * graphics context pixels' addresses and some graphics context characteristics.
 */
typedef struct {
	/*
	 * @brief A graphics context targets a mutable image (size and format).
	 */
	MICROUI_Image image;

	/*
	 * @brief Current graphics context foreground color. This color must be used
	 * to render the drawing. The color format is 0xAARRGGBB (where alpha level
	 * is always 0xff == fully opaque).
	 */
	jint foreground_color;

	/*
	 * @brief Graphics Engine reserved field.
	 */
	jint reserved0;

	/*
	 * @brief Current clip.
	 *
	 * Read-only. Call LLUI_DISPLAY_setClip to modify this value.
	 */
	ui_rect_t clip;

	/*
	 * @brief Log flags from drawing operations.
	 */
	jint drawing_log_flags;

	/*
	 * @brief The drawing engine identifier. Useful to retrieve the engine able to
	 * draw in the GraphicsContext buffer. The "0" value indicates the default engine:
	 * the same engine used to draw in the display buffer.
	 * @see LLUI_DISPLAY_IMPL_getDrawerIdentifier()
	 */
	uint8_t drawer;

} MICROUI_GraphicsContext;

// --------------------------------------------------------------------------------
// EOF
// --------------------------------------------------------------------------------

#ifdef __cplusplus
}
#endif
#endif
