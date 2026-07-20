/*
 * Copyright 2020-2025 MicroEJ Corp. All rights reserved.
 * MicroEJ Corp. PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

/*
 * @file
 * @brief This file implements all "Drawing" (MicroUI extended library) drawing native functions.
 * @see LLDW_PAINTER_impl.h file comment
 * @author MicroEJ Developer Team
 * @version 14.5.2
 * @since MicroEJ UI Pack 13.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

// implements LLDW_PAINTER_impl functions
#include <LLDW_PAINTER_impl.h>

// use graphical engine functions to synchronize drawings
#include <LLUI_DISPLAY.h>

// calls ui_drawing functions
#include "ui_drawing.h"

// traces the drawings
#include "ui_trace.h"

// --------------------------------------------------------------------------------
// LLDW_PAINTER_impl.h functions
// --------------------------------------------------------------------------------

void LLDW_PAINTER_IMPL_drawThickFadedPoint(MICROUI_GraphicsContext *gc, jint x, jint y, jint thickness, jint fade) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawThickFadedPoint)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawThickFadedPoint, gc, x, y, thickness, fade);
		if ((thickness > 0) || (fade > 0)) {
			status = UI_DRAWING_drawThickFadedPoint(gc, x, y, thickness, fade);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawThickFadedPoint, status);
	}
}

void LLDW_PAINTER_IMPL_drawThickFadedLine(MICROUI_GraphicsContext *gc, jint startX, jint startY, jint endX, jint endY,
                                          jint thickness, jint fade, DRAWING_Cap startCap, DRAWING_Cap endCap) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawThickFadedLine)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawThickFadedLine, gc, startX, startY, endX, endY, thickness, fade);
		if ((thickness > 0) || (fade > 0)) {
			status = UI_DRAWING_drawThickFadedLine(gc, startX, startY, endX, endY, thickness, fade, startCap, endCap);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawThickFadedLine, status);
	}
}

void LLDW_PAINTER_IMPL_drawThickFadedCircle(MICROUI_GraphicsContext *gc, jint x, jint y, jint diameter, jint thickness,
                                            jint fade) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawThickFadedCircle)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawThickFadedCircle, gc, x, y, diameter, thickness, fade);
		if ((thickness > 0) || (fade > 0)) {
			status = UI_DRAWING_drawThickFadedCircle(gc, x, y, diameter, thickness, fade);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawThickFadedCircle, status);
	}
}

void LLDW_PAINTER_IMPL_drawThickFadedCircleArc(MICROUI_GraphicsContext *gc, jint x, jint y, jint diameter,
                                               jfloat startAngle, jfloat arcAngle, jint thickness, jint fade,
                                               DRAWING_Cap start, DRAWING_Cap end) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawThickFadedCircleArc)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawThickFadedCircleArc, gc, x, y, diameter, (uint32_t)startAngle, (uint32_t)arcAngle,
		                    thickness, fade);
		if (((thickness > 0) || (fade > 0)) && (diameter > 0) && ((int32_t)arcAngle != 0)) {
			status = UI_DRAWING_drawThickFadedCircleArc(gc, x, y, diameter, startAngle, arcAngle, thickness, fade,
			                                            start, end);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawThickFadedCircleArc, status);
	}
}

void LLDW_PAINTER_IMPL_drawThickFadedEllipse(MICROUI_GraphicsContext *gc, jint x, jint y, jint width, jint height,
                                             jint thickness, jint fade) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawThickFadedEllipse)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawThickFadedEllipse, gc, x, y, width, height, thickness, fade);
		if (((thickness > 0) || (fade > 0)) && (width > 0) && (height > 0)) {
			status = UI_DRAWING_drawThickFadedEllipse(gc, x, y, width, height, thickness, fade);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawThickFadedEllipse, status);
	}
}

void LLDW_PAINTER_IMPL_drawThickLine(MICROUI_GraphicsContext *gc, jint startX, jint startY, jint endX, jint endY,
                                     jint thickness) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawThickLine)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawThickLine, gc, startX, startY, endX, endY, thickness);
		if (thickness > 0) {
			status = UI_DRAWING_drawThickLine(gc, startX, startY, endX, endY, thickness);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawThickLine, status);
	}
}

void LLDW_PAINTER_IMPL_drawThickCircle(MICROUI_GraphicsContext *gc, jint x, jint y, jint diameter, jint thickness) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawThickCircle)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawThickCircle, gc, x, y, diameter, thickness);
		if ((thickness > 0) && (diameter > 0)) {
			status = UI_DRAWING_drawThickCircle(gc, x, y, diameter, thickness);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawThickCircle, status);
	}
}

void LLDW_PAINTER_IMPL_drawThickEllipse(MICROUI_GraphicsContext *gc, jint x, jint y, jint width, jint height,
                                        jint thickness) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawThickEllipse)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawThickEllipse, gc, x, y, width, height, thickness);
		if ((thickness > 0) && (width > 0) && (height > 0)) {
			status = UI_DRAWING_drawThickEllipse(gc, x, y, width, height, thickness);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawThickEllipse, status);
	}
}

void LLDW_PAINTER_IMPL_drawThickCircleArc(MICROUI_GraphicsContext *gc, jint x, jint y, jint diameter, jfloat startAngle,
                                          jfloat arcAngle, jint thickness) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawThickCircleArc)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawThickCircleArc, gc, x, y, diameter, (uint32_t)startAngle, (uint32_t)arcAngle,
		                    thickness);
		if ((thickness > 0) && (diameter > 0) && ((int32_t)arcAngle != 0)) {
			status = UI_DRAWING_drawThickCircleArc(gc, x, y, diameter, startAngle, arcAngle, thickness);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawThickCircleArc, status);
	}
}

void LLDW_PAINTER_IMPL_drawFlippedImage(MICROUI_GraphicsContext *gc, MICROUI_Image *img, jint regionX, jint regionY,
                                        jint width, jint height, jint x, jint y, DRAWING_Flip transformation,
                                        jint alpha) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawFlippedImage)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawFlippedImage, gc, UI_TRACE_IMAGE(img), regionX, regionY, width, height, x, y,
		                    transformation, alpha);
		if (!LLUI_DISPLAY_isImageClosed(img) && (alpha > 0)) {
			status = UI_DRAWING_drawFlippedImage(gc, img, regionX, regionY, width, height, x, y,
			                                     transformation, alpha);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawFlippedImage, status);
	}
}

void LLDW_PAINTER_IMPL_drawRotatedImageNearestNeighbor(MICROUI_GraphicsContext *gc, MICROUI_Image *img, jint x, jint y,
                                                       jint rotationX, jint rotationY, jfloat angle, jint alpha) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawRotatedImageNearestNeighbor)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawRotatedImage, gc, UI_TRACE_IMAGE(img), x, y, rotationX, rotationY, (uint32_t)angle,
		                    alpha,
		                    UI_TRACE_NearestNeighbor);
		if (!LLUI_DISPLAY_isImageClosed(img) && (alpha > 0)) {
			status = UI_DRAWING_drawRotatedImageNearestNeighbor(gc, img, x, y, rotationX, rotationY, angle,
			                                                    alpha);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawRotatedImage, status);
	}
}

void LLDW_PAINTER_IMPL_drawRotatedImageBilinear(MICROUI_GraphicsContext *gc, MICROUI_Image *img, jint x, jint y,
                                                jint rotationX, jint rotationY, jfloat angle, jint alpha) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawRotatedImageBilinear)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawRotatedImage, gc, UI_TRACE_IMAGE(img), x, y, rotationX, rotationY, (uint32_t)angle,
		                    alpha,
		                    UI_TRACE_Bilinear);
		if (!LLUI_DISPLAY_isImageClosed(img) && (alpha > 0)) {
			status = UI_DRAWING_drawRotatedImageBilinear(gc, img, x, y, rotationX, rotationY, angle, alpha);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawRotatedImage, status);
	}
}

void LLDW_PAINTER_IMPL_drawScaledImageNearestNeighbor(MICROUI_GraphicsContext *gc, MICROUI_Image *img, jint x, jint y,
                                                      jfloat factorX, jfloat factorY, jint alpha) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawScaledImageNearestNeighbor)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawScaledImage, gc, UI_TRACE_IMAGE(img), x, y, (uint32_t)factorX, (uint32_t)factorY, alpha,
		                    UI_TRACE_NearestNeighbor);
		if (!LLUI_DISPLAY_isImageClosed(img) && (alpha > 0) && (factorX > 0.f) && (factorY > 0.f)) {
			status = UI_DRAWING_drawScaledImageNearestNeighbor(gc, img, x, y, factorX, factorY, alpha);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawScaledImage, status);
	}
}

void LLDW_PAINTER_IMPL_drawScaledImageBilinear(MICROUI_GraphicsContext *gc, MICROUI_Image *img, jint x, jint y,
                                               jfloat factorX, jfloat factorY, jint alpha) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawScaledImageBilinear)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawScaledImage, gc, UI_TRACE_IMAGE(img), x, y, (uint32_t)factorX, (uint32_t)factorY, alpha,
		                    UI_TRACE_Bilinear);
		if (!LLUI_DISPLAY_isImageClosed(img) && (alpha > 0) && (factorX > 0.f) && (factorY > 0.f)) {
			status = UI_DRAWING_drawScaledImageBilinear(gc, img, x, y, factorX, factorY, alpha);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawScaledImage, status);
	}
}

void LLDW_PAINTER_IMPL_drawScaledStringBilinear(MICROUI_GraphicsContext *gc, jchar *chars, jint length,
                                                MICROUI_Font *font, jint x, jint y, jfloat xRatio, jfloat yRatio) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawScaledStringBilinear)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawScaledString, gc, length, x, y, (uint32_t)xRatio, (uint32_t)yRatio, UI_TRACE_Bilinear);
		if ((length > 0) && (xRatio > 0) && (yRatio > 0)) {
			status = UI_DRAWING_drawScaledStringBilinear(gc, chars, length, font, x, y, xRatio, yRatio);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawScaledString, status);
	}
}

void LLDW_PAINTER_IMPL_drawScaledRenderableStringBilinear(MICROUI_GraphicsContext *gc, jchar *chars, jint length,
                                                          MICROUI_Font *font, jint width,
                                                          MICROUI_RenderableString *renderableString, jint x, jint y,
                                                          jfloat xRatio, jfloat yRatio) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawScaledRenderableStringBilinear)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawScaledRenderableString, gc, length, x, y, (uint32_t)xRatio, (uint32_t)yRatio,
		                    UI_TRACE_Bilinear);
		if ((length > 0) && (xRatio > 0) && (yRatio > 0)) {
			status = UI_DRAWING_drawScaledRenderableStringBilinear(gc, chars, length, font, width, renderableString, x,
			                                                       y, xRatio, yRatio);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawScaledRenderableString, status);
	}
}

void LLDW_PAINTER_IMPL_drawCharWithRotationBilinear(MICROUI_GraphicsContext *gc, jchar c, MICROUI_Font *font, jint x,
                                                    jint y, jint xRotation, jint yRotation, jfloat angle, jint alpha) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawCharWithRotationBilinear)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawRotatedCharacter, gc, c, x, y, xRotation, yRotation, (uint32_t)angle, (uint32_t)alpha,
		                    UI_TRACE_Bilinear);
		if (alpha > 0) {
			status = UI_DRAWING_drawCharWithRotationBilinear(gc, c, font, x, y, xRotation, yRotation, angle, alpha);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawRotatedCharacter, status);
	}
}

void LLDW_PAINTER_IMPL_drawCharWithRotationNearestNeighbor(MICROUI_GraphicsContext *gc, jchar c, MICROUI_Font *font,
                                                           jint x, jint y, jint xRotation, jint yRotation, jfloat angle,
                                                           jint alpha) {
	if (LLUI_DISPLAY_requestDrawing(gc, (SNI_callback)LLDW_PAINTER_IMPL_drawCharWithRotationNearestNeighbor)) {
		DRAWING_Status status = DRAWING_DONE;
		UI_TRACE_DRAW_START(drawRotatedCharacter, gc, c, x, y, xRotation, yRotation, (uint32_t)angle, (uint32_t)alpha,
		                    UI_TRACE_NearestNeighbor);
		if (alpha > 0) {
			status = UI_DRAWING_drawCharWithRotationNearestNeighbor(gc, c, font, x, y, xRotation, yRotation, angle,
			                                                        alpha);
		}
		LLUI_DISPLAY_setDrawingStatus(status);
		UI_TRACE_DRAW_END(drawRotatedCharacter, status);
	}
}

// --------------------------------------------------------------------------------
// EOF
// --------------------------------------------------------------------------------
