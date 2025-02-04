/*
 * C
 *
 * Copyright 2014-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <xf86drm.h>
#include <xf86drmMode.h>

#include "LLUI_DISPLAY_impl.h"
#include "LLDISPLAY_FB.h"
#include "LLDISPLAY_FB_drm.h"

static uint32_t buf_id = 0;
static uint32_t connector_id = 0;
static uint32_t crtc_id = 0;
static drmModeModeInfo mode_info;

int lldisplay_fb_drm_getscreeninfo(int fd, lldisplay_screeninfo_t* display_screeninfo) {
	int ret;
	uint64_t has_dumb;
	drmModeResPtr res = NULL;
	drmModeEncoderPtr encoder = NULL;
	drmModeConnectorPtr connector = NULL;
	drmModeModeInfoPtr mode = NULL;

	ret = drmGetCap(fd, DRM_CAP_DUMB_BUFFER, &has_dumb);
	if ((ret < 0) || !has_dumb) {
		LLDISPLAY_LOG_WARNING("Device does not support dumb buffers (%d): %m\n", errno);
		return -errno;

	}

	/* retrieve resources */
	res = drmModeGetResources(fd);
	if (!res) {
		LLDISPLAY_LOG_WARNING("cannot retrieve DRM resources (%d): %m\n", errno);
		return -errno;
	}
	if (res->count_connectors == 0) {
		LLDISPLAY_LOG_WARNING("No connector found\n");
		drmModeFreeResources(res);
		return -1;
	}

	/* Find the connector */
	for (int i = 0; i < res->count_connectors; i++) {
		connector = drmModeGetConnector(fd, res->connectors[i]);
		if (!connector) {
			LLDISPLAY_LOG_WARNING("cannot retrieve DRM connector %d:%u (%d): %m\n", i, res->connectors[i], errno);
			continue;
		}
		if (connector->connection == DRM_MODE_CONNECTED) {
#if 0 /* drmModeGetConnectorTypeName supported with libdrm >= 2.4.112 */
			LLDISPLAY_LOG_DEBUG("Found Connector: %d type %s\n", connector->connector_id, drmModeGetConnectorTypeName(connector->connector_type));
#endif
			break;
		}
		drmModeFreeConnector(connector);
	}

	/* check if we found a monitor connected */
	if (!connector) {
		LLDISPLAY_LOG_WARNING("Monitor not connected\n");
		drmModeFreeResources(res);
		return -1;
	}

	connector_id = connector->connector_id;

	/* check if there is at least one valid mode */
	if (connector->count_modes == 0) {
		LLDISPLAY_LOG_WARNING("no valid mode for connector\n");
		drmModeFreeConnector(connector);
		drmModeFreeResources(res);;
		return -1;
	}

	/* Get the preferred resolution if any */
	#if 0
	for (int i = 0; i < connector->count_modes; i++) {
			mode = &connector->modes[i];
			if (mode->type & DRM_MODE_TYPE_PREFERRED) {
				LLDISPLAY_LOG_DEBUG("found prefered\n");
				break;
			}
	}
	#else /* use the first one */
	mode = &connector->modes[0];
	#endif
	memcpy(&mode_info, mode, sizeof(drmModeModeInfo));

	LLDISPLAY_LOG_DEBUG("Selected mode: %dx%d\n", mode->hdisplay, mode->vdisplay);

	/* Get the crtc settings */
	if (connector->encoder_id != 0) {
		encoder = drmModeGetEncoder(fd, connector->encoder_id);
		if (!encoder) {
			LLDISPLAY_LOG_WARNING("Could retrieve encoder %u (%d): %m\n", connector->encoder_id, errno);
			return -errno;
		}
		LLDISPLAY_LOG_DEBUG("Found CRTC %u, encoder %u\n", encoder->crtc_id, encoder->encoder_id);
		crtc_id = encoder->crtc_id;
		drmModeFreeEncoder(encoder);
	} else if (connector->count_encoders > 0) {
		for (int i = 0; i < connector->count_encoders; i++) {
			encoder = drmModeGetEncoder(fd, connector->encoders[i]);
			if (!encoder) {
				LLDISPLAY_LOG_WARNING("Could retrieve encoder %d %u (%d): %m\n", i, connector->encoders[i], errno);
				continue;
			}
			/* iterate all global CRTCs */
			for (int j = 0; j < res->count_crtcs; ++j) {
				/* check whether this CRTC works with the encoder */
				if (!(encoder->possible_crtcs & (1 << j)))
					continue;
				crtc_id = res->crtcs[j];
				break;
			}
			if (crtc_id != 0) {
				LLDISPLAY_LOG_DEBUG("Found CRTC %u, encoder %u\n", encoder->crtc_id, encoder->encoder_id);
			}
			drmModeFreeEncoder(encoder);
		}
	} else {
		LLDISPLAY_LOG_WARNING("No encoder for this connector %u\n", connector->connector_id);
		crtc_id = 0;
	}
	if (!crtc_id) {
		LLDISPLAY_LOG_WARNING("Could not get encoder\n");
		drmModeFreeConnector(connector);
		drmModeFreeResources(res);
		return -1;
	}

	LLDISPLAY_LOG_DEBUG("Screen configuration done\n");

	display_screeninfo->width = mode->hdisplay;
	display_screeninfo->height = mode->vdisplay;
	display_screeninfo->bpp = 32; // FIXME


	drmModeFreeConnector(connector);
	drmModeFreeResources(res);
	return 0;
}

static int lldisplay_fb_drm_add_fb(int fd, lldisplay_screeninfo_t display_screeninfo, uint32_t *bo_handle) {
	int ret;
	struct drm_mode_create_dumb creq;

	/* create dumb buffer */
	memset(&creq, 0, sizeof(creq));
	creq.width = display_screeninfo.width;
	creq.height = display_screeninfo.height;
	creq.bpp = display_screeninfo.bpp;

	ret = drmIoctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &creq);
	if (ret == 0) {
		/* create framebuffer object for the dumb-buffer */
		ret = drmModeAddFB(fd, creq.width, creq.height, 24, 32, creq.pitch, creq.handle, &buf_id);
		if (ret == 0) {
			*bo_handle = creq.handle;
		} else {
			LLDISPLAY_LOG_WARNING("cannot add framebuffer (%d): %m\n", errno);
		}
	} else {
		LLDISPLAY_LOG_WARNING("cannot create dumb buffer (%d): %m\n", errno);
	}
	return ret;
}

static int lldisplay_fb_drm_map_fb(int fd, int screensize, char** fb_base, uint32_t bo_handle) {
	struct drm_mode_map_dumb mreq;
	int ret;

	/* prepare buffer for memory mapping */
	memset(&mreq, 0, sizeof(mreq));
	mreq.handle = bo_handle;
	ret = drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &mreq);
	if (ret >= 0) {
		*fb_base = mmap(0, screensize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mreq.offset);
		//cppcheck-suppress [misra-c2012-11.6] mmap returns (void *) -1
		if (*fb_base == MAP_FAILED) {
			LLDISPLAY_LOG_WARNING("mmap failed for size %d: %s\n", screensize, strerror(errno));
			ret = -errno;
		} else {
			ret = 0;
		}
	} else {
		LLDISPLAY_LOG_WARNING("cannot map dumb buffer (%d): %m\n", errno);
	}
	if (ret !=0) {
		drmModeRmFB(fd, buf_id);
	}
	return ret;
}


int lldisplay_fb_drm_create_fb(int fd, int screensize, lldisplay_screeninfo_t display_screeninfo, char** fb_base) {
	struct drm_mode_destroy_dumb dreq;
	int ret;
	uint32_t bo_handle = 0;

	ret = lldisplay_fb_drm_add_fb(fd, display_screeninfo, &bo_handle);

	if (ret == 0) {
		ret = lldisplay_fb_drm_map_fb(fd, screensize, fb_base, bo_handle);
	}

	if ((ret != 0) && (bo_handle != 0)) {
		memset(&dreq, 0, sizeof(dreq));
		dreq.handle = bo_handle;
		drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &dreq);
	}
	return ret;
}

int lldisplay_fb_drm_set_crtc(int fd) {
	drmModeCrtcPtr crtc;
	int ret;

	crtc = drmModeGetCrtc(fd, crtc_id);
	ret = drmModeSetCrtc(fd, crtc_id, buf_id, 0, 0, &connector_id, 1, &mode_info);
	if (ret != 0) {
		LLDISPLAY_LOG_WARNING("drmModeSetCrtc failed for crtc %u buf %u conn %u: %s\n", crtc_id, buf_id, connector_id, strerror(errno));
	}

	return ret;
}

void lldisplay_fb_drm_waitforvsync(int fd) {
	drm_wait_vblank_t blank;
	blank.request.type = DRM_VBLANK_RELATIVE;
	blank.request.sequence = 1;
	if (drmWaitVBlank(fd, (drmVBlankPtr) &blank) != 0) {
		LLDISPLAY_LOG_DEBUG("DRM error during vsync (%s)\n", strerror(errno));
		return;
	}
}