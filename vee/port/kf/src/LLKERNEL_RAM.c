/*
 * C
 *
 * Copyright 2018-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLKERNEL RAM implementation.
 * @author MicroEJ Development Team
 * @version 3.0.1
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "LLKERNEL_RAM.h"
#include "LLKERNEL_impl.h"

VEEPORT_LOGGER_DEFINE_MODULE(LLKERNEL_LOG_MODULE_NAME, LLKERNEL_LOG_LEVEL)

#ifdef __cplusplus
extern "C" {
#endif

// Utility macros for allocating RAM and ROM areas with required alignment constraints
#define KERNEL_AREA_GET_MAX_SIZE(size, alignment) ((size) + ((alignment) - 1))
#define KERNEL_AREA_GET_START_ADDRESS(addr, \
									  alignment) ((void *)((((int32_t)(addr)) + (alignment) - 1) & ~((alignment) - 1)))

typedef struct installed_feature {
	void *ROM_area;
	void *RAM_area;
	int32_t ROM_area_size;
	int32_t RAM_area_size;
	struct installed_feature *next;
} installed_feature_t;

static installed_feature_t *first_installed_feature = NULL;

static int32_t nb_allocated_features = 0;

static const char *_error_code_to_str(uint32_t error_code) {
	const char *str = "";
	switch (error_code) {
	case LLKERNEL_FEATURE_INIT_ERROR_CORRUPTED_CONTENT:
		str = "CORRUPTED CONTENT";
		break;
	case LLKERNEL_FEATURE_INIT_ERROR_INCOMPATIBLE_KERNEL_WRONG_UID:
		str = "INCOMPATIBLE_KERNEL_WRONG_UID";
		break;
	case LLKERNEL_FEATURE_INIT_ERROR_TOO_MANY_INSTALLED:
		str = "TOO_MANY_INSTALLED";
		break;
	case LLKERNEL_FEATURE_INIT_ERROR_ALREADY_INSTALLED:
		str = "ALREADY_INSTALLED";
		break;
	case LLKERNEL_FEATURE_INIT_ERROR_INCOMPATIBLE_KERNEL_WRONG_ADDRESSES:
		str = "INCOMPATIBLE_KERNEL_WRONG_ADDRESSES";
		break;
	case LLKERNEL_FEATURE_INIT_ERROR_ROM_OVERLAP:
		str = "ROM_OVERLAP";
		break;
	case LLKERNEL_FEATURE_INIT_ERROR_RAM_OVERLAP:
		str = "RAM_OVERLAP";
		break;
	case LLKERNEL_FEATURE_INIT_ERROR_RAM_ADDRESS_CHANGED:
		str = "RAM_ADDRESS_CHANGED";
		break;
	default:
		VEEPORT_LOGGER_LOG_ERR("no LLKERNEL error code found for %d", (int)error_code);
		str = "UNKNOWN";
		break;
	}
	return str;
}

/**
 * @brief Get the address of the pointer that refers to a feature in the installed features list.
 *
 * The list head is one of these pointers. A caller therefore unlinks the first feature with no
 * special case.
 *
 * @param feature the feature to find. NULL is never in the list.
 * @return the address of the pointer that refers to the feature. When the feature is not in the
 *         list, the address of the terminating NULL pointer. That address is the insertion point
 *         for a new feature.
 */
static installed_feature_t ** _get_feature_link(const installed_feature_t *feature) {
	installed_feature_t **link = &first_installed_feature;

	while ((NULL != *link) && (feature != *link)) {
		link = &(*link)->next;
	}
	return link;
}

static bool _is_valid_feature_handle(const installed_feature_t *handle) {
	return NULL != *_get_feature_link(handle);
}

#ifdef KERNEL_RAM_IMPL_BESTFIT
/**
 * @brief Bestfit allocator instance.
 *
 */
static BESTFIT_ALLOCATOR bestfit_allocator_instance;

void LLKERNEL_RAM_BESTFIT_initialize(int32_t start_address, int32_t end_address) {
	BESTFIT_ALLOCATOR_new(&bestfit_allocator_instance);
	BESTFIT_ALLOCATOR_initialize(&bestfit_allocator_instance, start_address, end_address);
}

void * BESTFIT_ALLOCATOR_allocate_with_check(int32_t size) {
	void *result = NULL;
	if ((0 < size) && (INT_MAX > size)) {
		result = BESTFIT_ALLOCATOR_allocate(&bestfit_allocator_instance, (int32_t)(size));
	}
	return result;
}

#endif // KERNEL_RAM_IMPL_BESTFIT

int32_t LLKERNEL_IMPL_allocateFeature(int32_t size_ROM, int32_t size_RAM) {
	VEEPORT_LOGGER_LOG_DBG("(%d, %d)", size_ROM, size_RAM);
	int32_t ret = 0;

	if (LLKERNEL_MAX_NB_DYNAMIC_FEATURES == nb_allocated_features) {
		VEEPORT_LOGGER_LOG_ERR("the maximum number of installed dynamic features is reached");
	} else {
		int32_t total_size = (int32_t)sizeof(installed_feature_t);
		total_size += KERNEL_AREA_GET_MAX_SIZE(size_ROM, LLKERNEL_ROM_AREA_ALIGNMENT);
		total_size += KERNEL_AREA_GET_MAX_SIZE(size_RAM, LLKERNEL_RAM_AREA_ALIGNMENT);

		installed_feature_t *feature = (installed_feature_t *)KERNEL_MALLOC(total_size);
		if (NULL != feature) {
			// Initialize the new feature before it becomes reachable from the installed features list
			feature->ROM_area = KERNEL_AREA_GET_START_ADDRESS((void *)(((int32_t)feature) +
			                                                           ((int32_t)sizeof(installed_feature_t))),
			                                                  LLKERNEL_ROM_AREA_ALIGNMENT);
			feature->ROM_area_size = size_ROM;
			feature->RAM_area = KERNEL_AREA_GET_START_ADDRESS((void *)(((int32_t)feature->ROM_area) + size_ROM),
			                                                  LLKERNEL_RAM_AREA_ALIGNMENT);
			feature->RAM_area_size = size_RAM;
			feature->next = NULL;

			// Add the new feature at the end of the installed features list
			*_get_feature_link(NULL) = feature;
			++nb_allocated_features;

			ret = (int32_t)feature;
		}
		// else Out of memory
	}
	return ret;
}

void LLKERNEL_IMPL_freeFeature(int32_t handle) {
	VEEPORT_LOGGER_LOG_DBG("(0x%.8x)", handle);

	// Remove installed feature from the installed features list
	installed_feature_t *remove_feature = (installed_feature_t *)handle;
	installed_feature_t **link = _get_feature_link(remove_feature);

	if (NULL == *link) {
		VEEPORT_LOGGER_LOG_ERR("cannot free the feature: feature not found (handle=0x%.8x)", (unsigned int)handle);
	} else {
		*link = remove_feature->next;
		--nb_allocated_features;
		KERNEL_FREE((void *)handle);
	}
}

// cppcheck-suppress [misra-c2012-5.5] Macro name is configured in VEE Port headers.
int32_t LLKERNEL_IMPL_getAllocatedFeaturesCount(void) {
	VEEPORT_LOGGER_LOG_DBG("()");
	VEEPORT_LOGGER_LOG_INF("%d feature(s) allocated", nb_allocated_features);
	return nb_allocated_features;
}

int32_t LLKERNEL_IMPL_getFeatureHandle(int32_t allocation_index) {
	VEEPORT_LOGGER_LOG_DBG("(%d)", allocation_index);
	int32_t ret = 0;

	installed_feature_t *ptr_feature = first_installed_feature;
	int32_t tmp_index = 0;
	while ((NULL != ptr_feature) && (tmp_index != allocation_index)) {
		ptr_feature = ptr_feature->next;
		++tmp_index;
	}

	if (NULL == ptr_feature) {
		// Allocation index not in range of allocated features count
		VEEPORT_LOGGER_LOG_ERR("no feature found at index (allocation_index=%d)", allocation_index);
	} else {
		ret = (int32_t)ptr_feature;
	}
	return ret;
}

void * LLKERNEL_IMPL_getFeatureAddressRAM(int32_t handle) {
	VEEPORT_LOGGER_LOG_DBG("(0x%.8x)", handle);
	void *ret = NULL;

	// Check if feature handle is valid (not freed)
	if (false == _is_valid_feature_handle((installed_feature_t *)handle)) {
		VEEPORT_LOGGER_LOG_ERR("feature handle not valid (handle=0x%.8x)", (unsigned int)handle);
	} else {
		ret = ((installed_feature_t *)handle)->RAM_area;
	}
	return ret;
}

void * LLKERNEL_IMPL_getFeatureAddressROM(int32_t handle) {
	VEEPORT_LOGGER_LOG_DBG("(0x%.8x)", handle);
	void *ret = NULL;

	// Check if feature handle is valid (not freed)
	if (false == _is_valid_feature_handle((installed_feature_t *)handle)) {
		VEEPORT_LOGGER_LOG_ERR("feature handle not valid (handle=0x%.8x)", (unsigned int)handle);
	} else {
		ret = ((installed_feature_t *)handle)->ROM_area;
	}
	return ret;
}

int32_t LLKERNEL_IMPL_copyToROM(void *dest_address_ROM, void *src_address, int32_t size) {
	VEEPORT_LOGGER_LOG_DBG("(0x%.8x, 0x%.8x, %d)", (unsigned int)dest_address_ROM, (unsigned int)src_address, size);
	int32_t ret = LLKERNEL_ERROR;

	// Check function parameters consistency
	if ((NULL == dest_address_ROM) || (NULL == src_address) || (size < 0)) {
		VEEPORT_LOGGER_LOG_ERR("wrong parameters passed");
	} else {
		// Check that copy to ROM area match an allocated installed feature ROM area
		installed_feature_t *ptr_feature = first_installed_feature;
		while (NULL != ptr_feature) {
			uint32_t ptr_feature_ROM_area_end = ((uint32_t)ptr_feature->ROM_area) +
			                                    ((uint32_t)ptr_feature->ROM_area_size);
			if ((size <= ptr_feature->ROM_area_size) &&
			    (((uint32_t)dest_address_ROM) >= ((uint32_t)ptr_feature->ROM_area)) &&
			    (((uint32_t)dest_address_ROM) < ptr_feature_ROM_area_end) &&
			    (((uint32_t)dest_address_ROM + ((uint32_t)size)) <= ptr_feature_ROM_area_end)) {
				// ROM destination address match an allocated installed feature ROM area
				// cppcheck-suppress [misra-c2012-17.7] no need to check memcpy return value here
				memcpy(dest_address_ROM, src_address, size);
				break;
			}
			ptr_feature = ptr_feature->next;
		}

		if (NULL == ptr_feature) {
			VEEPORT_LOGGER_LOG_ERR("the ROM destination address does not match the installed feature ROM area");
		} else {
			ret = LLKERNEL_OK;
		}
	}
	return ret;
}

// cppcheck-suppress [misra-c2012-5.5] Macro name is configured in VEE Port headers.
int32_t LLKERNEL_IMPL_flushCopyToROM(void) {
	VEEPORT_LOGGER_LOG_DBG("()");
	// Nothing to do here, flush already done
	return LLKERNEL_OK;
}

int32_t LLKERNEL_IMPL_onFeatureInitializationError(int32_t handle, int32_t error_code) {
	VEEPORT_LOGGER_LOG_ERR("cannot initialize the feature handle 0x%.8x, error %d (%s)", (int)handle, (int)error_code,
	                       _error_code_to_str(error_code));
	switch (error_code) {
	case LLKERNEL_FEATURE_INIT_ERROR_CORRUPTED_CONTENT:
		VEEPORT_LOGGER_LOG_ERR("feature detected but its content is corrupted, uninstalling it to free the memory");
		LLKERNEL_IMPL_freeFeature(handle);
		break;
	case LLKERNEL_FEATURE_INIT_ERROR_INCOMPATIBLE_KERNEL_WRONG_UID:
		VEEPORT_LOGGER_LOG_ERR(
			"feature detected but not compatible with the Kernel, uninstalling it to free the memory");
		LLKERNEL_IMPL_freeFeature(handle);
		break;
	case LLKERNEL_FEATURE_INIT_ERROR_INCOMPATIBLE_KERNEL_WRONG_ADDRESSES:
		VEEPORT_LOGGER_LOG_ERR("feature detected but its addresses are wrong, uninstalling it to free the memory");
		LLKERNEL_IMPL_freeFeature(handle);
		break;
	default:
		break;
	}

	return LLKERNEL_OK;
}

#ifdef __cplusplus
}
#endif
