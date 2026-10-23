/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

#ifndef SNI_EXTRAS_H
#define SNI_EXTRAS_H

#include <sni.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The SNI ABI carries every native handle as a jint, so a port converts a pointer to a jint and
 * back. That conversion holds only while a jint can hold a pointer. A negative array length
 * rejects the build if it stops holding. */
/* cppcheck-suppress misra-c2012-2.3 ; the type is unused on purpose. It carries no value and
 * declares no object: only its length matters, and the length is negative when a jint stops
 * holding a pointer, which rejects the build. */
typedef char sni_jint_holds_a_pointer[(sizeof(void *) <= sizeof(jint)) ? 1 : -1];

/**
 * @brief Reads the length of an SNI Java array.
 *
 * SNI_getArrayLength (from sni.h) reads the length word stored just before the array data, so it
 * casts the void* array pointer to an object pointer (MISRA 11.5), casts it to a different object
 * type (MISRA 11.3) and offsets it (MISRA 18.4). All three are inherent to the MicroEJ SNI ABI and
 * cannot be avoided at the call site. Wrapping the macro in this one function isolates the
 * deviation to a single place for the whole VEE Port, instead of repeating it at every call site
 * across every module.
 *
 * SNI maps a Java null reference to JNULL, so a native receives a NULL array whenever the Java layer
 * passes null: the initialization vector of a cipher initialized without one, for example. A NULL
 * array holds no element, so this function reports a length of 0 instead of reading the length word
 * before address 0.
 *
 * @param[in] array the SNI array whose length is read.
 * @return the length of @p array in elements, or 0 if @p array is NULL.
 */
static inline int32_t sni_array_get_length(void *array) {
	int32_t length = 0;

	if (NULL != array) {
		/* cppcheck-suppress [misra-c2012-11.3, misra-c2012-11.5, misra-c2012-18.4] : the SNI array-length
		 * macro reads the length word before the array data; the void*-to-object cast (11.5), the
		 * object-to-object cast (11.3) and the offset (18.4) are all inherent to the MicroEJ SNI ABI */
		length = SNI_getArrayLength(array);
	}
	return length;
}

/**
 * @brief Checks that an (offset, length) pair addresses a valid sub-range of an SNI array.
 *
 * Use this for the common case where the caller supplies both the start offset and the number of
 * elements accessed. Both are signed so a negative caller value is rejected rather than wrapping to
 * a huge size_t downstream.
 *
 * @param[in] array  the SNI array.
 * @param[in] offset the start offset into @p array.
 * @param[in] length the number of elements accessed from @p offset.
 * @return true iff @p offset >= 0, @p length >= 0 and [offset, offset + length) fits within @p array.
 *         A NULL array has a length of 0, so only an empty range at offset 0 fits.
 */
static inline bool sni_array_contains_range(void *array, int32_t offset, int32_t length) {
	int32_t array_length = sni_array_get_length(array);

	/* length >= 0 is checked before the (array_length - length) subtraction, so the subtraction
	 * cannot be fed a negative length; offset >= 0 keeps the final comparison well-defined. */
	return (offset >= 0) && (length >= 0) && (offset <= (array_length - length));
}

/**
 * @brief Returns the number of elements available in an SNI array from @p offset.
 *
 * Use this where the accessed length is not supplied by the caller but derived from the array
 * itself, so that the offset check and the available-length computation cannot drift apart. The
 * subtraction is reached only once @p offset is known to be in range, so an out-of-range offset
 * cannot make it overflow.
 *
 * @param[in] array  the SNI array.
 * @param[in] offset the offset into @p array.
 * @return the number of elements from @p offset to the end of @p array, or -1 if @p offset is
 *         negative or past the end of @p array.
 */
static inline int32_t sni_array_get_avail(void *array, int32_t offset) {
	int32_t array_length = sni_array_get_length(array);
	int32_t avail = -1;

	if ((offset >= 0) && (offset <= array_length)) {
		avail = array_length - offset;
	}
	return avail;
}

/**
 * @brief Converts an SNI close function into the close id the Java layer expects.
 *
 * The LLAPI *_IMPL_get_close_id natives return the close id as an int32_t, so a close function
 * pointer has to cross the SNI boundary as an integer (MISRA 11.1, and 11.6 because the function
 * takes a void* parameter). The signature is fixed by the LLAPI, so the conversion cannot be
 * avoided at the call site. Wrapping it in this one function isolates the deviation to a single
 * place for the whole VEE Port, instead of repeating it in every module that registers an SNI
 * resource.
 *
 * @param[in] close_function the close function registered with SNI_registerResource.
 * @return @p close_function as the int32_t close id.
 */
static inline int32_t sni_close_id(SNI_closeFunction close_function) {
	/* cppcheck-suppress [misra-c2012-11.1, misra-c2012-11.6] ; See the description above: the LLAPI
	 * fixes the return type at int32_t, so the close function must cross the boundary as an
	 * integer. */
	return (int32_t)close_function;
}

#ifdef __cplusplus
}
#endif

#endif /* SNI_EXTRAS_H */
