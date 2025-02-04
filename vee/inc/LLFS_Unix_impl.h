/*
 * C
 *
 * Copyright 2016-2021 MicroEJ Corp. All rights reserved.
 * This library is provided in source code for use, modification and test, subject to license terms.
 * Any modification of the source code will break MicroEJ Corp. warranties on the whole library.
 */
#ifndef LLFS_UNIX_IMPL
#define LLFS_UNIX_IMPL

/**
 * @file
 * @brief MicroEJ FS Unix low level API
 * @author MicroEJ Developer Team
 * @version 2.0.1
 * @date 28 March 2022
 */

#include <stdint.h>
#include <intern/LLFS_Unix_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Convert a pathname to canonical form.  The input path (path) is assumed to contain
 * no duplicate slashes. The result is stored in canonicalizePath.
 * On POSIX we can use realpath() to do this work.<p>
 * This method may not throw a NativeIOException if the file referenced by the given path
 * does not exist.
 *
 * @param path
 * 			path to canonicalize
 *
 * @param canonicalizePath
 * 			buffer to fill with the canonicalized path
 *
 * @param canonicalizePathLength
 * 			length of canonicalizePath
 *
 * @note Throws NativeIOException on error.
 *
 * @warning path and canonicalizePath must not be used outside of the VM task or saved.
 */
void LLFS_Unix_IMPL_canonicalize(uint8_t* path, uint8_t* canonicalizePath, int32_t canonicalizePathLength);


#ifdef __cplusplus
}
#endif

#endif
