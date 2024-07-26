/*
 * C
 *
 * Copyright 2019-2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 */

/**
 * @file
 * @brief MicroEJ Security low level API implementation for OpenSSL Library
 * @author MicroEJ Developer Team
 * @version 1.3.0
 * @date 15 June 2021
 */

#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <LLSEC_RANDOM_impl.h>
#include <sni.h>


static bool random_seed_init = false;

/**
 * Returns a nativeId.
 *
 * Throws NativeException on error.
 */
int32_t LLSEC_RANDOM_IMPL_init()
{
    if (!random_seed_init)
    {
        // Seed with a poll
        RAND_poll();
        random_seed_init = true;
    }
    return 1;
}

/**
 * Closes the resource related to the nativeId
 *
 * Throws NativeException on error.
 */
void LLSEC_RANDOM_IMPL_close(int32_t native_id)
{
}

/**
 * Generates random bytes
 *
 * @param native_id the resource's nativeId
 * @param rnd the buffer to fill with random bytes
 * @param size the size of rnd
 *
 * Throws NativeException on error.
 */
void LLSEC_RANDOM_IMPL_next_bytes(int32_t native_id, uint8_t* rnd, int32_t size)
{
    int rc = RAND_bytes(rnd, size);
    if (rc != 1)
    {
        SNI_throwNativeException(rc, "RAND_bytes failed");
    }
}

/**
 * Sets the seed of the PRNG
 *
 * @param native_id the resource's nativeId
 * @param seed the array of bytes used as a seed
 * @param size the size of seed
 *
 * Throws NativeException on error.
 */
void LLSEC_RANDOM_IMPL_set_seed(int32_t native_id, uint8_t* seed, int32_t size)
{
    // Redo seed
    RAND_seed(seed, size);
}

/**
 * Generates a new seed
 *
 * @param native_id the resource's nativeId
 * @param seed the array to fill with the seed
 * @param size the size of seed
 *
 * Throws NativeException on error.
 */
void LLSEC_RANDOM_IMPL_generate_seed(int32_t native_id, uint8_t* seed, int32_t size)
{
    int rc = RAND_bytes(seed, size);
    if (rc != 1)
    {
        SNI_throwNativeException(rc, "RAND_bytes failed");
    }
}

