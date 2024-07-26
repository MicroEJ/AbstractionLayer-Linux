/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */
#include "sni.h"

jfloat Java_com_microej_core_tests_MicroejCoreValidation_testFloat(jfloat a, jfloat b)
{
    return a * b;
}

jdouble Java_com_microej_core_tests_MicroejCoreValidation_testDouble(jdouble a, jdouble b)
{
    return a * b;
}

jint Java_com_microej_core_tests_MicroejCoreValidation_testNativeArguments01(jint i1, jint i2, jint i3, jint i4, jint i5, jint i6, jint i7, jint i8, jint i9, jint i10)
{
    jlong result = 0LL;
    if ((i1 == 0x01020304) &&
        (i2 == 0x05060708) &&
        (i3 == 0x090A0B0C) &&
        (i4 == 0x0D0E0F10) &&
        (i5 == 0x11121314) &&
        (i6 == 0x15161718) &&
        (i7 == 0x191A1B1C) &&
        (i8 == 0x1D1E1F20) &&
        (i9 == 0x21222324) &&
        (i10 == 0x25262728))
    {
        result = 0x292A2B2C;
    }
    return result;
}

jlong Java_com_microej_core_tests_MicroejCoreValidation_testNativeArguments02(jlong l1, jlong l2, jlong l3, jlong l4, jlong l5, jlong l6, jlong l7, jlong l8, jlong l9, jlong l10)
{
    jlong result = 0LL;
    if ((l1 == 0x2D2E2F3031323334LL) &&
        (l2 == 0x35363738393A3B3CLL) &&
        (l3 == 0x3D3E3F4041424344LL) &&
        (l4 == 0x45464748494A4B4CLL) &&
        (l5 == 0x4D4E4F5051525354LL) &&
        (l6 == 0x55565758595A5B5CLL) &&
        (l7 == 0x5D5E5F6061626364LL) &&
        (l8 == 0x65666768696A6B6CLL) &&
        (l9 == 0x6D6E6F7071727374LL) &&
        (l10 == 0x75767778797A7B7CLL))
    {
        result = 0x7D7E7F8081828384LL;
    }
    return result;
}

jlong Java_com_microej_core_tests_MicroejCoreValidation_testNativeArguments03(jint i1, jlong l2, jint i3, jlong l4, jint i5, jlong l6, jint i7, jlong l8, jint i9, jlong l10)
{
    jlong result = 0LL;
    if ((i1 == (jint) 0x85868788U) &&
        (l2 == (jlong) 0x898A8B8C8D8E8F90ULL) &&
        (i3 == (jint) 0x91929394U) &&
        (l4 == (jlong) 0x95969798999A9B9CULL) &&
        (i5 == (jint) 0x9D9E9FA0U) &&
        (l6 == (jlong) 0xA1A2A3A4A5A6A7A8ULL) &&
        (i7 == (jint) 0xA9AAABACU) &&
        (l8 == (jlong) 0xADAEAFB0B1B2B3B4ULL) &&
        (i9 == (jint) 0xB5B6B7B8U) &&
        (l10 == (jlong) 0xB9BABBBCBDBEBFC0ULL))
    {
        result = 0xC1C2C3C4C5C6C7C8ULL;
    }
    return result;
}

jfloat Java_com_microej_core_tests_MicroejCoreValidation_testNativeArguments04(jfloat f1, jfloat f2, jfloat f3, jfloat f4, jfloat f5, jfloat f6, jfloat f7, jfloat f8, jfloat f9, jfloat f10)
{
    jfloat result = 0.0f;
    if ((f1 == 1.0f) &&
        (f2 == 1.1f) &&
        (f3 == 1.2f) &&
        (f4 == 1.3f) &&
        (f5 == 1.4f) &&
        (f6 == 1.5f) &&
        (f7 == 1.6f) &&
        (f8 == 1.7f) &&
        (f9 == 1.8f) &&
        (f10 == 1.9f))
    {
        result = 2.0f;
    }
    return result;
}

jdouble Java_com_microej_core_tests_MicroejCoreValidation_testNativeArguments05(jdouble d1, jdouble d2, jdouble d3, jdouble d4, jdouble d5, jdouble d6, jdouble d7, jdouble d8, jdouble d9, jdouble d10)
{
    jdouble result = 0.0;
    if ((d1 == 2.0) &&
        (d2 == 2.1) &&
        (d3 == 2.2) &&
        (d4 == 2.3) &&
        (d5 == 2.4) &&
        (d6 == 2.5) &&
        (d7 == 2.6) &&
        (d8 == 2.7) &&
        (d9 == 2.8) &&
        (d10 == 2.9))
    {
        result = 3.0;
    }
    return result;
}

jdouble Java_com_microej_core_tests_MicroejCoreValidation_testNativeArguments06(jfloat f1, jdouble d2, jfloat f3, jdouble d4, jfloat f5, jdouble d6, jfloat f7, jdouble d8, jfloat f9, jdouble d10)
{
    jdouble result = 0.0;
    if ((f1 == 3.0f) &&
        (d2 == 3.1) &&
        (f3 == 3.2f) &&
        (d4 == 3.3) &&
        (f5 == 3.4f) &&
        (d6 == 3.5) &&
        (f7 == 3.6f) &&
        (d8 == 3.7) &&
        (f9 == 3.8f) &&
        (d10 == 3.9))
    {
        result = 4.0;
    }
    return result;
}