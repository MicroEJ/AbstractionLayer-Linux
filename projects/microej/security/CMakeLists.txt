# CMake
#
# Copyright 2012-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLSEC_CIPHER_openssl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLSEC_DIGEST_openssl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLSEC_KEY_FACTORY_openssl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLSEC_MAC_openssl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLSEC_RANDOM_openssl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLSEC_SIG_openssl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLSEC_X509_openssl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/OPENSSL_SECURITY_utils.c
)
