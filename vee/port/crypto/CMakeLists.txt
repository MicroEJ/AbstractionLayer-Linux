# CMake
#
# Copyright 2012-2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# Build: 7E4D1F7C

if(NOT BUILD_UTIL)
    message(FATAL_ERROR "BUILD_CRYPTO requires BUILD_UTIL (port/util provides sni_extras.h).")
endif()

target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/inc)
target_sources(${target}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_key.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_utils.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_AES_KEY_WRAP_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_CERT_PATH_VALIDATOR_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_CIPHER_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_DIGEST_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_EXTERNAL_KEYSTORE_common.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_KEY_AGREEMENT_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_KEY_FACTORY_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_KEY_GENERATOR_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_KEY_PAIR_GENERATOR_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_MAC_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_PRIVATE_KEY_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_PUBLIC_KEY_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_RANDOM_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_RSA_CIPHER_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_SECRET_KEY_FACTORY_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_SECRET_KEY_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_SIG_impl.c
    ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_X509_CERT_impl.c
)

if(LLCRYPTO_KEYSTORE_PKCS11)
    target_sources(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_EXTERNAL_KEYSTORE_pkcs11.c)

    # Lets backend-agnostic modules (e.g. key agreement) compile the direct
    # PKCS#11 C API fallback that bypasses pkcs11-provider's DER-wrapped ECDH
    # peer point, which the OP-TEE TA mis-parses.
    target_compile_definitions(${target} PRIVATE LLCRYPTO_KEYSTORE_PKCS11=1)

    # Non-extractable key import (HSM-grade): when ON, keys created by
    # setKeyEntry have CKA_SENSITIVE=TRUE and CKA_EXTRACTABLE=FALSE — bytes
    # cannot be read back from the token after import. When OFF (default),
    # keys are extractable so the testsuite's
    # `assertArrayEquals(originalKeyBytes, retrievedKeyBytes)` round-trip
    # check succeeds. Production deployments with a real HSM should set this
    # ON; downstream readback will return an empty getEncoded() (security-
    # correct) and the round-trip test will fail (expected).
    option(LLCRYPTO_PKCS11_NON_EXTRACTABLE_KEYS
        "Mark setKeyEntry-imported keys as CKA_SENSITIVE=TRUE / CKA_EXTRACTABLE=FALSE"
        OFF)
    if(LLCRYPTO_PKCS11_NON_EXTRACTABLE_KEYS)
        target_compile_definitions(${target} PRIVATE LLCRYPTO_PKCS11_NON_EXTRACTABLE_KEYS=1)
    endif()

    # Compiled-in PKCS#11 paths so application.out runs with no runtime
    # environment (no OPENSSL_CONF / OPENSSL_MODULES / LLCRYPTO_PKCS11_* needed).
    # A project sets these from project_options.cmake. The module path is
    # mandatory: it differs per backend, so there is no default worth guessing.
    # The others fall back to the C #ifndef defaults when unset. The application
    # reads no env vars at runtime.
    if(NOT LLCRYPTO_PKCS11_MODULE)
        message(FATAL_ERROR "LLCRYPTO_PKCS11_MODULE must be set in project_options.cmake: absolute path to the PKCS#11 module (.so) of the target token.")
    endif()
    target_compile_definitions(${target} PRIVATE LLCRYPTO_PKCS11_MODULE="${LLCRYPTO_PKCS11_MODULE}")
    if(DEFINED LLCRYPTO_OSSL_MODULES_DIR)
        target_compile_definitions(${target} PRIVATE LLCRYPTO_OSSL_MODULES_DIR="${LLCRYPTO_OSSL_MODULES_DIR}")
    endif()
    if(DEFINED LLCRYPTO_PKCS11_TOKEN)
        target_compile_definitions(${target} PRIVATE LLCRYPTO_PKCS11_TOKEN="${LLCRYPTO_PKCS11_TOKEN}")
    endif()

    # OASIS PKCS#11 v2.40 / v3.0 headers. Reads use OpenSSL pkcs11-provider
    # via OSSL_STORE; only the KeyStore.setKeyEntry / setCertificateEntry /
    # deleteEntry write paths use the PKCS#11 C API directly. Every compliant
    # PKCS#11 module exports exactly one symbol — C_GetFunctionList — which
    # returns a struct of function pointers for everything else; we resolve
    # that symbol once via dlopen()/dlsym() of the module path supplied by
    # LLCRYPTO_PKCS11_MODULE so the BSP stays backend-agnostic (SoftHSM2 on the
    # dev host, OP-TEE PKCS#11 TA on iMX boards, opensc on smartcards, ...).
    #
    # Header sources we accept:
    #   * Yocto/embedded sysroot: <sysroot>/usr/include/pkcs11.h
    #     (e.g. provided by p11-kit, opensc, optee-client/libckteec)
    #   * Ubuntu/Debian dev host: /usr/include/softhsm/pkcs11.h
    #     (libsofthsm2-dev)
    find_path(LLCRYPTO_PKCS11_INCLUDE_DIR NAMES pkcs11.h)
    if(NOT LLCRYPTO_PKCS11_INCLUDE_DIR)
        find_path(LLCRYPTO_PKCS11_INCLUDE_DIR
            NAMES pkcs11.h
            HINTS /usr/include/softhsm
            NO_CMAKE_FIND_ROOT_PATH
        )
    endif()
    if(NOT LLCRYPTO_PKCS11_INCLUDE_DIR)
        message(FATAL_ERROR "PKCS#11 header (pkcs11.h) not found. On Ubuntu/Debian install libsofthsm2-dev. On Yocto add a recipe that provides /usr/include/pkcs11.h to the SDK.")
    endif()
    message(STATUS "Using PKCS#11 headers from ${LLCRYPTO_PKCS11_INCLUDE_DIR}")
    target_include_directories(${target} PRIVATE ${LLCRYPTO_PKCS11_INCLUDE_DIR})
    # libdl is already linked at the parent CMakeLists level (used once at
    # startup to resolve C_GetFunctionList from the configured PKCS#11 module).
else()
    target_sources(${target} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/LLCRYPTO_EXTERNAL_KEYSTORE_pkcs12.c)

    # Compiled-in keystore file path so application.out runs with no runtime
    # environment. A project sets this from project_options.cmake; when unset
    # the C #ifndef fallback applies.
    if(DEFINED LLCRYPTO_KEYSTORE_PATH)
        target_compile_definitions(${target} PRIVATE LLCRYPTO_KEYSTORE_PATH="${LLCRYPTO_KEYSTORE_PATH}")
    endif()
endif()
