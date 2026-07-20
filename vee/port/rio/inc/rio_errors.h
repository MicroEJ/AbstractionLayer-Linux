/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief MicroEJ Java error codes for SNI_throwNativeIOException.
 *
 * Values match LLNET_ERRORS.h (com.is2t.errors.NetErrors) and
 * ej.rio.RioError on the Java side.  Defined here so all rio CCO
 * components (rio-core, rio-net-bsd, net-rio-wait) can share them without
 * depending on the net Foundation Library's LLNET_ERRORS.h.
 */

#ifndef RIO_ERRORS_H
#define RIO_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

#define J_EACCES        (-2)
#define J_EBADF         (-3)
#define J_EHOSTDOWN     (-4)
#define J_ENETDOWN      (-5)
#define J_ENETUNREACH   (-6)
#define J_EADDRINUSE    (-7)
#define J_ECONNABORTED  (-8)
#define J_EINVAL        (-9)
#define J_ENOPROTOOPT   (-10)
#define J_ENOTCONN      (-11)
#define J_EAFNOSUPPORT  (-12)
#define J_ECONNREFUSED  (-13)
#define J_EISCONN       (-14)
#define J_ECONNRESET    (-15)
#define J_EMSGSIZE      (-16)
#define J_EPIPE         (-17)
#define J_ETIMEDOUT     (-18)
#define J_ENOMEM        (-19)
#define J_EHOSTUNREACH  (-20)
#define J_EADDRNOTAVAIL (-22)
#define J_NETWORK_NOT_INITIALIZED (-25)
#define J_EUNKNOWN      (-255)

#ifdef __cplusplus
}
#endif

#endif /* RIO_ERRORS_H */
