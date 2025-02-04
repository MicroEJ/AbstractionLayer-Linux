/*
 * C
 *
 * Copyright 2015-2022 MicroEJ Corp. All rights reserved.
 * This library is provided in source code for use, modification and test, subject to license terms.
 * Any modification of the source code will break MicroEJ Corp. warranties on the whole library.
 */

#ifndef INTERN_LLDEVICE_IMPL_H
#define INTERN_LLDEVICE_IMPL_H

#ifdef __cplusplus
	extern "C" {
#endif

#define LLDEVICE_IMPL_getArchitecture Java_ej_util_DeviceNatives_getArchitecture
#define LLDEVICE_IMPL_getId Java_ej_util_DeviceNatives_getId
#define LLDEVICE_IMPL_getVersion Java_ej_util_DeviceNatives_getVersion
#define LLDEVICE_IMPL_reboot Java_ej_util_DeviceNatives_reboot
#define LLDEVICE_IMPL_shutdown Java_ej_util_DeviceNatives_shutdown

#ifdef __cplusplus
	}
#endif

#endif // INTERN_LLDEVICE_IMPL_H
