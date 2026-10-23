# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.5.0] - 2026-10-23

### Added

- Add ABLA Essentials 1.1.0.
- Add the `LLDEVICE_SERIAL_NUMBER_FILE` and `LLDEVICE_MACHINE_ID_FILE` defines to set the files that give the device ID.
- Add the `LLNET_ASSERT` define to the Linux network configuration. Migration: copy `LLNET_linux_configuration.h` from this version to get it.
- Document the MISRA C:2012 compliance of the Crypto Abstraction Layer.
- Implement the crypto KeyGenerator abstraction layer, so an application can generate an AES key of 128, 192 or 256 bits on the target.

### Changed

- Log the abstraction layers through the ABLA Essentials logger.
- Throw the exceptions of the abstraction layers through the ABLA Essentials error helpers.
- Stop building the rio abstraction layer by default, because rio is experimental. Migration: set the `BUILD_RIO` CMake option to `ON` in the `project_options.cmake` of the VEE Port.
- Update the Crypto Foundation Library to 2.3.0.
- Take the device ID from the device tree serial number when the board publishes one.
- Report the standard not-implemented error code from `Device.getVersion()`, `Device.reboot()` and `Device.shutdown()`.
- Report the documented exception when a network interface native fails, instead of returning a negative error code.
- Reject a build that enables the network without any address family, instead of building a network stack that reports no address.
- Make the Core Abstraction Layer compliant with MISRA C:2012.
- Crypto:
  - Require the PKCS#11 login to succeed on the External KeyStore read paths, instead of reading with an unauthenticated session.
  - Restrict the External KeyStore password and the PKCS#11 PIN to ASCII characters.
  - Report the module's own error code in the crypto exceptions, instead of an OpenSSL return value or the rejected argument.
  - Report the error codes that the Crypto Foundation Library 2.3.0 declares.
  - Align the Crypto abstraction layer sources with the MicroEJ C coding conventions.
- Update to KF RAM Abstraction Layer 3.0.1.
- Update to FS Pack 6.0.5, the Event Foundation Library 3.0.7 and the Device Foundation Library 1.4.1.
- Update to SERIAL Pack 3.0.1.

### Removed

- Remove the `IFADDRNAMEMAX` network configuration define. Migration: the port uses the Linux `IFNAMSIZ` constant, so no configuration is needed.

### Fixed

- Fix the SSL socket timeout reported as a generic `IOException` instead of a `SocketTimeoutException` when rio is not built (introduced in version 3.4.0).
- Fix the crypto X509 certificate verification and validity check, which could return success after a failure.
- Fix `Key.getEncoded()` throwing an exception instead of returning `null` for a private key stored on a PKCS#11 token.
- Fix `ej.bon.Util.setCurrentTimeMillis()` ignoring a failure to set the clock: it now throws a `NativeException`.
- Fix `ej.util.Device.getId()` failing where no MAC address is available.
- Fix the device ID ignoring the MAC address of a network interface that has no IP address assigned.
- Fix memory leak in `LLKERNEL_IMPL_freeFeature`. The first installed feature was not properly freed during uninstallation.
- Fix the network interface list, where an interface could be missing and the interfaces after it reported at the wrong index.
- Fix network interfaces whose name is longer than 9 characters, such as a predictable-name USB Ethernet adapter, reporting no IP address.
- Fix a crash when a network interface carries no address in the enabled address families.
- Fix the network prefix length reported for an address whose prefix is not a multiple of 8.
- Fix the broadcast address reported for an address that has none.
- Fix a memory corruption when an IPv6 network interface address is read.
- Fix `java.net.NetworkInterface.isUp()` reporting an interface that is administratively up without a carrier as up.
- Crypto:
  - Fix the misleading package name in the error for a missing PKCS#11 header.
  - Hardening of input/output buffers for various operations.
  - Hardening of External keystore login, writes, alias truncations.
  - Fix the operations that returned a wrong result and reported success.
  - Erase the private keys, the secret keys, the keystore password/PIN from memory before they are freed.
  - Fix various corner cases in `Mac`, `Cipher`, `KeyPairGenerator`, `Signature` operations.

## [3.4.0] - 2026-07-20

### Added

- Add the rio event-driven I/O abstraction layer (LLRIO poll/select, net, and pipe). Net and SSL route their readiness wait through rio (`LLNET_rio.h` / `LLNET_SSL_rio.h`) when `BUILD_RIO` is on (the default), with an `async_select` fallback.
- Add External KeyStore abstraction layer (LLSEC) with PKCS#11 and PKCS#12 backends, selected at build time and configured entirely from compile-time defaults (no runtime environment variables). Supports reads, writes (`KeyStore.setKeyEntry` / `setCertificateEntry` / `deleteEntry`), and alias enumeration.
- Add Audio abstraction layer implementation (LLAUDIO sink and source) based on SDL2, enabled with the `BUILD_AUDIO` CMake option.
- Add `SerialConnection` (LLSERIAL) abstraction layer implementation for Linux.
- Add fd_monitor, a module that polls file descriptors for changes and notifies registered Java threads.
- Add `clean.sh` / `clean.bat` scripts to remove the C build outputs (CMake build directories, deployed `inc`/`lib` folders, generated application artifacts).

### Fixed

- Fix latent bugs surfaced by compiler warnings: bound the architecture-string copy in LLDEVICE, detect an unspecified IPv6 peer with `IN6_IS_ADDR_UNSPECIFIED` instead of an always-false array-address test, drop an always-false unsigned `< 0` check in the buffered write, parenthesize an assignment used as a condition, and initialize the network-interface flags read on the error path.
- Fix cancelling a scheduled request.
- Fix thread names for debugging.
- Fix `run.sh` (`LOCAL_DEPLOY`): `exec` the deployed executable and deploy it under a per-executable directory, so the run leaves no orphan and starting one app no longer kills another running instance sharing the default `/tmp` deploy path.
- Fix `OSAL_task_delete`: implemented with `pthread_join` to release zombie thread resources and prevent virtual address space exhaustion on long-running open/close cycles.

### Changed

- Move the UI port configuration from runtime environment variables to compile-time CMake options: framebuffer device (`LLDISPLAY_FBDEVICE`), touchscreen device (`LLTOUCH_TSDEVICE`), vsync (`BUILD_UI_VSYNC`, default `ON`), and 32bpp to 16bpp conversion (`BUILD_UI_CONVERT_32_TO_16_BPP`, default `OFF`). The application now runs with no port runtime environment.
- Migrate the Crypto (formerly Security) abstraction layer to the Crypto Foundation Library 2.0.1, renaming the port to `port/crypto` and the `BUILD_CRYPTO` option, and adding Key Agreement (ECDH), AES/GCM and AES/ECB ciphers, opaque key management, and multi-part cipher `update`/`doFinal` support.
- Update the MicroUI C Module to 14.5.2 and migrate the UI configuration to UI Pack 14.5.x: `ui_configuration.h` now ships with the C Module and includes the VEE Port `veeport_configuration.h` (in `port/config`), and the drawing-trace API moves to the new `ui_trace.h`.
- Separate the commercially-licensed MicroUI C Module from the BSD-licensed UI abstraction layer: the C Module sources move to `middleware/microui` (own `LICENSE.txt` and PROPRIETARY/CONFIDENTIAL copyright header), while the board-specific implementation (display, input, framerate, touch) stays in `port/ui` under the BSD license.
- Remove support for OpenSSL < 3.0.
- Update the Device Foundation Library to 1.4.0.
- Update the Event Foundation Library to 3.0.3.
- Build the VEE port C/C++ sources with `-Wall -Wextra -Werror` and fix all resulting warnings.

## [3.3.0] - 2025-09-05

### Fixed

- Fixed run.sh script for application.out deployment
- Fixed run.bat script for application.out deployment
- Fixed Windows paths in .bat scripts
- Fixed double free when using UI without a screen
- Fixed Cpp warnings
- Fixed a FS modified time issue when DST is active

### Changed

- Cmake binary dir is now named after the C compiler (allows multiple builds)
- Added a trap in build.sh script in case of build errors
- Updated to MicroUI implementation 14.4.2
- Create the set_local_env scripts from the template, and gitignore them.
- Updated to async-worker 0.6.0
- Updated to osal headers 1.0.3
- Updated to FS llimpl 3.0.6

## [3.2.0] - 2025-05-28

### Added

- Added Event queue implementation on posix

### Fixed

- Fixed a timeout in osal posix
- Fixed not implemented Device natives
- Fixed DNS resolution in dual stack mode

## [3.1.0] - 2025-03-20

### Changed

- Fix compatiblity with cmake 3.16 (Ubuntu 20.04)
- Update to UI pack 14.3.2

## [3.0.0] - 2025-01-04

### Changed

- Migrate to SDK6 folder structure
- Packs versions: switch from ANT properties to Gradle's version catalog (TOML)
- Cmake: rebuild only updated files
- Update headers files to align with architecture version 8.3.0
- add possibility to build with docker

### Fixed

- Fixed a SCP compatibility issue with Dropbear SSH servers
- Fixed a minor gcc warning with OpenSSL 1.1.1u

## [2.0.2] - 2024-11-15

### Changed

- Complete the description of the supported features

## [2.0.1] - 2024-11-12

### Changed

- Remove non public dependencies

## [2.0.0] - 2024-11-08

### Added

- CI running on X86 linux VEE port (core)
- Update to pack net 11 (net/ssl/security)
- change default HID input device to touchscreen0

### Changed

- Update to UI pack 14.0.1

## [1.0.0] - 2024-07-26

### Added

- First version of the generic linux BSP
- VEE Port BSP code centralized
- CMake configuration
- CCO installer
- DRM framebuffer implementation

---
_Markdown_  
_Copyright 2024-2026 MicroEJ Corp. All rights reserved._  
_Use of this source code is governed by a BSD-style license that can be found with this software._  
_Build: 7E4D1F7C_
