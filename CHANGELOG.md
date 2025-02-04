# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
_Copyright 2024-2025 MicroEJ Corp. All rights reserved._  
_Use of this source code is governed by a BSD-style license that can be found with this software._  
