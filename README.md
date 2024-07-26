# Generic BSP for linux VEE ports

# Overview

This project contains all the necessary abstraction layers to run the VEE on a linux system.

A typical linux VEE port can use this module as its BSP.

# Usage

The VEE port configuration project must source the `configuration.xml` ANT script to deploy the following files:

- `set_project_env.sh`

=> used to set environment variables that might be used by the BSP

- `toolchain.cmake`

=> typical CMake toolchain configuration script, for example on X86:
```
# Copyright 2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# Toolchain settings
#

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR X86)

set(CMAKE_C_COMPILER i686-linux-gnu-gcc)

# fetch SYSROOT variable if set by Yocto SDK environment script
# set(CMAKE_SYSROOT $ENV{SDKTARGETSYSROOT})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
```

- `project_options.cmake`

This is where the project features configuration takes place.

Set custom CFLAGS options, ex:
```
#
# CFLAGS
#
# generate 32bit code, see https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html
set(CFLAGS ${CFLAGS} -m32)
# Prevent floating point comparison issues with 32bit code. Known GCC issue, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=323#c109
set(CFLAGS ${CFLAGS} -msse -mfpmath=sse)
```

Add custom code to the BSP
```
#
# BSP external source
#
set(BSP_EXTERNAL ../../../linux-bsp-x86)
# When specifying an out-of-tree source a binary directory must be explicitly specified
# here we will install the output files in a subdirectory of CMAKE_CURRENT_BINARY_DIR
add_subdirectory(${BSP_EXTERNAL} linux-bsp-x86)
```

Enable/Disable options defined in `projects/microej/options.cmake`, ex:
```
# Optional features
set(BUILD_UI_TOUCHSCREEN OFF)
# Debug features
set(BUILD_UI_FRAMERATE ON)
```

# Requirements

None.

# Dependencies

_All dependencies are retrieved transitively by MicroEJ Module Manager_.

# Source

N/A

# Restrictions

None.
---
_Copyright 2024 MicroEJ Corp. All rights reserved._
_Use of this source code is governed by a BSD-style license that can be found with this software._
