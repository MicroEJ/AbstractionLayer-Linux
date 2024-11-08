# Generic Abstraction layers for Linux VEE ports

# Overview

This project contains all the abstraction layers implementation to run the VEE on a Linux system.

It also contains a cmake project with differents sets of configuration (toolchains, features).

This abstraction layer requires a GNU GCC 32 bit toolchain as well as a few listed C librairies, see [Requirements](#requirements)

## Abstraction layers supported

| Foundation Library | Version |
| ------------------ | ------- |
| BON                | 1.4     |
| DEVICE             | 1.2     |
| DRAWING            | 1.0     |
| ECOM-NETWORK       | 2.1     |
| FS                 | 2.1     |
| KF                 | 1.7     |
| MICROUI            | 3.5     |
| NET                | 1.1     |
| RESOURCEMANAGER    | 1.0     |
| SECURITY           | 1.7     |
| SNI                | 1.4     |
| SSL                | 2.2     |
| TRACE              | 1.1     |
| WATCHDOG           | 1.0     |

# Usage

This project has 2 configuration steps.

First you [add this abstraction layer into a Linux VEE port project](#how-to-use-this-abstraction-layer-in-a-linux-vee-port)

Then you [customize the features for your VEE port requirements](#how-to-customize-the-vee-port)

# How to use this abstraction layer in a Linux VEE port

A typical Linux VEE port can use this abstraction layer as its BSP to build and run the VEE.

See MicroEJ documentation about [BSP connection](https://docs.microej.com/en/latest/VEEPortingGuide/bspConnection.html#bsp-connection)

The following folder structure can be used:
- a VEE port configuration project containing the board specific configurations (see details below)
- a VEE port abstraction layer (the current repository, named `Linux-abstractionlayer`), with all the necessary C abstraction layers and scripts.

It should look like this:
```
Linux-configuration/
├── bsp
│   ├── bsp.properties
│   └── scripts
│       ├── project_options.cmake
│       ├── set_project_env.sh
│       └── toolchain.cmake
├── configuration.xml
├── module.ivy
└── override.module.ant
Linux-abstractionlayer/
└── projects
    └── microej
        └── ...
```

- The VEE port configuration project uses variables to locate the `Linux-abstractionlayer` folder.
For example in `Linux-configuration/bsp/bsp.properties`:
```
microejapp.relative.dir=projects/microej/platform/lib
microejlib.relative.dir=projects/microej/platform/lib
microejinc.relative.dir=projects/microej/platform/inc
microejscript.relative.dir=projects/microej/scripts
root.dir=${project.parent.dir}/Linux-abstractionlayer
```

- The VEE port configuration project imports the `module.properties` file.
For example in `Linux-configuration/override.module.ant`:
```
        <property file="${override.module.dir}/../Linux-abstractionlayer/module.properties"/>
```

- The VEE port configuration project imports the `configuration.xml` file.
For example in `Linux-configuration/configuration.xml`:
```
        <!-- Import BSP Configuration script -->
        <import file="${project.parent.dir}/Linux-abstractionlayer/configuration.xml"/>
```

# How to customize the VEE port

## Build & Run Scripts

In the directory ``project/microej/scripts/`` are scripts that can be used to build and flash the executable.  
The ``.bat`` and ``.sh`` scripts are meant to run in a Windows and Linux environment respectively.

- The ``build*`` scripts are used to compile and link the abstraction layers with a MicroEJ Application to produce a MicroEJ executable (``application.out``) that can be run on a linux device.

  The ``build*`` scripts work out of the box, assuming the toolchain is configured properly, see :ref:`Plaftorm configuration section`

- The ``run*`` scripts are used to send and execute a MicroEJ executable (``application.out``) on a device, over SSH.

The environment variables can be defined globally by the user or in the ``set_local_env*`` scripts.  When the ``.bat`` (``.sh``) scripts are executed, the ``set_local_env.bat`` (``set_local_env.sh``) script is executed if it exists.
Create and configure these files to customize the environment locally.

## Host configuration

### target SSH configuration

See ``set_local_env.sh``. This is where you can configure the ``SSH_HOSTNAME`` variable.

This address is then used to deploy the executable on the target automatically.

### WSL configuration (if using WSL for Windows)

See ``set_local_env.bat``. The default setting is ``Ubuntu``, but if you have several WSL distributions it could be different.

You can verify your WSL distribution name with the commande ``wsl --list`` in Windows terminal and then set the correct value in this script:

```
IF [%WSL_DISTRIBUTION_NAME%] == [] (
  SET WSL_DISTRIBUTION_NAME=Ubuntu
)
```

## VEE port configuration

At build time, the |VEEPORT| configuration project will install the 3 following files into the ``project/microej/scripts/`` folder:

* ``set_project_env.sh``

This script is used to setup environment variables for compilation (such as the path to the Compiler and/or Yocto SDK)

* ``toolchain.cmake``

This is a cmake configuration file purely dedicated to the toolchain configuration.

* ``project_options.cmake``

This is a cmake configuration file dedicated to the abstraction layers configuration.

### set_project_env.sh

This general script will be sourced before calling the cmake build.
It is used to export environment variables (ex: `$CC`, `$CFLAGS`) for cross compilation.

Here is an example when building with a [Yocto SDK](https://docs.yoctoproject.org/2.1/sdk-manual/sdk-manual.html):

```
#!/bin/bash
#
# BASH
#
# Copyright 2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# Toolchain settings:
# Application SDK installation path (e.g. /usr/local/oecore-x86_64)
if [ -z $YOCTO_SDK_INSTALL ]; then
YOCTO_SDK_INSTALL=/usr/local/oecore-x86_64
fi
if [ -z $YOCTO_SDK_ENV_SCRIPT ]; then
 YOCTO_SDK_INSTALL=environment-setup-armv7at2hf-neon-vfpv4-oemllib32-linux-gnueabi
fi

if [ ! -d "$YOCTO_SDK_INSTALL" ]; then
echo ""
echo "ERROR: YOCTO_SDK_INSTALL="$YOCTO_SDK_INSTALL" is not a valid path."
echo "Please verify set_project_env.sh"
echo ""
exit -1
fi

. "$YOCTO_SDK_INSTALL/$YOCTO_SDK_ENV_SCRIPT"
```

### toolchain.cmake

This file is used to setup the [cmake toolchain](https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html)

#### Using Yocto SDK

When building with a [Yocto SDK](https://docs.yoctoproject.org/2.1/sdk-manual/sdk-manual.html), the toolchain configuration will mostly come from the Yocto SDK environment script sourced in ``set_project_env.sh``.
A few additional settings are necessary like setting the sysroot, see below:

```
# Copyright 2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# Toolchain settings
#

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# set(CMAKE_C_COMPILER ${CC})

# fetch SYSROOT variable if set by Yocto SDK environment script
set(CMAKE_SYSROOT $ENV{SDKTARGETSYSROOT})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
```

#### Using a standalone toolchain

Here is how to cross compile for i686 GCC on Ubuntu, see the CMAKE_C_COMPILER variable below:

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

### project_options.cmake

This is where all the generic abstraction layers configuration takes place.

#### How to add your own abstraction layer

With the following syntax, you can specify the source of external code:

```
#
# Abstraction layer external source
#
# set(ABSTRACTION_LAYER_EXTERNAL ../../../Linux-abstractionlayer-imx93)
# When specifying an out-of-tree source a binary directory must be explicitly specified
# here we will install the output files in a subdirectory of CMAKE_CURRENT_BINARY_DIR
# add_subdirectory(${ABSTRACTION_LAYER_EXTERNAL} Linux-abstractionlayer-imx93)
```

#### How to set custom CFLAGS options

Here is an example when building a 32bit executable for a 64bit target

```
#
# CFLAGS
#
# generate 32bit code, see https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html
set(CFLAGS ${CFLAGS} -m32)
# Prevent floating point comparison issues with 32bit code. Known GCC issue, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=323#c109
set(CFLAGS ${CFLAGS} -msse -mfpmath=sse)
```

#### How to enable/disable Abstraction layers

The list of options can be found in the [options.cmake](projects/microej/options.cmake) file.

This file lists all the different options, and sets a default value with the `option(<variable> "<help_text>" [value])` syntax.

```
# Select which Abstraction Layer to build
option(BUILD_CORE         "Build Core Abstraction Layer"                   ON)
option(BUILD_ECOM_NETWORK "Build Embedded COMmunication Abstraction Layer" ON)
option(BUILD_FS           "Build File System Abstraction Layer"            ON)
option(BUILD_KF           "Build Kernel Feature Abstraction Layer"         ON)
option(BUILD_NET          "Build Network Abstraction Layer"                ON)
option(BUILD_SECURITY     "Build Security Abstraction Layer"               ON)
option(BUILD_SSL          "Build SSL Abstraction Layer"                    ON)
option(BUILD_UI           "Build UI Abstraction Layer"                     ON)
option(BUILD_UTIL         "Build Util Abstraction Layer"                   ON)
option(BUILD_VALIDATION   "Build validation utilities"                     OFF)
```

examples:

* if your VEE port doesn't have the FS foundation library, you can disable BUILD_FS
* BUILD_VALIDATION is only used to validate the core architecture.

To disable a feature, simply add the following line in the project_options.cmake file of your VEE port project:

```
set(BUILD_XXX         "Build XXX Abstraction Layer"                   OFF)
```

#### Abstraction layers specific configurations

```
# Set specific features
if (BUILD_UI)
  option(BUILD_UI_TOUCHSCREEN "Build UI Touchscreen feature" ON)
  option(BUILD_UI_FRAMERATE "Build UI Framerate debug feature" OFF)
  option(BUILD_UI_FBDEV "Build UI Framebuffer device support" ON)
  option(BUILD_UI_DRM "Build UI DRM Framebuffer support" OFF)
endif()

if (BUILD_NET)
  option(ENABLE_NET_AF_IPV4_SUPPORT "IPv4 support" ON)
  option(ENABLE_NET_AF_IPV6_SUPPORT "IPv6 support" OFF)
endif()
```

* BUILD_UI_TOUCHSCREEN is based on tslib API (https://github.com/libts/tslib)
* BUILD_UI_FBDEV and BUILD_UI_DRM are mutually exclusive.

  * If linux only supports the legacy frame buffer (/dev/fb0), select BUILD_UI_FBDEV
  * Otherwise, if linux supports DRM, select BUILD_UI_DRM
  * If you don't have a display, just disable BUILD_UI

#### Debug and advanced features

```
# Debug features
option(ADVANCED_TRACE "Enable MJVM Advanced trace" OFF)
```

* ADVANCED_TRACE is used for `Advanced Event Tracing <https://docs.microej.com/en/latest/VEEPortingGuide/advanceTrace.html>`_


# Requirements

This abstraction layer implementation requires a GNU compiler for 32-bit Linux architecture.

The following librairies must be installed in the sysroot:
- libc.so
- libssl.so
- libcrypto.so
- libdrm.so (optional, for DRM displays only)
- libts.so (optional)

As an example with Yocto, on a ARMv7 chipset, the following configuration can be done:
```
echo -e "require conf/multilib.conf" >>  ./conf/local.conf
echo -e "MULTILIBS = \"multilib:lib32\"" >>  ./conf/local.conf
echo -e "DEFAULTTUNE:virtclass-multilib-lib32 = \"armv7athf-neon\"" >>  ./conf/local.conf
echo -e "IMAGE_INSTALL:append = \" lib32-glibc lib32-libgcc lib32-libstdc++\"" >> ./conf/local.conf 
echo -e "IMAGE_INSTALL:append = \" lib32-libssl lib32-libdrm lib32-tslib\"" >> ./conf/local.conf 
```

# Dependencies

_All dependencies are retrieved transitively by MicroEJ Module Manager_.

# Source

N/A

# Restrictions

None.
---
_Copyright 2024 MicroEJ Corp. All rights reserved._
_Use of this source code is governed by a BSD-style license that can be found with this software._
