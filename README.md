![SDK](https://shields.microej.com/endpoint?url=https://repository.microej.com/packages/badges/sdk_6.0.json)
![ARCH](https://shields.microej.com/endpoint?url=https://repository.microej.com/packages/badges/arch_8.1.json)
![GUI](https://shields.microej.com/endpoint?url=https://repository.microej.com/packages/badges/gui_3.json)

# Generic Abstraction Layer for Linux VEE Ports

# Overview

This project contains a complete Abstraction Layer implementation to run the VEE on a Linux system.

It also contains a cmake project with different sets of configuration (toolchains, features).

This Abstraction Layer requires a GNU GCC 32 bit toolchain as well as a few listed C libraries, see [Requirements](#requirements)

## Supported Features

This Abstraction Layer is compliant with Architecture `8.x` and the following Packs:

| Pack Name    | Version  |
| ------------ | -------- |
| DEVICE       | 1.2.0    |
| ECOM-NETWORK | 1.0.0    |
| FS           | 6.0.4    |
| NET          | 11.1.0   |
| UI           | 14.3.2   |

### Architecture

The Multi-Sandbox Application download implementation is based on malloc/free in RAM, so without reboot persistence.

### Device Pack

The Device UID is based on the Ethernet HWAddr.

### Networking Pack

Both IPv4 a IPv6 are supported.

SSL supports TLSv1, TLSv1.1, TLSv1.2, DTLS1.2.

Security algorithms:
- Cipher: AES-128-CBC, AES-192-CBC, AES-256-CBC, DES-CBC
- RSA Cipher: RSA/ECB/PKCS1Padding, RSA/ECB/OAEPWithSHA-1AndMGF1Padding, RSA/ECB/OAEPWithSHA-256AndMGF1Padding
- Digest: MD5, SHA-1, SHA-256, SHA-512
- Key generation: EC, RSA
- HMAC: SHA-256
- Signature: SHA256withRSA, SHA256withECDSA

### UI Pack

This Abstraction Layer implements the display on either the Linux kernel Frame Buffer or Direct Rendering Manager (libdrm).

# Usage

This project has 2 configuration steps.

First you [add this Abstraction Layer into a Linux VEE Port project](#how-to-use-this-abstraction-layer-in-a-linux-vee-port).

Then you [customize the features for your VEE Port requirements](#how-to-customize-the-vee-port).

# How to Use this Abstraction Layer in a Linux VEE Port

A typical Linux VEE Port can use this Abstraction Layer as its BSP to build and run the VEE.

See MicroEJ documentation about [BSP connection](https://docs.microej.com/en/latest/VEEPortingGuide/bspConnection.html#bsp-connection).

The following folder structure can be used:
- a VEE Port configuration project containing the board specific configurations (see details below)
- a VEE Port Abstraction Layer (the current repository, named `AbstractionLayer-Linux`)

It should look like this:
```
├── vee-port/
    ├── bsp
        ├── project_options.cmake
        ├── set_project_env.sh
        └── toolchain.cmake
    ├── build.gradle.kts
    ├── configuration.properties
    ...
├── AbstractionLayer-Linux
    ├── gradle/libs.versions.toml
    └── vee
        ├── CMakeLists.txt
        ├── build
        ├── inc
        ├── lib
        ├── options.cmake
        ├── port
        └── scripts
```

## BSP Connection
- In this folder structure, we are using a full BSP connection:
For example in `vee-port/configuration.properties`:
```
bsp.microejapp.relative.dir=vee/lib
bsp.microejlib.relative.dir=vee/lib
bsp.microejinc.relative.dir=vee/inc
bsp.microejscript.relative.dir=vee/scripts
bsp.root.dir=${project.parent.dir}/AbstractionLayer-Linux
```

## Pack Version Dependencies

This Abstraction Layer is compatible with a set of MicroEJ packs.

The VEE Port project can use the file `libs.versions.toml` to set the proper pack dependencies in gradle.

For example in `vee-port/build.gradle.kts`:
```
    // load the versions
    dependencyResolutionManagement {
        versionCatalogs {
            create("libsOverride") {
                from(files("./AbstractionLayer-Linux/gradle/libs.versions.toml"))
            }
        }
    }
    // then add the packs in the gradle dependencies
    microejPack(libsOverride.pack.device)
    microejPack(libsOverride.pack.ecom.network)
    microejPack(libsOverride.pack.fs)
    microejPack(libsOverride.pack.net)
```

## CMake Project Configuration

This Abstraction Layer does not come with a default configuration. It needs to be provided by the VEE Port project.

3 files are necessary, their contents are detailed in a following section [VEE Port Configuration](#vee-port-configuration).

Here is a way to install them properly on top of the Abstraction Layer:
```
// Add this code in vee-port/build.gradle.kts
tasks.register<Copy>("copyBspScripts") {
    from("bsp")
    into("../AbstractionLayer-Linux/vee/scripts")
}

tasks.getByName("buildVeePort").dependsOn("copyBspScripts")
tasks.getByName("buildVeePortConfiguration").dependsOn("copyBspScripts")
```
This method makes sure that the files are copied before the compilation stage.

# How to Customize the VEE Port

Now that we have seen how to connect this Abstraction Layer with a VEE Port, we will see how it can be configured.

## Build & Run Scripts

In the directory ``vee/scripts/`` are scripts that can be used to build and flash the executable.  
The ``.bat`` and ``.sh`` scripts are meant to run in a Windows and Linux environment respectively.

- The ``build*`` scripts are used to compile and link the Abstraction Layer with a MicroEJ Application to produce a MicroEJ executable (``application.out``) that can be run on a Linux device.

  The ``build*`` scripts work out of the box, assuming the toolchain is configured properly, see :ref:`Plaftorm configuration section`

- The ``run*`` scripts are used to send and execute a MicroEJ executable (``application.out``) on a device, over SSH.

The environment variables can be defined globally by the user or in the ``set_local_env*`` scripts.  When the ``.bat`` (``.sh``) scripts are executed, the ``set_local_env.bat`` (``set_local_env.sh``) script is executed if it exists.
You can edit these files to customize the environment locally.

## Host Configuration

### Target SSH Configuration

See ``set_local_env.sh``. This is where you can configure the ``SSH_HOSTNAME`` environment variable.

This address is then used to deploy the executable on the target automatically.

You can also set this environment variable in your machine shell, or via your IDE by editing the gradle task `runOnDevice`.

### WSL Configuration (if using WSL for Windows)

See ``set_local_env.bat``. The default setting is ``Ubuntu``, but if you have several WSL distributions it could be different.

You can verify your WSL distribution name with the commande ``wsl --list`` in Windows terminal and then set the correct value in this script:

```
IF [%WSL_DISTRIBUTION_NAME%] == [] (
  SET WSL_DISTRIBUTION_NAME=Ubuntu
)
```

### Docker configuration

In case of running a docker image to build the executable, you must set the following environment variables:
- ``DOCKER_IMAGE`` to chose the docker image to use.
- ``ROOT_PROJECT_DIR`` indicating the absolute path to the root of your project

## VEE Port Configuration

At build time, the VEE Port configuration project will install the 3 following files into the ``vee/scripts/`` folder:

* ``set_project_env.sh``

This script is used to setup environment variables for compilation (such as the path to the Compiler and/or Yocto SDK).

* ``toolchain.cmake``

This is a cmake configuration file purely dedicated to the toolchain configuration.

* ``project_options.cmake``

This is a cmake configuration file dedicated to the Abstraction Layer configuration.

### set_project_env.sh

This general script will be sourced before calling the cmake build.
It is used to export environment variables (ex: `$CC`, `$CFLAGS`) for cross compilation.

Here is an example when building with a [Yocto SDK](https://docs.yoctoproject.org/2.1/sdk-manual/sdk-manual.html):

```
#!/bin/bash
#
# BASH
#

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

#### Using a Standalone Toolchain

Here is how to cross compile for i686 GCC on Ubuntu, see the CMAKE_C_COMPILER variable below:

```
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

This is where all the generic Abstraction Layer configuration takes place.
This CMake file is sourced by `vee/CMakeLists.txt`, and so any CMake option can be set or overridden here.

#### How to Add Your Own Native Code

With the following syntax, you can specify the source of external code:

```
#
# Abstraction Layer external source
#
# set(ABSTRACTION_LAYER_EXTERNAL ../../../AbstractionLayer-Linux-external)
# When specifying an out-of-tree source a binary directory must be explicitly specified
# here we will install the output files in a subdirectory of CMAKE_CURRENT_BINARY_DIR
# add_subdirectory(${ABSTRACTION_LAYER_EXTERNAL} AbstractionLayer-Linux-external)
```

#### How to Set Custom CFLAGS Options

Here is an example when building a 32bit executable for a 64bit target:

```
#
# CFLAGS
#
# generate 32bit code, see https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html
set(CFLAGS ${CFLAGS} -m32)
# Prevent floating point comparison issues with 32bit code. Known GCC issue, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=323#c109
set(CFLAGS ${CFLAGS} -msse -mfpmath=sse)
```

#### How to Enable/Disable Each Module

The support for each pack is separated in different modules, which can all be disabled using a CMake option.

The file [options.cmake](vee/options.cmake) lists all the different options, and sets a default value with the `option(<variable> "<help_text>" [value])` syntax.

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

Examples:

* If your VEE Port doesn't need the FS Foundation Library, you can disable BUILD_FS.
* BUILD_VALIDATION is only used to validate the core architecture.

To disable a feature, simply add the following line in the project_options.cmake file of your VEE Port project:

```
set(BUILD_FS OFF)
```

#### Module Specific Configurations

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

* BUILD_UI_TOUCHSCREEN is based on tslib API (https://github.com/libts/tslib).
* BUILD_UI_FBDEV and BUILD_UI_DRM are mutually exclusive.

  * If Linux only supports the legacy frame buffer (/dev/fb0), select BUILD_UI_FBDEV
  * Otherwise, if Linux supports DRM, select BUILD_UI_DRM.
  * If you don't have a display, just disable BUILD_UI.

#### Debug and Advanced Features

```
# Debug features
option(ADVANCED_TRACE "Enable MJVM Advanced trace" OFF)
```

* ADVANCED_TRACE is used for [Advanced Event Tracing](https://docs.microej.com/en/latest/VEEPortingGuide/advanceTrace.html)


# Requirements

This Abstraction Layer implementation requires a GNU compiler for 32-bit Linux architecture.

The following libraries must be installed in the sysroot:
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
_Markdown_  
_Copyright 2024-2025 MicroEJ Corp. All rights reserved._  
_Use of this source code is governed by a BSD-style license that can be found with this software._  
