![SDK](https://shields.microej.com/endpoint?url=https://repository.microej.com/packages/badges/sdk_6.0.json)
![ARCH](https://shields.microej.com/endpoint?url=https://repository.microej.com/packages/badges/arch_8.1.json)
![GUI](https://shields.microej.com/endpoint?url=https://repository.microej.com/packages/badges/gui_3.json)

# Generic Abstraction Layer for Linux VEE Ports

# Overview

This project contains a complete Abstraction Layer implementation to run the VEE on a Linux system.

It also contains a cmake project with different sets of configuration (toolchains, features).

This Abstraction Layer requires a GNU GCC 32 bit toolchain as well as a few listed C libraries, see [Requirements](#requirements)

## Supported Features

This Abstraction Layer is compliant with Architecture `8.x` and the following Packs and Foundation Libraries:

| Pack Name    | Version  |
| ------------ | -------- |
| AUDIO        | 2.1.0    |
| CRYPTO       | 2.0.1    |
| DEVICE       | 1.4.1    |
| ECOM-NETWORK | 1.0.0    |
| EVENT        | 3.0.7    |
| FS           | 6.0.5    |
| NET          | 15.0.1   |
| SERIAL       | 3.0.0    |
| UI           | 14.5.2   |

### Architecture

The Multi-Sandbox Application download implementation is based on malloc/free in RAM, so without reboot persistence.

### Device Pack

The Device UID comes from the first of these sources that answers, in this order:

- The serial number of the board, read from the device tree
- The MAC address of the first non-loopback network interface
- An identifier derived from the machine ID of the host

The Device UID holds at most 64 bytes.
The identifier derived from the machine ID never exposes the machine ID itself.

A machine ID identifies an installation, not a hardware unit.
An image that ships a populated `/etc/machine-id` gives the same Device UID to every unit flashed from it.
Where the Device UID must be unique per unit, and the board publishes no device tree serial number and holds no MAC address, the provisioning must regenerate the machine ID on each unit, with `systemd-machine-id-setup` or by shipping the file empty so systemd populates it on first boot.

### Networking Pack

Both IPv4 and IPv6 are supported.
`ENABLE_NET_AF_IPV4_SUPPORT` and `ENABLE_NET_AF_IPV6_SUPPORT` select which of the two the port reports, and enabling both gives a dual stack.
See [Module Specific Configurations](#module-specific-configurations).

SSL supports TLSv1, TLSv1.1, TLSv1.2, DTLS1.2.

Security algorithms:
- Cipher: AES/CBC/NoPadding, AES/CTR/NoPadding, AES/ECB/NoPadding, AES/GCM/NoPadding (128, 192, 256-bit keys), DESede/CBC/NoPadding
- Key wrap: AESWrap
- RSA Cipher: RSA/ECB/PKCS1Padding, RSA/ECB/OAEPWithSHA-1AndMGF1Padding, RSA/ECB/OAEPWithSHA-256AndMGF1Padding
- Digest: MD5, SHA-1, SHA-256, SHA-512
- HMAC: HmacMD5, HmacSHA1, HmacSHA256
- Key generation: EC, RSA
- Key derivation: PBKDF2WithHmacSHA1, PBKDF2WithHmacSHA224, PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA384, PBKDF2WithHmacSHA512
- Key agreement: ECDH
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

In the directory ``vee/scripts/`` are scripts that can be used to build and flash the executable.\
The ``.bat`` and ``.sh`` scripts are meant to run in a Windows and Linux environment respectively.

- The ``build*`` scripts are used to compile and link the Abstraction Layer with a MicroEJ Application to produce a MicroEJ executable (``application.out``) that can be run on a Linux device.

  The ``build*`` scripts work out of the box, assuming the toolchain is configured properly, see :ref:`Plaftorm configuration section`

- The ``run*`` scripts are used to send and execute a MicroEJ executable (``application.out``) on a device, over SSH.

The environment variables can be defined globally by the user or in the ``set_local_env*`` scripts. You can edit these files to customize the environment locally.

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
option(BUILD_AUDIO        "Build Audio Abstraction Layer"                  ON)
option(BUILD_CORE         "Build Core Abstraction Layer"                   ON)
option(BUILD_ECOM_NETWORK "Build Embedded COMmunication Abstraction Layer" ON)
option(BUILD_FS           "Build File System Abstraction Layer"            ON)
option(BUILD_KF           "Build Kernel Feature Abstraction Layer"         ON)
option(BUILD_NET          "Build Network Abstraction Layer"                ON)
option(BUILD_RIO          "Build rio Event-Driven I/O Abstraction Layer"   OFF)
option(BUILD_CRYPTO       "Build Security Abstraction Layer"               ON)
option(BUILD_SERIAL       "Build Serial Abstraction Layer"                 ON)
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

* ENABLE_NET_AF_IPV4_SUPPORT and ENABLE_NET_AF_IPV6_SUPPORT are not mutually exclusive.

  * Enable both for a dual stack, which is what most ports want.
  * Enable one to report the addresses of that family only.
    An interface whose addresses are all outside the enabled family is still listed, and reports no address.
  * Disabling both is rejected at CMake configure time, because the network would then report no address at all.
    Set BUILD_NET to OFF instead.

* BUILD_NET requires BUILD_UTIL, which provides `sni_extras.h`.
  Leaving BUILD_UTIL off with BUILD_NET on is rejected at CMake configure time.

* BUILD_UI_TOUCHSCREEN is based on tslib API (https://github.com/libts/tslib).
* BUILD_UI_FBDEV and BUILD_UI_DRM are mutually exclusive.

  * If Linux only supports the legacy frame buffer (/dev/fb0), select BUILD_UI_FBDEV
  * Otherwise, if Linux supports DRM, select BUILD_UI_DRM.
  * If you don't have a display, just disable BUILD_UI.

#### Debug and Advanced Features

```
# Debug features
option(ADVANCED_TRACE "Enable MJVM Advanced trace" OFF)

if (BUILD_ESSENTIALS)
  option(USE_VEEPORT_LOGGER "Use the VEE Port Essentials logger for the abstraction layer traces" ON)
endif()
```

* ADVANCED_TRACE is used for [Advanced Event Tracing](https://docs.microej.com/en/latest/VEEPortingGuide/advanceTrace.html)
* USE_VEEPORT_LOGGER routes the `VEEPORT_LOGGER_LOG_*` traces of the abstraction layers to the VEE Port Essentials logger, which filters each layer with its `<LAYER>_LOG_LEVEL` (set in `vee/port/config/inc/veeport_configuration.h`). When it is OFF, the traces fall back to `VEEPORT_PRINTF` and every message is printed, whatever its level. The default log level is error and the default format of the logging messages is the following: `[module name][function name][line number][log level][log message]`.


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

# MISRA Compliance

This Abstraction Layer has a list of components that are MISRA-compliant (MISRA C:2012) with some noted exceptions.
Below is the list of directories and files that have been verified:

- `vee/port/core/src`
- `vee/port/crypto`
- `vee/port/util/inc/sni_extras.h`

It has been verified with Cppcheck v2.21.
Here is the list of deviations from MISRA standard:

| Deviation | Category | Justification |
|-----------|----------|---------------|
| Rule 2.3 | Advisory | The type declared by the static assertion is unused on purpose, because only its array size carries the check |
| Rule 2.5 | Advisory | The analysis pins a single configuration, so a macro used only by the other keystore configuration is reported as unused |
| Rule 5.5 | Required | The LLMJVM header that the architecture generates defines a macro for each LLAPI function, and some of these macros expand to their own name. The Core Engine links to these names |
| Rule 5.9 | Advisory | The logger module macro gives its two internal-linkage objects the same names in every file, because the logging macros read those names |
| Rule 8.7 | Advisory | LLAPI functions require external linkage but invocation cannot be detected by cppcheck |
| Rule 8.9 | Advisory | The logger requires the module definition at the top of the file, also in a file where only `main()` logs |
| Rule 11.1 | Required | Abstract data type for SNI usage. The LLAPI fixes the return type at `int32_t`, so the close function crosses the boundary as an integer |
| Rule 11.3 | Required | Abstract data type for SNI usage. The array length accessor reads the length word that precedes the array data |
| Rule 11.4 | Advisory | Abstract data type for SNI usage. The SNI ABI carries each native resource handle as a `jint`, and the LLAPI header that the pack delivers fixes this signature |
| Rule 11.5 | Advisory | Abstract data type for SNI usage. SNI stores each native resource as a `void*`, and the allocators return a `void*`. POSIX gives a signal handler the context of the interrupted thread as a `void*` |
| Rule 11.6 | Required | Abstract data type for SNI usage. The random native registers a synthetic handle, because the OpenSSL random generator is global state with no object to point at. The crash handler reads the saved instruction pointer as an integer, and prints it as a pointer |
| Rule 11.8 | Required | The OpenSSL and PKCS#11 functions declare an input buffer without `const`, and only read it |
| Rule 15.1 | Advisory | A forward `goto` to a single cleanup label releases the acquired OpenSSL objects. An exit path that does not release them leaks memory |
| Rule 15.2 | Required | Cppcheck false positive. The `goto` does jump forward, to a label declared later in the same function |
| Rule 15.5 | Advisory | Guard clauses reject invalid arguments with an early return, before any resource is acquired |
| Rule 18.4 | Advisory | Abstract data type for SNI usage. The array length accessor offsets a pointer to reach the length word |
| Rule 19.2 | Advisory | A tagged union holds the key backends, which are mutually exclusive for a given key. A structure that holds all of them wastes RAM. The POSIX thread types are unions in the C library |
| Rule 21.3 | Required | Managed Code asks the port for crypto resources whose size is known only at run time, so the allocation is dynamic by nature |
| Rule 21.5 | Required | The port installs a crash handler and a dump handler, which requires `<signal.h>` |
| Rule 21.8 | Required | The port ends the process when the Core Engine timer fails, because a supervisor can restart a process that ends, but not a process that hangs |
| Rule 21.10 | Required | POSIX declares its clock API only in `<time.h>`. No ISO C time and date function is used |

---
_Markdown_\
_Copyright 2024-2026 MicroEJ Corp. All rights reserved._\
_Use of this source code is governed by a BSD-style license that can be found with this software._\
_Build: 7E4D1F7C_
