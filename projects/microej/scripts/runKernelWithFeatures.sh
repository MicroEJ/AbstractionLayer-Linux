#!/bin/bash
#
# BASH
#
# Copyright 2023-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# Run script implementation for KF Testsuite dynamic Feature injection mode.
# The Kernel is loaded and started until the `main` entry point is reached.
# Then Feature '.fo' files ('F1.fo' to 'F4.fo') are dynamically injected to the memory reserved resources. 
# See associated 'runKernelWithFeatures.gdb' file.

if [ -z "$1" ]; then
    APPLICATION_FILE="$(pwd)/application.out"
else
    APPLICATION_FILE="$(cd $(dirname $1) ; pwd)/$(basename $1)"
fi

if [ ! -e "${APPLICATION_FILE}" ]; then
    echo "FAILED - file '${APPLICATION_FILE}' does not exist"
    exit -1
fi

chmod +x ${APPLICATION_FILE}
pushd $(dirname ${APPLICATION_FILE})
gdb --batch -x $(dirname "$0")/runKernelWithFeatures.gdb ${APPLICATION_FILE}

popd
