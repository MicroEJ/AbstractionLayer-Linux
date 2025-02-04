#!/bin/bash
#
# BASH
#
# Copyright 2023-2025 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# Run script implementation for KF Testsuite dynamic Feature injection mode.
# The Kernel is loaded and started until the `main` entry point is reached.
# Then Feature '.fo' files ('F1.fo' to 'F4.fo') are dynamically injected to the memory reserved resources. 
# See associated 'runKernelWithFeatures.gdb' file.

set -euo pipefail

origin=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit

if [ -z "${1:-""}" ]; then
    application_file="$(pwd)/application.out"
else
    application_file="$(cd $(dirname $1) ; pwd)/$(basename "$1")"
fi

if [ ! -e "${application_file}" ]; then
    echo "FAILED - file '${application_file}' does not exist"
    exit 1
fi

chmod +x "${application_file}"
cd "$(dirname "${application_file}")" || exit
gdb --batch -x "${origin}/runKernelWithFeatures.gdb" "${application_file}"
cd -
