#!/bin/bash
#
# BASH
#
# Copyright 2026 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# Build: 7E4D1F7C

# 'clean.sh' implementation for MicroEJ Linux builds.

# 'clean.sh' is responsible for removing the C build outputs:
# the CMake build directories ('vee/build-*'), the headers and libraries
# deployed by the VEE Port build ('vee/inc', 'vee/lib') and the generated
# application artifacts ('application.out', 'application.map').

set -euo pipefail

SCRIPTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit
VEE_DIR="${SCRIPTS_DIR}/.."

# Remove the CMake build directories (one per compiler, see build.sh)
rm -rf "${VEE_DIR}"/build-*

# Remove the headers and libraries deployed by the VEE Port build
rm -rf "${VEE_DIR}/inc" "${VEE_DIR}/lib"

# Remove the generated application artifacts
rm -f "${SCRIPTS_DIR}/application.out" "${SCRIPTS_DIR}/application.map"

echo "C build outputs removed."
