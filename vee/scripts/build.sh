#!/bin/bash
#
# BASH
#
# Copyright 2021-2025 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# 'build.sh' implementation for MicroEJ Linux builds.

# 'build.sh' is responsible for producing the executable file 
# then copying this executable file to the current directory where it has been executed to a file named 'application.out'

set -euo pipefail

# Save application current directory
CURRENT_DIR=$(pwd)

SCRIPTS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit

unset LD_LIBRARY_PATH

# Ensure we always return to the original directory
function cleanup {
    cd "${CURRENT_DIR}" || exit
}
trap cleanup EXIT

# Setup build environment variables
. "${SCRIPTS_DIR}/set_env.sh"

# Run in Docker if requested
if [ ! -f "/.dockerenv" ] && [ ! -f "${HOME}/.dockerenv" ]; then
    if [ -n "${DOCKER_IMAGE:-""}" ]; then
        if [ -z "${DOCKER_IMAGE:-""}" ]; then
            echo "To run on Docker, provide DOCKER_IMAGE environment variable to choose the docker image to use"
            exit 1
        fi
        if [ -z "${ROOT_PROJECT_DIR:-""}" ]; then
            echo "To run on Docker, provide ROOT_PROJECT_DIR indicating the absolute path to the root of your project"
            exit 1
        fi

        if ! docker images -a | grep "${DOCKER_IMAGE}"; then
            echo "No Docker image ${DOCKER_IMAGE} found."
            exit 1
        fi

        docker run -i \
                   -v"${ROOT_PROJECT_DIR}":"${ROOT_PROJECT_DIR}" \
                   -v"${CURRENT_DIR}":"${CURRENT_DIR}" \
                   -v"${TOOLCHAIN_DIR}":"${TOOLCHAIN_DIR}" \
                   -w"${CURRENT_DIR}" \
                   -e TOOLCHAIN_DIR="${TOOLCHAIN_DIR}" \
                   --net=host \
                   --platform linux/amd64 \
                   "${DOCKER_IMAGE}" \
                   bash -c "${SCRIPTS_DIR}/$(basename "${0}")" "$@"
        exit $?
    fi
fi

# Create a cmake build folder, using the compiler name
if [ -n "${CC:-""}" ]; then
    compiler=$(basename "$CC")
elif [[ -f "${SCRIPTS_DIR}/toolchain.cmake" ]]; then
    compiler=$(grep -E '^[[:space:]]*set\s*\(\s*CMAKE_C_COMPILER' ${SCRIPTS_DIR}/toolchain.cmake | \
               sed -E 's/.*set\s*\(\s*CMAKE_C_COMPILER\s+([^ )]+).*/\1/' | \
               xargs basename)
else
    echo "Error: No compiler found (CC not set, and ${SCRIPTS_DIR}/toolchain.cmake missing)"
    exit 1
fi

BUILD_DIR="${SCRIPTS_DIR}/../build-${compiler}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}" || exit

echo "CURRENT_DIR = ${CURRENT_DIR}"
echo "SCRIPTS_DIR = ${SCRIPTS_DIR}"
echo "BUILD_DIR = ${BUILD_DIR}"

cmake -DCMAKE_TOOLCHAIN_FILE=scripts/toolchain.cmake "${SCRIPTS_DIR}/.."

#make -j VERBOSE=1
make -j"$(nproc)"

# Copy the application file
if [ "${SCRIPTS_DIR}" != "${CURRENT_DIR}" ]; then
    cp "${SCRIPTS_DIR}/application.out" "${CURRENT_DIR}"
fi
# Copy the map file
cp "${BUILD_DIR}/microej_gcc.map" "${CURRENT_DIR}/application.map"

echo "The application executable file has been generated here: ${CURRENT_DIR}/application.out"
