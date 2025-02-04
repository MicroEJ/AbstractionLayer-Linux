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
current_dir=$(pwd)

origin=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit

unset LD_LIBRARY_PATH

# Setup build environment variables
. "${origin}/set_project_env.sh"

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
                   -v"${current_dir}":"${current_dir}" \
                   -v"${TOOLCHAIN_DIR}":"${TOOLCHAIN_DIR}" \
                   -w"${current_dir}" \
                   -e TOOLCHAIN_DIR="${TOOLCHAIN_DIR}" \
                   --net=host \
                   --platform linux/amd64 \
                   "${DOCKER_IMAGE}" \
                   bash -c "${origin}/$(basename "${0}")" "$@"
        exit $?
    fi
fi

cmake_build_dir="${origin}/../build"
mkdir -p "${cmake_build_dir}"
cd "${cmake_build_dir}" || exit
cmake --toolchain ./scripts/toolchain.cmake "${origin}/.."
#make -j VERBOSE=1
make -j"$(nproc)"

# Copy the application file
if [ "${origin}" != "${current_dir}" ]; then
    cp "${origin}/application.out" "${current_dir}"
fi
# Copy the map file
cp "${cmake_build_dir}/microej_gcc.map" "${current_dir}/application.map"

echo "The application executable file has been generated here: ${current_dir}/application.out"
# Restore application directory
cd "${current_dir}" || exit
