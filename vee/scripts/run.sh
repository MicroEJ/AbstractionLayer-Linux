#!/bin/bash
#
# BASH
#
# Copyright 2023-2025 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# 'run.sh' implementation for MicroEJ Linux builds.

# 'run.sh' is responsible for producing the executable file.

# Exit on failure & fail on unset variable
set -euo pipefail

# Save application current directory
current_dir=$(pwd)

origin=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit

if [ -z "${1:-""}" ]; then
    application_file="$(pwd)/application.out"
else
    application_file="$(cd $(dirname $1) ; pwd)/$(basename "$1")"
fi

cd "${origin}"

if [ ! -e "${application_file}" ]; then
    echo "FAILED - file '${application_file}' does not exist"
    exit 1
fi

project_env_file="${origin}/set_project_env.sh"
if [ -f "${project_env_file}" ]; then
    # shellcheck source=set_project_env.sh
    . "${project_env_file}"
else
    echo ""
    echo "ERROR: Missing set_project_env.sh script."
    echo ""
    exit 1
fi

local_env_file="${origin}/set_local_env.sh"
if [ -f "${local_env_file}" ]; then
    # shellcheck source=set_local_env.sh
    . "${local_env_file}"
else
    echo ""
    echo "ERROR: Missing set_local_env.sh script."
    echo "For local build, please create it using set_local_env.sh.tpl as example."
    echo ""
    exit 1
fi

#### Run application locally (X86 only) if the project has set LOCAL_DEPLOY=yes
if [ "${LOCAL_DEPLOY:-""}" = "yes" ]; then
    chmod +x "${application_file}"
    ${application_file}
    exit $?
fi

#### Run application on target
if [ -z "${SSH_HOSTNAME:-""}" ]; then
    echo "ERROR: Missing SSH_HOSTNAME environment variable"
    echo "Please set the SSH_HOSTNAME in your shell environment variables or in set_local_env.sh script"
    exit 1
fi

if [ -z "${SSH_USER:-""}" ]; then
    echo "ERROR: Missing SSH_USER environment variable"
    echo "Please set the SSH_USER in your shell environment variables or in set_local_env.sh script"
    exit 1
fi

if [ -z "${SSH_PASSWORD:-""}" ]; then
    echo "NOTICE: No ssh password set to connect to the target board."
    echo "If ssh password is required, please set it with the SSH_PASSWORD environment variable"
    # set dummy password as sshpass does not support empty password
    ssh_password_option=""
else
    ssh_password_option="sshpass -p ${SSH_PASSWORD}"
fi

if [ -z "${SSH_REMOTE_DIRECTORY:-""}" ]; then
    #use /tmp as default remote directory where the application will be copied
    SSH_REMOTE_DIRECTORY="/tmp"
fi

ssh_remote_application="${SSH_REMOTE_DIRECTORY}/application.out"

#check if the remote directory where the application will be copied exists and create it if needed
${ssh_password_option} ssh -oStrictHostKeyChecking=no "${SSH_USER}@${SSH_HOSTNAME}" "mkdir -p ${SSH_REMOTE_DIRECTORY}"

# kill old process if any
${ssh_password_option} ssh -oStrictHostKeyChecking=no "${SSH_USER}@${SSH_HOSTNAME}" "killall -q startup.out || killall -q application.out || true"

${ssh_password_option} scp -O -oStrictHostKeyChecking=no "${application_file}" "${SSH_USER}@${SSH_HOSTNAME}:${ssh_remote_application}"

${ssh_password_option} ssh -oStrictHostKeyChecking=no "${SSH_USER}@${SSH_HOSTNAME}" "chmod +x ${ssh_remote_application} &&  LLDISPLAY_USE_VSYNC=1 exec ${ssh_remote_application}"

# Restore application directory
cd "${current_dir}" || exit
