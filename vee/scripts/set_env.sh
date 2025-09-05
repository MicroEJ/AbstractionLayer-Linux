#!/bin/bash
#
# BASH
#
# Copyright 2025 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# SSH connection infos for application deployment

# Source Local environment variables
local_env_file="${SCRIPTS_DIR}/set_local_env.sh"
local_env_template="${local_env_file}.tpl"
if [ ! -f "${local_env_file}" ]; then
    echo "Copying ${local_env_template} from ${local_env_file}"
    cp "${local_env_template}" "${local_env_file}"
fi
. "${local_env_file}"

# Source VEE Port project environment
project_env_file="${SCRIPTS_DIR}/set_project_env.sh"
if [ -f "${project_env_file}" ]; then
    . "${project_env_file}"
else
    echo ""
    echo "ERROR: Missing ${project_env_file} script."
    echo ""
    exit 1
fi
