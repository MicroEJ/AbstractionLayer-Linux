#!/bin/bash
#
# BASH
#
# Copyright 2023-2025 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.
#
# SSH connection infos for application deployment

# Set the board's hostname (e.g. 192.168.13.22)
if [ -z "${SSH_HOSTNAME:-""}" ]; then
	SSH_HOSTNAME=""
fi

# Set the board's user name
if [ -z "${SSH_USER:-""}" ]; then
    SSH_USER="root"
fi

# Set the board's user password
if [ -z "${SSH_PASSWORD:-""}" ]; then
    SSH_PASSWORD=""
fi

# Set remote directory where the application will be copied (if not set, /bin is used as default remote directory)
if [ -z "${SSH_REMOTE_DIRECTORY:-""}" ]; then
    SSH_REMOTE_DIRECTORY=/bin
fi

# Set the temporary directory where the application will be localy copied and executed (X86 only if the project has set LOCAL_DEPLOY=yes)
if [ -z "${LOCAL_DEPLOY_TMP_DIRECTORY:-""}" ]; then
    LOCAL_DEPLOY_TMP_DIRECTORY=/tmp
fi