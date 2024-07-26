#!/bin/bash
#
# BASH
#
# Copyright 2023-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# 'run.sh' implementation for MicroEJ Linux builds.

# 'run.sh' is responsible for producing the executable file.

# Exit on failure
set -e

# Save application current directory
CURRENT_DIRECTORY=$(pwd)

if [ -z "$1" ]; then
	APPLICATION_FILE="$(pwd)/application.out"
else
	APPLICATION_FILE="$(cd $(dirname $1) ; pwd)/$(basename $1)"
fi

cd $(dirname "$0")

if [ ! -e "${APPLICATION_FILE}" ]; then
	echo "FAILED - file '${APPLICATION_FILE}' does not exist"
	exit -1
fi

PROJECT_ENV_FILE=./set_project_env.sh
if [ -f "$PROJECT_ENV_FILE" ]; then
	. $PROJECT_ENV_FILE
else
	echo ""
	echo "ERROR: Missing set_project_env.sh script."
	echo ""
	exit -1
fi

LOCAL_ENV_FILE=./set_local_env.sh
if [ -f "$LOCAL_ENV_FILE" ]; then
	. $LOCAL_ENV_FILE
else
	echo ""
	echo "ERROR: Missing set_local_env.sh script."
	echo "For local build, please create it using set_local_env.sh.tpl as example."
	echo ""
	exit -1
fi

#### Run application locally (X86 only) if the project has set LOCAL_DEPLOY=yes
if [ "$LOCAL_DEPLOY" == "yes" ]; then
	chmod +x $APPLICATION_FILE
	$APPLICATION_FILE
	exit 0
fi

#### Run application on target
if [ "$SSH_HOSTNAME" == "" ]; then
	echo "Please set the SSH_HOSTNAME environment variable with the target board's IP address"
	exit -1
fi

if [ "$SSH_USER" == "" ]; then
	echo "Please set the SSH_USER environment variable with the target board's user name"
	exit -1
fi

if [ "$SSH_PASSWORD" == "" ]; then
	echo "NOTICE: No ssh password set to connect to the target board."
	echo "If ssh password is required, please set it with the SSH_PASSWORD environment variable"
	#set dummy password as sshpass does not support empty password
	SSH_PASSWORD_OPTION=""
else
	SSH_PASSWORD_OPTION="sshpass -p $SSH_PASSWORD"
fi


if [ "$SSH_REMOTE_DIRECTORY" == "" ]; then
	#use /tmp as default remote directory where the application will be copied
	SSH_REMOTE_DIRECTORY="/tmp"
fi

SSH_REMOTE_APPLICATION=$SSH_REMOTE_DIRECTORY/application.out

#check if the remote directory where the application will be copied exists and create it if needed
$SSH_PASSWORD_OPTION ssh -oStrictHostKeyChecking=no $SSH_USER@$SSH_HOSTNAME "test -d $SSH_REMOTE_DIRECTORY || mkdir -p $SSH_REMOTE_DIRECTORY"

# kill old process if it exists
$SSH_PASSWORD_OPTION ssh -oStrictHostKeyChecking=no $SSH_USER@$SSH_HOSTNAME "killall -q startup.out || killall -q application.out || true"

$SSH_PASSWORD_OPTION scp -oStrictHostKeyChecking=no ${APPLICATION_FILE} $SSH_USER@$SSH_HOSTNAME:$SSH_REMOTE_APPLICATION

$SSH_PASSWORD_OPTION ssh -oStrictHostKeyChecking=no $SSH_USER@$SSH_HOSTNAME "chmod +x $SSH_REMOTE_APPLICATION &&  LLDISPLAY_USE_VSYNC=1 exec $SSH_REMOTE_APPLICATION"

# Restore application directory
cd $CURRENT_DIRECTORY/

