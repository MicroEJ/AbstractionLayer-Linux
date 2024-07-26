#!/bin/bash
#
# BASH
#
# Copyright 2023-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# 'debug.sh' implementation for MicroEJ Linux builds using GDB

. ./set_project_env.sh

if [ -z "$1" ]; then
    APPLICATION_FILE="$(pwd)/application.out"
else
    APPLICATION_FILE="$(cd $(dirname $1) ; pwd)/$(basename $1)"
fi

if [ ! -e "${APPLICATION_FILE}" ]; then
    echo "FAILED - file '${APPLICATION_FILE}' does not exist"
    exit -1
fi

# Instruct the Linux kernel to Dump file-backed private mappings.
echo 0x37 > /proc/self/coredump_filter

# Stard gdb.
$GDB -x $(dirname "$0")/debug.gdb ${APPLICATION_FILE}



