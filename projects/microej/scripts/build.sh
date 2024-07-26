#!/bin/bash
#
# BASH
#
# Copyright 2021-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# 'build.sh' implementation for MicroEJ Linux builds.

# 'build.sh' is responsible for producing the executable file 
# then copying this executable file to the current directory where it has been executed to a file named 'application.out'

# Save application current directory
CURRENT_DIRECTORY=$(pwd)

cd $(dirname "$0")/
SCRIPTS_DIRECTORY=$(pwd)
CMAKE_BUILD_DIRECTORY=$SCRIPTS_DIRECTORY/../build

unset LD_LIBRARY_PATH

# Setup build environment variables
. set_project_env.sh

rm -rf $CMAKE_BUILD_DIRECTORY
mkdir -p $CMAKE_BUILD_DIRECTORY
cd $CMAKE_BUILD_DIRECTORY
cmake --toolchain ./scripts/toolchain.cmake $CMAKE_BUILD_DIRECTORY/..
#make -j VERBOSE=1
make -j

if [ $? -ne 0 ];
then
   exit -1
fi

# Copy the application file
if [ "$SCRIPTS_DIRECTORY" != "$CURRENT_DIRECTORY" ];
then
    cp $SCRIPTS_DIRECTORY/application.out $CURRENT_DIRECTORY/application.out
fi
# Copy the map file
cp $CMAKE_BUILD_DIRECTORY/microej_gcc.map $CURRENT_DIRECTORY/application.map

if [ $? -ne 0 ];
then
    exit -1
fi

echo "The application executable file has been generated here: $CURRENT_DIRECTORY/application.out"
# Restore application directory
cd $CURRENT_DIRECTORY/
