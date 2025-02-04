#
# GDB script
#
# Copyright 2023-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# This script is invoked in the directory where are gathered the '.fo' files

set confirm off
set pagination off

b main
run

set $file_index = 1
while($file_index <= 4)

	eval "restore ./F%d.fo binary &'_java_rodata_resource_java_PF%d.fo'", $file_index, $file_index

    set $file_index = $file_index + 1
end

# Run the custom command when the GDB session starts
c

# Exit GDB after the injection
quit