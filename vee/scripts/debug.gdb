#
# GDB script
#
# Copyright 2022-2024 MicroEJ Corp. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be found with this software.

# The following GDB script generates a core dump file when:
# 
# - the signal SIGUSR1 is received,
# - or when a out of memory error occurs,
# - or when an explicit garbage collection (GC) is done.

set confirm off
set pagination off

set $id = 1 

catch signal SIGUSR1
commands
silent
eval "generate-core-file vee-core-%d-sig.elf", $id
set $id = $id+1
cont
end

break LLMJVM_on_OutOfMemoryError_thrown
commands
silent
eval "generate-core-file vee-core-%d-oome.elf", $id
set $id = $id+1
cont
end

break LLMJVM_on_Runtime_gc_done
commands
silent
eval "generate-core-file vee-core-%d-gc.elf", $id
set $id = $id+1
cont
end

run
quit