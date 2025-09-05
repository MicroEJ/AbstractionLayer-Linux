REM BAT
REM Copyright 2021-2024 MicroEJ Corp. All rights reserved.
REM Use of this source code is governed by a BSD-style license that can be found with this software.

REM Set the name of your WSL instance
REM To have the full list of WSL instances, run 'wsl --list'

IF [%WSL_DISTRIBUTION_NAME%] == [] (
    SET WSL_DISTRIBUTION_NAME=Ubuntu
)
