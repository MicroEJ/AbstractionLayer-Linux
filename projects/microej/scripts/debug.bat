@echo off

REM BAT
REM Copyright 2021-2024 MicroEJ Corp. All rights reserved.
REM Use of this source code is governed by a BSD-style license that can be found with this software.

REM 'debug.bat' implementation for MicroEJ Linux builds.

REM Save application current directory and jump one level above scripts
SET CURRENT_DIRECTORY=%CD%
CD "%~dp0\..\"

CALL "%~dp0\set_project_env.bat" > NUL
IF %ERRORLEVEL% NEQ 0 (
	exit /B %ERRORLEVEL%
)

IF "%1"=="" (
	set APPLICATION_FILE="application.out"
) ELSE (
	set APPLICATION_FILE="%1"
)

WSL -d %WSL_DISTRIBUTION_NAME% --cd %CURRENT_DIRECTORY% sh -c "echo 0x37 > /proc/self/coredump_filter; gdb -x `wslpath "%~dp0\debug.gdb"` `wslpath -a %APPLICATION_FILE%`; cat /proc/self/coredump_filter"

CD "%CURRENT_DIRECTORY%"
