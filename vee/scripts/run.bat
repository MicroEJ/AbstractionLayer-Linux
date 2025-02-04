@echo off

REM BAT
REM Copyright 2021-2024 MicroEJ Corp. All rights reserved.
REM Use of this source code is governed by a BSD-style license that can be found with this software.

REM 'run.bat' implementation for MicroEJ Linux builds.

REM 'run.bat' is responsible for running the executable file.

REM Save application current directory and jump one level above scripts
SET CURRENT_DIRECTORY=%CD%
CD "%~dp0\..\"

SET BSP_ROOT_DIRECTORY=%~dp0\..\..\

CALL "scripts\set_project_env.bat" > NUL
IF %ERRORLEVEL% NEQ 0 (
	exit /B %ERRORLEVEL%
)

IF "%1"=="" (
	set APPLICATION_FILE="application.out"
) ELSE (
	For %%A in ("%1") do (
	    set APPLICATION_FILE=%%~nxA
	)
)

SET VARS=SSH_HOSTNAME=%SSH_HOSTNAME% SSH_USER=%SSH_USER%

WSL -d %WSL_DISTRIBUTION_NAME% --cd %CURRENT_DIRECTORY% sh -c "%VARS% bash $(wslpath '%BSP_ROOT_DIRECTORY%')/vee/scripts/run.sh $(wslpath '%APPLICATION_FILE%')"
IF %ERRORLEVEL% NEQ 0 (
	exit /B %ERRORLEVEL%
)

CD "%CURRENT_DIRECTORY%"
