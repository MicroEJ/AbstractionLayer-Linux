@echo off
SETLOCAL ENABLEEXTENSIONS

REM BAT
REM Copyright 2021-2024 MicroEJ Corp. All rights reserved.
REM Use of this source code is governed by a BSD-style license that can be found with this software.

REM 'build.bat' implementation for MicroEJ Linux builds.

REM 'build.bat' is responsible for producing the executable file.

REM Save application current directory and jump one level above scripts
SET CURRENT_DIRECTORY=%CD%
CD "%~dp0\..\"

SET BSP_ROOT_DIRECTORY=%~dp0\..\..\..\
REM Set the default value for 'ENV_BASH_CMD' environment variable (default is to build a full features firmware) 

CALL "scripts\set_project_env.bat"

IF %ERRORLEVEL% NEQ 0 (
	ECHO error level %ERRORLEVEL%
	EXIT /B %ERRORLEVEL%
)

SET VARS=WSL_DISTRIBUTION_NAME=%WSL_DISTRIBUTION_NAME% APP_SDK_INSTALL=%APP_SDK_INSTALL%

WSL -d %WSL_DISTRIBUTION_NAME% --cd %CURRENT_DIRECTORY% bash -c "dos2unix $(wslpath '%BSP_ROOT_DIRECTORY%')/projects/microej/scripts/*.sh && %VARS% bash $(wslpath '%BSP_ROOT_DIRECTORY%')/projects/microej/scripts/build.sh"

IF %ERRORLEVEL% NEQ 0 (
	EXIT /B %ERRORLEVEL%
)

REM Restore application directory
CD "%CURRENT_DIRECTORY%"

IF %ERRORLEVEL% NEQ 0 (
	EXIT /B %ERRORLEVEL%
)
