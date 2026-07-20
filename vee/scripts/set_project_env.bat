@echo off

REM BAT
REM Copyright 2021-2026 MicroEJ Corp. All rights reserved.
REM Use of this source code is governed by a BSD-style license that can be found with this software.

REM 'set_project_env.bat' implementation for MicroEJ Linux builds.

REM 'set_project_env' is responsible for
REM - checking the availability of required environment variables 
REM - setting project local variables for 'build.bat' and 'run.bat' 

REM Load local settings if the file exists. Create local settings file from the template otherwise.

SET "LOCAL_ENV_SCRIPT=%~dp0\set_local_env.bat"
SET "LOCAL_ENV_SCRIPT_TPL=%LOCAL_ENV_SCRIPT%.tpl"

IF NOT EXIST "%LOCAL_ENV_SCRIPT%" (
	ECHO Copying "%LOCAL_ENV_SCRIPT_TPL%" to "%LOCAL_ENV_SCRIPT%"
	COPY "%LOCAL_ENV_SCRIPT_TPL%" "%LOCAL_ENV_SCRIPT%"
	IF %ERRORLEVEL% NEQ 0 (
		ECHO Failed to copy from template.
		exit /B %ERRORLEVEL%
	)
)

CALL "%LOCAL_ENV_SCRIPT%"
IF %ERRORLEVEL% NEQ 0 (
	exit /B %ERRORLEVEL%
)


IF [%WSL_DISTRIBUTION_NAME%] == [] (
	ECHO Please set the environment variable 'WSL_DISTRIBUTION_NAME' to the name of your WSL instance.
	EXIT 1
)
