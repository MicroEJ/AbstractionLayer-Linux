@echo off

REM BAT
REM Copyright 2021-2024 MicroEJ Corp. All rights reserved.
REM Use of this source code is governed by a BSD-style license that can be found with this software.

REM 'set_project_env.bat' implementation for MicroEJ Linux builds.

REM 'set_project_env' is responsible for
REM - checking the availability of required environment variables 
REM - setting project local variables for 'build.bat' and 'run.bat' 

REM Load local settings if the file exists.  See set_local_env.bat.tpl for an example.
SET LOCAL_ENV_SCRIPT="%~dp0\set_local_env.bat"
IF EXIST "%LOCAL_ENV_SCRIPT%" (
   ECHO "Load %LOCAL_ENV_SCRIPT%"
   CALL "%LOCAL_ENV_SCRIPT%"
   IF %ERRORLEVEL% NEQ 0 (
      exit /B %ERRORLEVEL%
   )
) ELSE (
   ECHO ERROR: Missing set_local_env.bat script.
   ECHO Please create it using set_local_env.bat.tpl as an example.
   exit 1
)

IF [%WSL_DISTRIBUTION_NAME%] == [] (
	ECHO Please set the environment variable 'WSL_DISTRIBUTION_NAME' to the name of your WSL instance.
	EXIT 1
)
