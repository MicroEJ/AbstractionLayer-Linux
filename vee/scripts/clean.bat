@echo off

REM BAT
REM Copyright 2026 MicroEJ Corp. All rights reserved.
REM Use of this source code is governed by a BSD-style license that can be found with this software.
REM
REM Build: 7E4D1F7C

REM 'clean.bat' implementation for MicroEJ Linux builds.

REM 'clean.bat' is responsible for removing the C build outputs:
REM the CMake build directories ('vee\build-*'), the headers and libraries
REM deployed by the VEE Port build ('vee\inc', 'vee\lib') and the generated
REM application artifacts ('application.out', 'application.map').

SET VEE_DIRECTORY=%~dp0..

REM Remove the CMake build directories (one per compiler, see build.sh)
FOR /D %%D IN ("%VEE_DIRECTORY%\build-*") DO RMDIR /S /Q "%%D"

REM Remove the headers and libraries deployed by the VEE Port build
IF EXIST "%VEE_DIRECTORY%\inc" RMDIR /S /Q "%VEE_DIRECTORY%\inc"
IF EXIST "%VEE_DIRECTORY%\lib" RMDIR /S /Q "%VEE_DIRECTORY%\lib"

REM Remove the generated application artifacts
IF EXIST "%~dp0application.out" DEL /Q "%~dp0application.out"
IF EXIST "%~dp0application.map" DEL /Q "%~dp0application.map"

ECHO C build outputs removed.
