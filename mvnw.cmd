@REM ----------------------------------------------------------------------------
@REM MailShield Maven Wrapper Batch Script
@REM ----------------------------------------------------------------------------
@echo off
setlocal

set "DIRNAME=%~dp0"
if "%DIRNAME%" == "" set "DIRNAME=."

if exist "%DIRNAME%\.tools\apache-maven-3.9.6\bin\mvn.cmd" (
    call "%DIRNAME%\.tools\apache-maven-3.9.6\bin\mvn.cmd" %*
) else (
    call mvn %*
)

