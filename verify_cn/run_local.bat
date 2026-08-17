@echo off
rem Wrapper for scheduled task (mkdy-verify-local). ASCII only to avoid encoding issues.
setlocal
set "PY=C:\Users\Admin\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
set "DIR=%~dp0"
set "LOGDIR=%DIR%logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
set "LOG=%LOGDIR%\run.log"

rem rotate log when it exceeds ~5MB
for %%F in ("%LOG%") do if %%~zF GTR 5242880 move /y "%LOG%" "%LOGDIR%\run.prev.log" >nul 2>&1

"%PY%" "%DIR%run_local.py" -c 20 -t 10 >> "%LOG%" 2>&1
exit /b %ERRORLEVEL%
