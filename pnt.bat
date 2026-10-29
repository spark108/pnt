@echo off
chcp 65001 >nul
if "%~2"=="-r" (
  "%ProgramData%\PNT\app\pnt.exe" install -r "%~3"
  exit /b
)
set "PNT_ACTION=%~1"
if "%PNT_ACTION%"=="" set "PNT_ACTION=status"
for %%A in (install update repair start stop restart status) do if /I "%PNT_ACTION%"=="%%A" goto management
if not exist "%ProgramData%\PNT\app\pnt.exe" (
  echo PNT is not installed. Run pnt.bat install from an Administrator terminal.
  exit /b 1
)
"%ProgramData%\PNT\app\pnt.exe" %*
exit /b
:management
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy\pnt.ps1" -Action "%PNT_ACTION%"
set "PNT_RESULT=%ERRORLEVEL%"
set "PATH=%PATH%;%ProgramData%\PNT\bin"
exit /b %PNT_RESULT%
