@echo off
rem Driver Doctor - repair. Creates a restore point and driver backup, then asks before EVERY change.
rem SEC-003: this runs as administrator, so keep the folder where only administrators can change it
rem (see README). The path reaches PowerShell through an environment variable, never as code, so a
rem quote or $ in a folder name cannot break or change the elevation command.
fltmc >nul 2>&1 || (
  set "DD_SELF=%~f0"
  powershell -NoProfile -Command "Start-Process -FilePath $env:DD_SELF -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DriverDoctor.ps1" -Mode Repair %*
echo.
pause
