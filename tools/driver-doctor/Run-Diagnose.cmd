@echo off
rem Driver Doctor - read-only diagnosis. Elevates (UAC prompt) and writes a report to your Desktop.
rem SEC-003: this runs as administrator, so keep the folder where only administrators can change it
rem (see README). The path reaches PowerShell through an environment variable, never as code, so a
rem quote or $ in a folder name cannot break or change the elevation command.
fltmc >nul 2>&1 || (
  set "DD_SELF=%~f0"
  powershell -NoProfile -Command "Start-Process -FilePath $env:DD_SELF -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DriverDoctor.ps1" -Mode Diagnose %*
echo.
pause
