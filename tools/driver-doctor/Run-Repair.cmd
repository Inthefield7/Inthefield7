@echo off
rem Driver Doctor - repair. Creates a restore point and driver backup, then asks before EVERY change.
fltmc >nul 2>&1 || (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DriverDoctor.ps1" -Mode Repair %*
echo.
pause
