@echo off
rem Driver Doctor - read-only diagnosis. Elevates (UAC prompt) and writes a report to your Desktop.
fltmc >nul 2>&1 || (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DriverDoctor.ps1" -Mode Diagnose %*
echo.
pause
