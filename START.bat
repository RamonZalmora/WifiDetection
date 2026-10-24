@echo off
setlocal
cd /d "%~dp0"
if not exist "WPA2RecoveryLab.exe" (
  echo WPA2RecoveryLab.exe is missing. Use the Windows build instructions in README.md.
  pause
  exit /b 1
)
"%~dp0WPA2RecoveryLab.exe"
if errorlevel 1 (
  echo Application failed. Review the message above and README.txt.
  pause
  exit /b 1
)
