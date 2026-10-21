@echo off
setlocal
cd /d "%~dp0"
title TriageArc - SOC Analyst Lab

echo.
echo  TriageArc - From signal to decision
echo  ------------------------------------
echo.

where py >nul 2>nul
if %errorlevel%==0 (
  set "PYTHON=py -3"
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo ERROR: Python 3 was not found.
    echo Install Python 3.11 or newer from https://www.python.org/downloads/windows/
    echo During setup, enable the option to add Python to PATH.
    pause
    exit /b 1
  )
  set "PYTHON=python"
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/3] Creating the project virtual environment...
  %PYTHON% -m venv .venv
  if errorlevel 1 goto failed
)

echo [2/3] Checking and installing required packages...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed

echo [3/3] Starting TriageArc in your browser...
echo Keep this window open while using the lab.
echo To stop the local server, press Ctrl+C.
start "" http://127.0.0.1:5000
".venv\Scripts\python.exe" app.py
if errorlevel 1 goto failed
exit /b 0

:failed
echo.
echo Startup did not complete. Read the error above.
echo If package installation failed, check your internet connection and try again.
pause
exit /b 1
