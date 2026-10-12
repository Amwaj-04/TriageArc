@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run START_TRIAGEARC.bat first to create the environment.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m py_compile app.py database.py engine.py rules.py seed.py run_demo.py
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m unittest discover -s tests -v
if errorlevel 1 goto failed
echo.
echo TriageArc checks passed.
pause
exit /b 0
:failed
echo One or more checks failed. Review the error above.
pause
exit /b 1
