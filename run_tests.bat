@echo off
REM Run the full test suite in the project venv. Fail-closed on activation.
setlocal

call .venv\Scripts\activate.bat
if errorlevel 1 exit /b 1

python -m pytest -v
pause
exit /b %errorlevel%
