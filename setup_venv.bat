@echo off
REM Create the project virtual environment and install Portal.
REM Fail-closed: stop at the first error rather than reporting success anyway.
setlocal

python -m venv .venv
if errorlevel 1 exit /b 1

call .venv\Scripts\activate.bat
if errorlevel 1 exit /b 1

python -m pip install --upgrade pip
if errorlevel 1 exit /b 1

REM Foundation + tests. Add extras as phases need them, e.g. .[dev,ui,capture].
pip install -e .[dev]
if errorlevel 1 exit /b 1

echo.
echo Environment ready. Next: python scripts\smoke_native.py
