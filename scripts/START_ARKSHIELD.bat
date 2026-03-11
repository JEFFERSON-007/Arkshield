@echo off
echo.
echo ====================================================================
echo   ARKSHIELD SECURITY PLATFORM - STARTUP SCRIPT
echo ====================================================================
echo.

cd /d "%~dp0"

echo [1/3] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)
python --version

echo.
echo [2/3] Installing/Checking dependencies...
pip install -q fastapi uvicorn psutil 2>nul
if errorlevel 1 (
    echo Warning: Some dependencies might be missing
)

echo.
echo [3/3] Starting Arkshield Server...
echo.
python -m uvicorn src.arkshield.api.server:app --host 127.0.0.1 --port 8000 --reload

pause
