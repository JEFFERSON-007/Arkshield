@echo off
REM Start ArkShield Web-Based Dashboard (Localhost Version)

cd /d "%~dp0\.."

echo.
echo ========================================
echo   ArkShield Web Dashboard
echo ========================================
echo.
echo Starting FastAPI server...
echo.

python -m uvicorn src.arkshield.api.server:app --host 127.0.0.1 --port 8000

echo.
echo Server stopped.
pause
