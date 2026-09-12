@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ==========================================================
echo        ARKSHIELD - AUTONOMOUS CYBER DEFENSE PLATFORM
echo ==========================================================
echo.

set "PY_CMD="

REM Check virtual environments with working uvicorn installation
for %%V in ("%~dp0.venv-2\Scripts\python.exe" "%~dp0.venv-1\Scripts\python.exe" "%~dp0.venv\Scripts\python.exe") do (
    if "!PY_CMD!"=="" (
        if exist %%V (
            %%V -c "import uvicorn" >nul 2>&1
            if !errorlevel! equ 0 (
                set "PY_CMD=%%~V"
            )
        )
    )
)

REM Fallback to any working virtual environment python
if "!PY_CMD!"=="" (
    for %%V in ("%~dp0.venv-2\Scripts\python.exe" "%~dp0.venv-1\Scripts\python.exe" "%~dp0.venv\Scripts\python.exe") do (
        if "!PY_CMD!"=="" (
            if exist %%V (
                %%V --version >nul 2>&1
                if !errorlevel! equ 0 (
                    set "PY_CMD=%%~V"
                )
            )
        )
    )
)

REM Fallback to py -3 or system python
if "!PY_CMD!"=="" (
    py -3 --version >nul 2>&1
    if !errorlevel! equ 0 (
        set "PY_CMD=py -3"
    ) else (
        set "PY_CMD=python"
    )
)

echo [1/3] Python Interpreter: !PY_CMD!
echo [2/3] Setting PYTHONPATH to ./src...
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
set "ARKSHIELD_API_KEY=arkshield-dev-key-2026"

echo [3/3] Launching Arkshield Platform on http://127.0.0.1:8000 ...
echo.
echo ==========================================================
echo   Dashboard URL: http://127.0.0.1:8000
echo   API Docs:      http://127.0.0.1:8000/docs
echo   Default Key:   arkshield-dev-key-2026
echo   Press Ctrl+C in this terminal to stop.
echo ==========================================================
echo.

REM Open browser after 2 seconds
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:8000"

"!PY_CMD!" -m uvicorn --app-dir "%~dp0src" arkshield.api.server:app --host 127.0.0.1 --port 8000

if %errorlevel% neq 0 (
    echo.
    echo Uvicorn direct launch encountered an issue. Attempting desktop launcher...
    cd windows
    "!PY_CMD!" arkshield_app.py
)

pause
