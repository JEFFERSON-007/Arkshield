@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ========================================
echo   ArkShield Desktop Application
echo   Windows Native Version
echo ========================================
echo.

set "PY_CMD="

REM Check virtual environments with working uvicorn installation
for %%V in ("%~dp0..\.venv-2\Scripts\python.exe" "%~dp0..\.venv-1\Scripts\python.exe" "%~dp0..\.venv\Scripts\python.exe" "%~dp0.venv\Scripts\python.exe") do (
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
    for %%V in ("%~dp0..\.venv-2\Scripts\python.exe" "%~dp0..\.venv-1\Scripts\python.exe" "%~dp0..\.venv\Scripts\python.exe" "%~dp0.venv\Scripts\python.exe") do (
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

set "PYTHONPATH=%~dp0..\src;%PYTHONPATH%"
set "ARKSHIELD_API_KEY=arkshield-dev-key-2026"

echo Starting ArkShield with !PY_CMD!...
echo (No browser dependencies required!)
echo.

"!PY_CMD!" arkshield_app.py

if %errorlevel% neq 0 (
    echo.
    echo ========================================
    echo   Error: Failed to start application
    echo ========================================
    echo.
    echo Try running manually:
    echo   !PY_CMD! arkshield_app.py
    echo.
    pause
    exit /b 1
)

exit /b 0

