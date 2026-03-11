@echo off
REM ArkShield Windows Desktop Application Launcher
REM Uses Microsoft Edge app mode (no additional dependencies needed)

echo ========================================
echo   ArkShield Desktop Application
echo   Windows Native Version
echo ========================================
echo.

echo Starting ArkShield in Edge app mode...
echo (No browser dependencies required!)
echo.
python arkshield_app.py

if %errorlevel% neq 0 (
    echo.
    echo ========================================
    echo   Error: Failed to start application
    echo ========================================
    echo.
    echo Try running manually:
    echo   python arkshield_app.py
    echo.
    pause
    exit /b 1
)

exit /b 0
