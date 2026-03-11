@echo off
REM Quick launcher for ArkShield Desktop App

cd /d "%~dp0"

echo.
echo ========================================
echo   Launching ArkShield
echo ========================================
echo.
echo ✓ Web Dashboard UI (same HTML interface)
echo ✓ Native Desktop Window
echo ✓ Real-Time Security Monitoring
echo.

if exist "dist\ArkShield.exe" (
    echo Starting ArkShield...
    start "" "dist\ArkShield.exe"
    echo.
    echo ✅ ArkShield launched successfully!
    echo    A native window with web dashboard will open.
    echo.
) else (
    echo ❌ ArkShield.exe not found in dist folder!
    echo    Run BUILD_GUI_EXE.bat first to build the application.
    echo.
    pause
)
