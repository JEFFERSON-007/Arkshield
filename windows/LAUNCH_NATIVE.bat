@echo off
REM ArkShield Native Desktop App Launcher
REM NO WEB SERVER - Pure native GUI

cd /d "%~dp0"

echo.
echo ========================================
echo   ArkShield Security Platform
echo   Native Desktop Application
echo ========================================
echo.
echo Starting ArkShield...
echo.

if exist "dist\ArkShield.exe" (
    echo ✅ Launching ArkShield.exe
    echo.
    echo This is a NATIVE DESKTOP APP:
    echo   - NO localhost/web browser
    echo   - Pure Windows GUI
    echo   - Real-time system monitoring
    echo.
    start "" "dist\ArkShield.exe"
    timeout /t 2 /nobreak >nul
    echo.
    echo ✅ ArkShield launched successfully!
    echo.
    echo Close this window or press any key...
    pause >nul
) else (
    echo ❌ Error: ArkShield.exe not found!
    echo.
    echo Please build the application first:
    echo    BUILD_GUI_EXE.bat
    echo.
    pause
)
