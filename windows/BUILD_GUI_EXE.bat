@echo off
REM ArkShield Native GUI EXE Builder
REM Creates a standalone desktop application with NATIVE INTERFACE (NO LOCALHOST)

echo ========================================
echo   ArkShield Native GUI Builder
echo ========================================
echo.

cd /d "%~dp0"

echo [1/4] Checking PyInstaller...
python -m pip show PyInstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller...
    python -m pip install PyInstaller -q
)
echo ✓ PyInstaller ready
echo.

echo [2/4] Building ArkShield.exe...
echo This creates a NATIVE DESKTOP APP (NO LOCALHOST)
echo Cross-platform GUI - Works on Windows and Linux
echo This may take 1-2 minutes...
echo.

rmdir /s /q build dist 2>nul

python -m PyInstaller ^
    arkshield_native.py ^
    --name=ArkShield ^
    --onefile ^
    --windowed ^
    --clean ^
    --distpath=dist ^
    --workpath=build ^
    --specpath=. ^
    --hidden-import=psutil ^
    --hidden-import=tkinter ^
    --exclude-module=matplotlib ^
    --exclude-module=numpy ^
    --exclude-module=pandas ^
    --exclude-module=scipy ^
    --exclude-module=PIL ^
    --exclude-module=cv2 ^
    --exclude-module=fastapi ^
    --exclude-module=starlette ^
    --exclude-module=uvicorn ^
    --exclude-module=flask ^
    --exclude-module=django ^
    --exclude-module=pytest ^
    --exclude-module=setuptools ^
    --noconfirm

if %errorlevel% neq 0 (
    echo.
    echo ❌ Build failed!
    pause
    exit /b 1
)

echo.
echo [3/4] Verifying...

if exist "dist\ArkShield.exe" (
    echo ✓ ArkShield.exe created successfully!
    echo.
    
    echo [4/4] Completed!
    echo.
    echo ========================================
    echo   BUILD COMPLETE!
    echo ========================================
    echo.
    echo 📍 Location: %cd%\dist\ArkShield.exe
    echo.
    echo 🚀 This is a NATIVE DESKTOP APPLICATION:
    echo    ✓ Pure native GUI (no web browser/localhost)
    echo    ✓ Modern dark theme interface
    echo    ✓ Real-time system monitoring
    echo    ✓ Process, network, disk monitoring
    echo    ✓ Live activity feed
    echo    ✓ Cross-platform (Windows + Linux compatible)
    echo    ✓ NO web server required
    echo.
    echo 🎯 How to use:
    echo.
    echo   1. Double-click ArkShield.exe
    echo      A native Windows window opens instantly
    echo.
    echo   2. Create Desktop shortcut:
    echo      Right-click ArkShield.exe ^> Send to ^> Desktop
    echo.
    echo   3. Pin to Start Menu:
    echo      Right-click ArkShield.exe ^> Pin to Start
    echo.
    echo ========================================
    echo.
) else (
    echo ❌ ArkShield.exe was not created!
    echo Check the error messages above.
    pause
    exit /b 1
)

pause
