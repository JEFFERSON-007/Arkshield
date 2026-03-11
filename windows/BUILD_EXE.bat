@echo off
REM ArkShield EXE Builder for Windows
REM Creates a standalone executable file

echo ========================================
echo   ArkShield EXE Builder
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
echo This may take 2-5 minutes...
echo.

rmdir /s /q build dist 2>nul

python -m PyInstaller ^
    arkshield_app.py ^
    --name=ArkShield ^
    --onefile ^
    --windowed ^
    --clean ^
    --distpath=dist ^
    --workpath=build ^
    --specpath=. ^
    --add-data="..\src\arkshield;arkshield" ^
    --collect-all=fastapi ^
    --collect-all=starlette ^
    --collect-all=uvicorn ^
    --hidden-import=psutil ^
    --hidden-import=pydantic ^
    --exclude-module=matplotlib ^
    --exclude-module=tkinter ^
    --exclude-module=PIL ^
    --exclude-module=numpy ^
    --exclude-module=pandas ^
    --exclude-module=scipy ^
    --exclude-module=pytest ^
    --exclude-module=setuptools

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
    for /f "tokens=*" %%a in ('dir /b dist\ArkShield.exe ^| find "."') do set exe_size=%%~za
    
    echo [4/4] Completed!
    echo.
    echo ========================================
    echo   BUILD COMPLETE!
    echo ========================================
    echo.
    echo 📍 Location: %cd%\dist\ArkShield.exe
    echo.
    echo 🚀 How to use:
    echo.
    echo   1. Double-click ArkShield.exe to launch
    echo.
    echo   2. Create Desktop shortcut:
    echo      Right-click ArkShield.exe ^> Send to ^> Desktop (create shortcut)
    echo.
    echo   3. Add to Windows Start Menu:
    echo      Press Win+R, type shell:appsFolder
    echo      Create shortcut there
    echo.
    echo   4. Run from Command Prompt:
    echo      dist\ArkShield.exe
    echo.
    echo ========================================
    echo.
) else (
    echo ❌ ArkShield.exe was not created!
    echo Check the error messages above.
    pause
    exit /b 1
)
