@echo off
cd /d "%~dp0\dist"
echo Launching ArkShield with Web Dashboard UI...
start "" ArkShield.exe
timeout /t 3 /nobreak >nul
echo.
echo ✅ ArkShield launched!
echo    Opening native window with web dashboard...
echo.
