@echo off
cd /d "%~dp0"
echo ==========================================================
echo          Arkshield Git Commit & Push Utility
echo ==========================================================
echo.
git status
echo.
echo Pushing commits to https://github.com/JEFFERSON-007/Arkshield ...
git push origin main
echo.
if %errorlevel% equ 0 (
    echo [SUCCESS] Push completed successfully!
) else (
    echo [NOTICE] If GitHub prompts for authentication, complete the sign-in prompt in your browser or enter your personal access token.
)
echo.
pause
