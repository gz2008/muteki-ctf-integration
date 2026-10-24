@echo off
setlocal EnableExtensions
set "ROOT=%~dp0"
set "PWSH=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
where pwsh.exe >nul 2>nul
if not errorlevel 1 set "PWSH=pwsh.exe"

if not "%~1"=="" goto :run_args

:menu
title CTF Studio Setup
cls
echo ============================================================
echo                  CTF Studio Setup
echo ============================================================
echo.
echo  1. Quick setup and start        RECOMMENDED
echo     Check Python and source, run a smoke test, open Studio.
echo     No large downloads, system changes, or admin rights.
echo.
echo  2. Full setup                   OPTIONAL
echo     Download offline corpora and build the desktop app.
echo     Requires several GB and a working WSL ctf-kali distro.
echo.
echo  3. Check environment only
echo  4. Exit
echo.
set "CHOICE="
set /p "CHOICE=Enter 1-4 and press Enter: "

if "%CHOICE%"=="1" goto :core
if "%CHOICE%"=="2" goto :full
if "%CHOICE%"=="3" goto :check
if "%CHOICE%"=="4" exit /b 0
echo.
echo Invalid choice.
pause
goto :menu

:core
call :bootstrap
if errorlevel 1 goto :failed
echo.
echo Core setup passed. Starting CTF Studio...
start "" "%ROOT%bin\ctf-studio.cmd"
exit /b 0

:full
echo.
echo Full setup downloads corpora and needs WSL with ctf-kali.
echo Keep the network connected; this may take several minutes.
echo.
call :bootstrap_ps -Full -CreateShortcut
if errorlevel 1 goto :failed
echo.
echo Full setup complete. Starting CTF Studio...
if exist "%ROOT%studio\dist\CTFStudio.exe" (
    start "" "%ROOT%studio\dist\CTFStudio.exe"
) else (
    start "" "%ROOT%bin\ctf-studio.cmd"
)
exit /b 0

:check
call :bootstrap
if errorlevel 1 goto :failed
echo.
echo Environment check complete. Press any key to close.
pause >nul
exit /b 0

:bootstrap
call :bootstrap_ps
exit /b %errorlevel%

:bootstrap_ps
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\bootstrap.ps1" %*
exit /b %errorlevel%

:run_args
"%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%ROOT%scripts\bootstrap.ps1" %*
exit /b %errorlevel%

:failed
echo.
echo ============================================================
echo Setup failed. Copy the full error text or take a screenshot.
echo Common causes:
echo   - Python 3.10+ is missing or not on PATH
echo   - WSL is stopped or ctf-kali does not exist
echo   - Full setup needs network access and enough disk space
echo.
echo Python: https://www.python.org/downloads/
echo Guide:  %ROOT%docs\USAGE.zh-CN.md
echo ============================================================
pause
exit /b 1
