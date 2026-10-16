@echo off
setlocal
set "ROOT=%~dp0.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\bin\ctf-index.ps1" %*
exit /b %errorlevel%
