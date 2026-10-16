@echo off
setlocal
set "ROOT=%~dp0.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\bin\ctf-xor.ps1" %*
exit /b %errorlevel%
