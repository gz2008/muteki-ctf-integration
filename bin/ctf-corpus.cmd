@echo off
setlocal
set "ROOT=%~dp0.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\bin\ctf-corpus.ps1" %*
exit /b %errorlevel%
