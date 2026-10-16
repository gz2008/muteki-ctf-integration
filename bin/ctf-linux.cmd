@echo off
:: Thin wrapper: the command text must reach the script with its own options
:: intact, so no extra quoting or parameter handling happens here.
setlocal
set "ROOT=%~dp0.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\bin\ctf-linux.ps1" %*
exit /b %errorlevel%
