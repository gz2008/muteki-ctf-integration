@echo off
:: Windows-native entry. See ctf-triage.cmd for why this bypasses powershell.exe.
setlocal
set "ROOT=%~dp0.."
set "PY=%CTF_LOCAL_PYTHON%"
if not defined PY for /f "delims=" %%I in ('where python 2^>nul') do if not defined PY set "PY=%%I"
if not defined PY for /f "delims=" %%I in ('where py 2^>nul') do if not defined PY set "PY=%%I"
if not defined PY (
    echo %~n0: no local python found. Set CTF_LOCAL_PYTHON to a python.exe path, 1>&2
    echo or use the WSL twin: scripts\ctf-repair.sh 1>&2
    exit /b 3
)
"%PY%" "%ROOT%\scripts\ctf-repair.py" %*
exit /b %errorlevel%
