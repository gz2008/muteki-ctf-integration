@echo off
:: Windows-native entry. Runs the stdlib-only analyser with the local python and
:: forwards every argument untouched. Routing the call through
:: "powershell.exe -File <name>.ps1 -- %*" made PowerShell bind python-style
:: options ("--out", "--write") as PowerShell parameters and abort with
:: "parameter name 'out' is ambiguous" / "cannot find parameter '-write'",
:: which broke the documented usage of these tools.
setlocal
set "ROOT=%~dp0.."
set "PY=%CTF_LOCAL_PYTHON%"
if not defined PY for /f "delims=" %%I in ('where python 2^>nul') do if not defined PY set "PY=%%I"
if not defined PY for /f "delims=" %%I in ('where py 2^>nul') do if not defined PY set "PY=%%I"
if not defined PY (
    echo %~n0: no local python found. Set CTF_LOCAL_PYTHON to a python.exe path, 1>&2
    echo or use the WSL twin: scripts\ctf-triage.sh 1>&2
    exit /b 3
)
"%PY%" "%ROOT%\scripts\ctf-triage.py" %*
exit /b %errorlevel%
