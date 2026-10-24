@echo off
:: CTF Studio - local graphical entry.  The server binds to 127.0.0.1 and
:: injects a per-process token into the page; no external service is required.
setlocal
set "ROOT=%~dp0.."
set "PY=%CTF_LOCAL_PYTHON%"
if not defined PY for /f "delims=" %%I in ('where python 2^>nul') do if not defined PY set "PY=%%I"
if not defined PY for /f "delims=" %%I in ('where py 2^>nul') do if not defined PY set "PY=%%I"
if not defined PY (
    echo %~n0: no local python found. Set CTF_LOCAL_PYTHON to a python.exe path, 1>&2
    exit /b 3
)
"%PY%" "%ROOT%\studio\server.py" --open %*
exit /b %errorlevel%
