[CmdletBinding()]
param(
    [string]$Python = $env:CTF_LOCAL_PYTHON,
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Studio = Join-Path $Root "studio"
$Venv = Join-Path $Studio ".desktop-venv"
$VenvPython = Join-Path $Venv "Scripts\python.exe"
$VenvPyInstaller = Join-Path $Venv "Scripts\pyinstaller.exe"

if (-not $Python) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source }
}
if (-not $Python) { throw "python not found; set CTF_LOCAL_PYTHON" }

if (-not (Test-Path -LiteralPath $VenvPython)) {
    & $Python -m venv $Venv
}
if (-not $SkipInstall) {
    & $VenvPython -m pip install --upgrade pip --quiet
    & $VenvPython -m pip install pywebview pyinstaller --quiet
}
if (-not (Test-Path -LiteralPath $VenvPyInstaller)) {
    throw "pyinstaller missing; rerun without -SkipInstall"
}

$AddData = "$Studio\web;studio\web"
$Icon = Join-Path $Studio "ctf-studio.ico"
Push-Location $Root
try {
    & $VenvPyInstaller `
        --noconfirm --clean --onefile --windowed `
        --name CTFStudio `
        --icon $Icon `
        --add-data $AddData `
        --collect-all webview `
        --collect-all clr_loader `
        --collect-all pythonnet `
        --hidden-import webview.platforms.edgechromium `
        --paths $Studio `
        --distpath (Join-Path $Studio "dist") `
        --workpath (Join-Path $Studio "build") `
        --specpath $Studio `
        (Join-Path $Studio "desktop.py")
    if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

$Exe = Join-Path $Studio "dist\CTFStudio.exe"
if (-not (Test-Path -LiteralPath $Exe)) { throw "build output missing: $Exe" }
Get-Item $Exe | Select-Object FullName,Length,LastWriteTime
