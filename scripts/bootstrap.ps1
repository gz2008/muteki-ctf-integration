[CmdletBinding()]
param(
    [switch]$WithKnowledge,
    [switch]$BuildDesktop,
    [switch]$CreateShortcut,
    [switch]$Full,
    [switch]$SkipVerify
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

if ($Full) {
    $WithKnowledge = $true
    $BuildDesktop = $true
}

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "OK  $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "WARN $Message" -ForegroundColor Yellow
}

function Resolve-Python {
    if ($env:CTF_LOCAL_PYTHON -and (Test-Path -LiteralPath $env:CTF_LOCAL_PYTHON)) {
        return (Resolve-Path -LiteralPath $env:CTF_LOCAL_PYTHON).Path
    }
    $command = Get-Command python -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $command = Get-Command py -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw "Python 3.10+ was not found. Install Python and enable 'Add Python to PATH'."
}

function Resolve-PowerShell {
    $command = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $command = Get-Command powershell.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return ""
}

Write-Host "CTF Studio bootstrap" -ForegroundColor White
Write-Host "Repository: $Root"
Write-Host "Default mode is core-only: no large downloads and no system settings are changed."

Write-Step "Checking Python"
$Python = Resolve-Python
$Version = & $Python -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
if ($LASTEXITCODE -ne 0) { throw "Python could not run: $Python" }
if ([version]$Version -lt [version]"3.10") {
    throw "Python 3.10+ is required; found $Version at $Python"
}
Write-Ok "Python $Version"

$RequiredFiles = @(
    "studio\server.py",
    "studio\web\index.html",
    "scripts\ctf-triage.py",
    "bin\ctf-studio.cmd"
)
foreach ($Relative in $RequiredFiles) {
    $Path = Join-Path $Root $Relative
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Incomplete checkout: missing $Relative"
    }
}
Write-Ok "Core files are present"

Write-Step "Checking the local toolchain"
$Distro = if ($env:CTF_KALI_DISTRO) { $env:CTF_KALI_DISTRO } else { "ctf-kali" }
$Wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
$WslReady = $false
if ($Wsl) {
    & $Wsl.Source -d $Distro -- echo WSL_OK *> $null
    $WslReady = ($LASTEXITCODE -eq 0)
}
if ($WslReady) {
    Write-Ok "WSL distribution '$Distro' is available"
} else {
    Write-Warn "WSL distribution '$Distro' is not available"
    Write-Host "     Core analysis still works, but pwntools/GDB/Docker/Kali commands need WSL."
    Write-Host "     Full setup: wsl.exe --install --no-distribution, reboot, then prepare $Distro."
}

$Codex = Get-Command codex -ErrorAction SilentlyContinue
if ($Codex) {
    Write-Ok "Codex CLI: $($Codex.Source)"
} else {
    Write-Warn "Codex CLI not found; the local and Muteki modes do not require it."
}

if (-not $SkipVerify) {
    Write-Step "Running core verification"
    & $Python -m py_compile `
        (Join-Path $Root "studio\server.py") `
        (Join-Path $Root "studio\desktop.py")
    if ($LASTEXITCODE -ne 0) { throw "Python syntax verification failed" }
    Write-Ok "Studio Python sources compile"

    $TriageOutput = & $Python `
        (Join-Path $Root "scripts\ctf-triage.py") `
        --json `
        (Join-Path $Root "README.md")
    if ($LASTEXITCODE -ne 0) { throw "ctf-triage smoke test failed" }
    $TriageOutput | ConvertFrom-Json | Out-Null
    Write-Ok "ctf-triage produced valid JSON"
}

if ($WithKnowledge) {
    Write-Step "Installing offline knowledge corpora"
    if (-not $WslReady) {
        throw "Offline corpus provisioning needs a working WSL distribution named '$Distro'. Start WSL and rerun with -WithKnowledge."
    }
    $Ps = Resolve-PowerShell
    if (-not $Ps) { throw "PowerShell was not found" }
    $Fetch = Join-Path $Root "scripts\fetch-knowledge.ps1"
    $Verify = Join-Path $Root "scripts\verify-knowledge.ps1"
    if (-not (Test-Path -LiteralPath $Fetch)) { throw "Missing $Fetch" }
    Write-Host "This downloads about 1.4 GB and extracts a larger generated tree."
    & $Ps -NoProfile -File $Fetch
    if ($LASTEXITCODE -ne 0) { throw "Knowledge provisioning failed" }
    if (Test-Path -LiteralPath $Verify) {
        & $Ps -NoProfile -File $Verify
        if ($LASTEXITCODE -ne 0) { throw "Knowledge verification failed" }
    }
    Write-Ok "Offline knowledge is ready"
}

if ($BuildDesktop) {
    Write-Step "Building the native desktop application"
    $Ps = Resolve-PowerShell
    if (-not $Ps) { throw "PowerShell was not found" }
    & $Ps -NoProfile -File (Join-Path $Root "scripts\build-desktop.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Desktop build failed" }
    Write-Ok "Desktop build completed"
}

if ($CreateShortcut) {
    Write-Step "Creating the desktop shortcut"
    $Ps = Resolve-PowerShell
    if (-not $Ps) { throw "PowerShell was not found" }
    & $Ps -NoProfile -File (Join-Path $Root "scripts\create-studio-shortcut.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Shortcut creation failed" }
    Write-Ok "Shortcut created"
}

Write-Host ""
Write-Host "Bootstrap complete." -ForegroundColor Green
if (Test-Path -LiteralPath (Join-Path $Root "studio\dist\CTFStudio.exe")) {
    Write-Host "Launch: $Root\studio\dist\CTFStudio.exe"
} else {
    Write-Host "Launch: $Root\bin\ctf-studio.cmd"
}
if (-not $WithKnowledge) {
    Write-Host "Optional full knowledge setup: .\bootstrap.cmd -WithKnowledge"
}
if (-not $WslReady) {
    Write-Host "Full Kali tools remain optional and require WSL2."
}
