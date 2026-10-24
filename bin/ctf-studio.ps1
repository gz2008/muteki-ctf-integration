# Intentionally no param block: python-style options must pass through untouched.
[string[]]$Rest = @($args)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Python = $env:CTF_LOCAL_PYTHON
if (-not $Python) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source }
}
if (-not $Python) {
    Write-Error "no local python found; set CTF_LOCAL_PYTHON"
    exit 3
}

$arguments = @((Join-Path $Root "studio\server.py"), "--open") + $Rest
& $Python @arguments
exit $LASTEXITCODE
