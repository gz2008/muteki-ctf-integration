# Intentionally a simple script with no param block: PowerShell then leaves
# python-style options (--out, --write, -n) untouched in $args. With a
# [Parameter(ValueFromRemainingArguments)] block PowerShell instead tried to
# bind "--out" as "-Out..." and aborted with "parameter name 'out' is
# ambiguous" / "cannot find parameter '-write'".
[string[]]$Rest = @($args)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Distro = if ($env:CTF_KALI_DISTRO) { $env:CTF_KALI_DISTRO } else { "ctf-kali" }
$KaliUser = if ($env:CTF_KALI_USER) { $env:CTF_KALI_USER } else { "ctf" }
$WslExe = Join-Path $env:SystemRoot "System32\wsl.exe"

function ConvertTo-WslPath {
    param([string]$WindowsPath)
    $full = [IO.Path]::GetFullPath($WindowsPath)
    $drive = $full.Substring(0, 1).ToLowerInvariant()
    return "/mnt/$drive" + $full.Substring(2).Replace("\", "/")
}

$helper = ConvertTo-WslPath (Join-Path $Root "scripts\ctf-net.sh")
if (-not $Rest -or $Rest.Count -eq 0) {
    & $WslExe -d $Distro -u $KaliUser -- bash $helper --help
    exit $LASTEXITCODE
}
$converted = @()
foreach ($item in $Rest) {
    if ($item -match '^[A-Za-z]:[\\/]') { $converted += (ConvertTo-WslPath $item) }
    else { $converted += $item }
}

# An agent sandbox can refuse to start WSL (Wsl/Service/E_ACCESSDENIED), which
# would make this tool unusable in exactly the place a capture needs analysing.
# The analyser is stdlib-only, so fall back to the local python in that case.
$local = $env:CTF_LOCAL_PYTHON
if (-not $local) {
    & $WslExe -d $Distro -u $KaliUser -- bash -lc "true" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { $local = "python" }
}
if ($local) {
    $python = if ($local -eq "python") { (Get-Command python -ErrorAction SilentlyContinue).Source } else { $local }
    if (-not $python) { Write-Error "WSL is unavailable and no local python was found"; exit 3 }
    & $python (Join-Path $Root "scripts\ctf-net.py") @Rest
    exit $LASTEXITCODE
}

& $WslExe -d $Distro -u $KaliUser -- bash $helper @converted
exit $LASTEXITCODE
