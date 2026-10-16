[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

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

$helper = ConvertTo-WslPath (Join-Path $Root "scripts\ctf-hashpump.sh")
if (-not $Rest -or $Rest.Count -eq 0) {
    & $WslExe -d $Distro -u $KaliUser -- bash $helper --help
    exit $LASTEXITCODE
}
& $WslExe -d $Distro -u $KaliUser -- bash $helper @Rest
exit $LASTEXITCODE
