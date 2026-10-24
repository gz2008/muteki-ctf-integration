[CmdletBinding()]
param(
    [string]$Name = "CTF Studio",
    [string]$Desktop = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Exe = Join-Path $Root "studio\dist\CTFStudio.exe"
$Cmd = Join-Path $Root "bin\ctf-studio.cmd"
$Icon = Join-Path $Root "studio\ctf-studio.ico"
if (Test-Path -LiteralPath $Exe) {
    $Target = $Exe
    $IconLocation = "$Exe,0"
} else {
    $Target = $Cmd
    $IconLocation = "$Icon,0"
}
if (-not (Test-Path -LiteralPath $Target)) { throw "missing entry: $Target" }
if (-not $Desktop) { $Desktop = [Environment]::GetFolderPath("Desktop") }
if (-not $Desktop -or -not (Test-Path -LiteralPath $Desktop)) { throw "desktop folder not found" }
if (-not (Test-Path -LiteralPath $Icon)) { throw "missing icon: $Icon" }

$Shortcut = Join-Path $Desktop ($Name + ".lnk")
$Shell = New-Object -ComObject WScript.Shell
$Link = $Shell.CreateShortcut($Shortcut)
$Link.TargetPath = $Target
$Link.WorkingDirectory = $Root
$Link.IconLocation = $IconLocation
$Link.Description = "Muteki CTF Studio - 本地图形化 CTF 解题工作台"
$Link.WindowStyle = 1
$Link.Save()

$Check = $Shell.CreateShortcut($Shortcut)
[pscustomobject]@{
    Shortcut = $Shortcut
    Target = $Check.TargetPath
    WorkingDirectory = $Check.WorkingDirectory
    Icon = $Check.IconLocation
    Exists = (Test-Path -LiteralPath $Shortcut)
}
