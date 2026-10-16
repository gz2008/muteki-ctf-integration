[CmdletBinding()]
param(
    # Limit to specific lock entry names, for example -Only hacktricks,vulhub
    [string[]]$Only = @(),
    # Re-download and re-extract entries even when the target already exists.
    [switch]$Force,
    # Skip the SecLists link and rockyou provisioning step.
    [switch]$SkipWordlists,
    # Alternate lock file, used by tests and by pinned variants.
    [string]$LockFile = ""
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
if (-not $LockFile) { $LockFile = Join-Path $Root "locks\knowledge-sources.json" }
$KaliDistro = if ($env:CTF_KALI_DISTRO) { $env:CTF_KALI_DISTRO } else { "ctf-kali" }
$KaliUser = if ($env:CTF_KALI_USER) { $env:CTF_KALI_USER } else { "ctf" }
$Tar = Join-Path $env:SystemRoot "System32\tar.exe"

function Get-Lock {
    if (-not (Test-Path -LiteralPath $LockFile)) { throw "knowledge lock file missing: $LockFile" }
    return (Get-Content -LiteralPath $LockFile -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Resolve-TargetPath {
    param([string]$ToolRoot, [string]$Relative, [string]$Name)
    if (-not $Relative) { throw "$Name has no target path" }
    if ([IO.Path]::IsPathRooted($Relative)) { throw "$Name target must be relative: $Relative" }
    $rootFull = [IO.Path]::GetFullPath($ToolRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $targetFull = [IO.Path]::GetFullPath((Join-Path $rootFull $Relative))
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $targetFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "unsafe target outside the tool root: $Name -> $targetFull"
    }
    return $targetFull
}

function ConvertTo-WslPath {
    param([string]$WindowsPath)
    $full = [IO.Path]::GetFullPath($WindowsPath)
    $drive = $full.Substring(0, 1).ToLowerInvariant()
    $rest = $full.Substring(2).Replace("\", "/")
    return "/mnt/$drive$rest"
}

function Test-DirectoryHasContent {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if (-not (Get-Item -LiteralPath $Path -Force).PSIsContainer) { return $false }
    return [bool](Get-ChildItem -LiteralPath $Path -Force | Select-Object -First 1)
}

function Get-RecordFileCount {
    param([string]$Path)
    return (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Measure-Object).Count
}

function Get-DirectoryBytes {
    param([string]$Path)
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { return [int64]0 }
    return [int64]$sum
}

function Invoke-Kali {
    param([string]$Script)
    & wsl.exe -d $KaliDistro -u $KaliUser -- bash -lc $Script
    if ($LASTEXITCODE -ne 0) { throw "ctf-kali command failed (exit $LASTEXITCODE): $Script" }
}

function Invoke-Download {
    param([string]$Url, [string]$Destination, [string]$Name)
    $partial = "$Destination.partial"
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    Write-Host "  DOWNLOAD $Name"
    & curl.exe -4 -L -sS --fail --retry 4 --retry-delay 3 --max-time 1800 --output $partial $Url
    if ($LASTEXITCODE -ne 0) {
        if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
        throw "download failed: $Name"
    }
    Move-Item -LiteralPath $partial -Destination $Destination -Force
}

function Remove-GitMetadata {
    param([string]$Path)
    $gitDirs = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory -Filter ".git" -ErrorAction SilentlyContinue)
    $treeRoot = [IO.Path]::GetFullPath($Path)
    foreach ($gitDir in $gitDirs) {
        $full = [IO.Path]::GetFullPath($gitDir.FullName)
        if (-not $full.StartsWith($treeRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "refusing to remove .git outside the target tree: $full"
        }
    }
    foreach ($gitDir in $gitDirs) { Remove-Item -LiteralPath $gitDir.FullName -Recurse -Force }
    return $gitDirs.Count
}

function Expand-ArchiveRooted {
    param([string]$Archive, [string]$Staging, [string]$Target, [bool]$StripRoot)
    New-Item -ItemType Directory -Path $Staging -Force | Out-Null
    # Corpora such as hacktricks carry member paths past the Windows 260-character
    # limit. bsdtar switches to a \\?\ prefix but keeps forward slashes there, which
    # Windows rejects, so extract inside ctf-kali first (Linux paths have no such
    # limit) and keep bsdtar only as a fallback.
    $extracted = $false
    try {
        # `; true` swallows unzip's warning exit code (1); an empty staging tree
        # is the real failure signal and falls back to bsdtar below.
        Invoke-Kali ("unzip -q -o '" + (ConvertTo-WslPath $Archive) + "' -d '" + (ConvertTo-WslPath $Staging) + "'; true")
        $extracted = [bool](Get-ChildItem -LiteralPath $Staging -Force | Select-Object -First 1)
    } catch {
        $extracted = $false
    }
    if (-not $extracted) {
        if (-not (Test-Path -LiteralPath $Tar)) { throw "no unzip in ctf-kali and bsdtar missing: $Tar" }
        Write-Host "  WARN unzip failed, retrying with bsdtar"
        & $Tar -xf $Archive -C $Staging
        if ($LASTEXITCODE -ne 0) { throw "extract failed: $Archive" }
    }
    $entries = @(Get-ChildItem -LiteralPath $Staging -Force)
    if ($entries.Count -eq 0) { throw "archive produced no content: $Archive" }
    if ($StripRoot) {
        New-Item -ItemType Directory -Path $Target -Force | Out-Null
        foreach ($child in Get-ChildItem -LiteralPath $entries[0].FullName -Force) {
            Move-Item -LiteralPath $child.FullName -Destination $Target -Force
        }
        Remove-Item -LiteralPath $Staging -Recurse -Force
        return
    }
    if ($entries.Count -ne 1 -or -not $entries[0].PSIsContainer) {
        throw "unexpected archive layout (expected one top-level directory): $Archive"
    }
    Move-Item -LiteralPath $entries[0].FullName -Destination $Target -Force
    Remove-Item -LiteralPath $Staging -Recurse -Force
}

$lock = Get-Lock
$ToolRoot = [IO.Path]::GetFullPath($lock.tool_root)
if (-not (Test-Path -LiteralPath $ToolRoot)) {
    # The lock records the absolute paths of the machine the corpora were pinned
    # on. On any other checkout they do not exist, so fall back to this
    # repository's own layout, which is what a fresh clone has.
    $ToolRoot = Join-Path $Root "muteki-tool-root"
    Write-Host "tool root recorded in the lock is missing here; using $ToolRoot"
}
$ArchiveRoot = [IO.Path]::GetFullPath($lock.archive_root)
if (-not (Test-Path -LiteralPath $ArchiveRoot)) {
    $ArchiveRoot = Join-Path $Root "archives\knowledge"
    Write-Host "archive root recorded in the lock is missing here; using $ArchiveRoot"
}
if (-not (Test-Path -LiteralPath $ToolRoot)) { throw "tool root missing: $ToolRoot" }

$selected = @($lock.entries)
if ($Only.Count -gt 0) {
    # `-File script.ps1 -Only a,b` hands over one literal string, so accept both
    # comma-separated and repeated forms.
    $Only = @($Only | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $unknown = @($Only | Where-Object { -not ($lock.entries.name -contains $_) })
    if ($unknown.Count -gt 0) { throw "unknown lock entry: $($unknown -join ', ')" }
    $selected = @($lock.entries | Where-Object { $Only -contains $_.name })
}

# Resolve every target before touching the network so a bad lock fails fast.
$plan = @()
foreach ($entry in $selected) {
    $plan += [pscustomobject]@{
        Entry  = $entry
        Target = (Resolve-TargetPath -ToolRoot $ToolRoot -Relative $entry.target -Name $entry.name)
    }
}

New-Item -ItemType Directory -Path $ArchiveRoot -Force | Out-Null

$results = @()
foreach ($item in $plan) {
    $entry = $item.Entry
    $target = $item.Target
    Write-Host "==> $($entry.name) ($($entry.repository)@$($entry.commit.Substring(0, 12)))"
    $parent = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }

    if (-not $Force -and (Test-DirectoryHasContent -Path $target)) {
        Write-Host "  SKIP already present"
        $results += [pscustomobject]@{ Name = $entry.name; Action = "skip"; Files = (Get-RecordFileCount -Path $target); Bytes = (Get-DirectoryBytes -Path $target) }
        continue
    }
    if ($Force -and (Test-Path -LiteralPath $target)) {
        Write-Host "  FORCE removing $target"
        Remove-Item -LiteralPath $target -Recurse -Force
    }

    $archive = Join-Path $ArchiveRoot "$($entry.name)-$($entry.commit).zip"
    if (-not (Test-Path -LiteralPath $archive) -or (Get-Item -LiteralPath $archive).Length -eq 0) {
        Invoke-Download -Url "https://codeload.github.com/$($entry.repository)/zip/$($entry.commit)" -Destination $archive -Name $entry.name
    } else {
        Write-Host "  REUSE archive $(Split-Path -Leaf $archive)"
    }
    $staging = Join-Path $ArchiveRoot ".staging-$($entry.name)-$([guid]::NewGuid().ToString('N'))"
    try {
        Expand-ArchiveRooted -Archive $archive -Staging $staging -Target $target -StripRoot ([bool]$entry.strip_root)
    } finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    }
    $gitRemoved = Remove-GitMetadata -Path $target
    $files = Get-RecordFileCount -Path $target
    Write-Host ("  READY files={0} bytes={1} git-dirs-removed={2}" -f $files, (Get-DirectoryBytes -Path $target), $gitRemoved)
    $results += [pscustomobject]@{ Name = $entry.name; Action = "fetch"; Files = $files; Bytes = (Get-DirectoryBytes -Path $target) }
}

if (-not $SkipWordlists) {
    Write-Host "==> wordlists"
    $helper = ConvertTo-WslPath (Join-Path $PSScriptRoot "knowledge-wordlists.sh")
    $wordlistResult = Invoke-Kali ("bash '$helper' provision '$WslToolRoot' '" + [string]$lock.wordlists.seclists.mode + "'")
    foreach ($line in ($wordlistResult.Output -split "`r?`n")) {
        if ($line.Trim()) { Write-Host "  $line" }
    }
}

Write-Host ""
Write-Host "Knowledge corpora ready under $ToolRoot"
$results | Format-Table -AutoSize
