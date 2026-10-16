[CmdletBinding()]
param(
    # Skip the archive-versus-tree integrity audit (it reads every pinned zip).
    [switch]$SkipIntegrity
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$LockFile = Join-Path $Root "locks\knowledge-sources.json"
$KaliDistro = if ($env:CTF_KALI_DISTRO) { $env:CTF_KALI_DISTRO } else { "ctf-kali" }
$KaliUser = if ($env:CTF_KALI_USER) { $env:CTF_KALI_USER } else { "ctf" }

$script:Failures = @()

function Add-Result {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $state = if ($Ok) { "PASS" } else { "FAIL" }
    Write-Host ("  [{0}] {1} :: {2}" -f $state, $Name, $Detail)
    if (-not $Ok) { $script:Failures += "$Name :: $Detail" }
}

function ConvertTo-WslPath {
    param([string]$WindowsPath)
    $full = [IO.Path]::GetFullPath($WindowsPath)
    $drive = $full.Substring(0, 1).ToLowerInvariant()
    return "/mnt/$drive" + $full.Substring(2).Replace("\", "/")
}

function Invoke-Kali {
    param([string]$Script)
    $output = & wsl.exe -d $KaliDistro -u $KaliUser -- bash -lc $Script 2>&1
    return @{ Exit = $LASTEXITCODE; Output = (($output | Out-String).Trim()) }
}

function Get-WslLineCount {
    param([string]$WindowsPath)
    $result = Invoke-Kali ("wc -l < '" + (ConvertTo-WslPath $WindowsPath) + "'")
    if ($result.Exit -ne 0) { return [int64]0 }
    $value = [int64]0
    if (-not [int64]::TryParse($result.Output, [ref]$value)) { return [int64]0 }
    return $value
}

if (-not (Test-Path -LiteralPath $LockFile)) { throw "knowledge lock file missing: $LockFile" }
$lock = Get-Content -LiteralPath $LockFile -Raw -Encoding UTF8 | ConvertFrom-Json
$ToolRoot = [IO.Path]::GetFullPath($lock.tool_root)
$WslToolRoot = ConvertTo-WslPath $ToolRoot

Write-Host "Verifying offline CTF corpora under $ToolRoot"

foreach ($entry in $lock.entries) {
    $target = [IO.Path]::GetFullPath((Join-Path $ToolRoot $entry.target))
    if (-not (Test-Path -LiteralPath $target)) {
        Add-Result "$($entry.name):present" $false "target missing: $target"
        continue
    }
    Add-Result "$($entry.name):present" $true $entry.target

    $files = (Get-ChildItem -LiteralPath $target -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object).Count
    Add-Result "$($entry.name):files" ($files -ge [int]$entry.verify.min_files) "files=$files min=$($entry.verify.min_files)"

    $marker = Join-Path $target $entry.verify.path
    Add-Result "$($entry.name):marker" (Test-Path -LiteralPath $marker) "path=$($entry.verify.path)"

    $stray = @(Get-ChildItem -LiteralPath $target -Recurse -Force -Directory -Filter ".git" -ErrorAction SilentlyContinue)
    Add-Result "$($entry.name):no-git" ($stray.Count -eq 0) "stray .git dirs=$($stray.Count)"

    & rg.exe --no-ignore --hidden --files-with-matches --quiet --regexp ([regex]::Escape($entry.verify.phrase)) $target | Out-Null
    $rgExit = $LASTEXITCODE
    Add-Result "$($entry.name):phrase" ($rgExit -eq 0) "phrase='$($entry.verify.phrase)' rg-exit=$rgExit"

}

if (-not $SkipIntegrity) {
    $integrity = Invoke-Kali ("bash '" + (ConvertTo-WslPath (Join-Path $PSScriptRoot "knowledge-integrity.sh")) + "' '" + (ConvertTo-WslPath $LockFile) + "'")
    $gapCounts = @{}
    $gapPaths = @{}
    foreach ($line in ($integrity.Output -split "`r?`n")) {
        if ($line -match '^GAP_([^=]+)=(.+)$') { $gapCounts[$matches[1]] = $matches[2] }
        elseif ($line -match '^MISSING_([^=]+)=(.+)$') {
            if (-not $gapPaths.ContainsKey($matches[1])) { $gapPaths[$matches[1]] = @() }
            $gapPaths[$matches[1]] += $matches[2]
        }
    }
    # Antivirus quarantine removes payload-bearing documents, so compare the
    # real gap count against what the lock records as already known.
    foreach ($entry in $lock.entries) {
        $actual = $gapCounts[$entry.name]
        if ($null -eq $actual) { Add-Result "$($entry.name):integrity" $false "audit produced no result"; continue }
        if ($actual -eq "unreadable") { Add-Result "$($entry.name):integrity" $false "archive or target unreadable"; continue }
        $known = 0
        if ($entry.known_gaps) { $known = [int]$entry.known_gaps.count }
        $actualCount = [int]$actual
        $detail = "missing=$actualCount recorded=$known"
        if ($actualCount -gt $known) {
            $detail += " unexpected: $(($gapPaths[$entry.name] -join ' | '))"
        }
        Add-Result "$($entry.name):integrity" ($actualCount -le $known) $detail
    }
}

# SecLists is an LX symlink into the distro and the env/projection probes need a
# shell that can expand its own variables, so the helper script runs inside
# ctf-kali and this side only reads its KEY=VALUE output.
$helper = ConvertTo-WslPath (Join-Path $PSScriptRoot "knowledge-wordlists.sh")
$probe = Invoke-Kali ("bash '$helper' check '$WslToolRoot'")
$metrics = @{}
foreach ($line in ($probe.Output -split "`r?`n")) {
    if ($line -match '^([A-Za-z0-9_\-\.]+)=(.*)$') { $metrics[$matches[1]] = $matches[2] }
}
if ($probe.Exit -ne 0 -and $metrics.Count -eq 0) {
    Add-Result "wordlists:probe" $false "helper produced no metrics: $($probe.Output)"
}

Add-Result "seclists:present" ($metrics["SECLISTS"] -and $metrics["SECLISTS"] -ne "missing") "$($metrics["SECLISTS"])"
Add-Result "seclists:readme" ($metrics["SECLISTS_README"] -eq "ok") "README.md readable from ctf-kali"

$metricMap = @{}
foreach ($check in $lock.wordlists.seclists.checks) { $metricMap[[string]$check.metric] = $check }
foreach ($key in @("RAFT_LINES", "XATO_LINES")) {
    $value = [int64]0
    [void][int64]::TryParse([string]$metrics[$key], [ref]$value)
    $check = $metricMap[$key]
    if ($null -eq $check) { Add-Result "seclists:$key" $false "no lock entry for metric $key"; continue }
    Add-Result "seclists:$($check.name)" ($value -ge [int64]$check.min_lines) "lines=$value min=$($check.min_lines)"
}

$rockyouLines = [int64]0
[void][int64]::TryParse([string]$metrics["ROCKYOU_LINES"], [ref]$rockyouLines)
Add-Result "rockyou:lines" ($rockyouLines -ge [int64]$lock.wordlists.rockyou.min_lines) "lines=$rockyouLines min=$($lock.wordlists.rockyou.min_lines)"

$templateCount = [int64]0
[void][int64]::TryParse([string]$metrics["NUCLEI_YAML"], [ref]$templateCount)
Add-Result "nuclei:templates" ($templateCount -gt 5000) "yaml templates=$templateCount min=5000"

foreach ($name in @("MUTEKI_OFFLINE_KNOWLEDGE_DIR", "MUTEKI_POC_DIR", "MUTEKI_SECLISTS_DIR", "MUTEKI_WORDLIST_DIR", "NUCLEI_TEMPLATES")) {
    $state = [string]$metrics["ENV_$name"]
    Add-Result "env:$name" ($state -like "ok:*") "$state"
}
$projectionFailures = @()
foreach ($logical in @("knowledge", "pocs", "wordlists", "nuclei-templates")) {
    $state = [string]$metrics["PROJECTION_$logical"]
    if ($state -ne "ok") { $projectionFailures += $logical }
}
Add-Result "toolbox:projection-inputs" ($projectionFailures.Count -eq 0) "non-empty: $((@('knowledge','pocs','wordlists','nuclei-templates') | Where-Object { $projectionFailures -notcontains $_ }) -join ', ')"

Write-Host ""
if ($script:Failures.Count -eq 0) {
    Write-Host "verify-knowledge: OK"
    exit 0
}
Write-Host "verify-knowledge: $($script:Failures.Count) failure(s)"
foreach ($failure in $script:Failures) { Write-Host "  - $failure" }
exit 1
