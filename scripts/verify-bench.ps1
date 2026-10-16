<#
    Benchmark self-check: run this before trusting any agentic measurement.

    Two failure modes once made a whole measurement meaningless, and both were
    only noticed after the agent time had been spent:

      * a challenge shipped its flag in plain sight - forensics-http-pcap put
        the flag in an HTTP request URI inside the capture, so the "solve"
        measured the harness, not the agent;
      * a challenge could not be solved with the shipped files at all inside
        the harness - the agent sandbox cannot execute a Linux ELF, so
        pwn-ret2win had no legitimate route to its flag and the agent went
        looking in the expected-flag manifest instead.

    This script fails loudly on both, and it proves the third thing a
    measurement depends on: that every challenge can actually be solved, by
    running each one's reference solver in ctf-kali and comparing the result
    with the manifest.
#>
[CmdletBinding()]
param(
    [string]$RunId = "verify-bench",
    # Keep the prepared work directories for inspection.
    [switch]$KeepRunDirectories
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$SuiteRoot = if ($env:CTF_SUITE_ROOT) { $env:CTF_SUITE_ROOT } else { "D:\codex\ctf-suite" }
$Distro = if ($env:CTF_KALI_DISTRO) { $env:CTF_KALI_DISTRO } else { "ctf-kali" }
$KaliUser = if ($env:CTF_KALI_USER) { $env:CTF_KALI_USER } else { "ctf" }
$WslExe = Join-Path $env:SystemRoot "System32\wsl.exe"

function ConvertTo-WslPath {
    param([string]$WindowsPath)
    $full = [IO.Path]::GetFullPath($WindowsPath)
    $drive = $full.Substring(0, 1).ToLowerInvariant()
    return "/mnt/$drive" + $full.Substring(2).Replace("\", "/")
}

$failures = New-Object System.Collections.Generic.List[string]

# --- 1. every challenge is solvable, and solves to the manifest's flag ------
Write-Host "[1/2] reference solve in ctf-kali"
$reference = ConvertTo-WslPath (Join-Path $PSScriptRoot "verify-bench-reference.sh")
& $WslExe -d $Distro -u $KaliUser -- bash $reference
if ($LASTEXITCODE -ne 0) {
    $failures.Add("reference solve failed (see the report above)")
}

# --- 2. nothing shipped to the agent carries the flag in the clear ---------
Write-Host ""
Write-Host "[2/2] leak scan on freshly prepared work directories"
$prepareRun = "$RunId-prep"
& pwsh -NoProfile -File (Join-Path $PSScriptRoot "bench-agentic.ps1") `
    -Set local -RunId $prepareRun | Out-Null
$reportPath = Join-Path $Root "bench\$prepareRun\report.json"
if (-not (Test-Path -LiteralPath $reportPath)) {
    $failures.Add("the prepare run wrote no report at $reportPath")
} else {
    $report = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($result in $report.results) {
        if (@($result.leaked).Count -gt 0) {
            Write-Host ("    LEAK  {0}: {1}" -f $result.id, (@($result.leaked) -join ", ")) -ForegroundColor Red
            $failures.Add("$($result.id) ships its flag in the clear: $(@($result.leaked) -join ', ')")
        } else {
            Write-Host ("    clean {0}" -f $result.id)
        }
    }
    if ($report.results.Count -eq 0) {
        $failures.Add("the prepare run scored no tasks at all")
    }
    foreach ($entry in @($report.skipped)) {
        Write-Host ("    skip  {0} (declared unmeasurable)" -f $entry.id) -ForegroundColor DarkGray
    }
}

if (-not $KeepRunDirectories) {
    $prepared = Join-Path $Root "bench\$prepareRun"
    if (Test-Path -LiteralPath $prepared) {
        Remove-Item -LiteralPath $prepared -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host "verify-bench: FAILED" -ForegroundColor Red
    foreach ($failure in $failures) { Write-Host "  - $failure" -ForegroundColor Red }
    exit 1
}
Write-Host "verify-bench: OK - every challenge is solvable and none leaks its flag" -ForegroundColor Green
exit 0
