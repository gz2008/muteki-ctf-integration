[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("help", "doctor", "validate", "shell", "exec", "new", "scope", "journal", "env", "status", "run-web")]
    [string]$Command = "help",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$WslExe = Join-Path $env:SystemRoot "System32\wsl.exe"
$Distro = if ($env:CTF_KALI_DISTRO) { $env:CTF_KALI_DISTRO } else { "ctf-kali" }
$SuiteRoot = if ($env:CTF_SUITE_ROOT) { $env:CTF_SUITE_ROOT } else { "D:\codex\ctf-suite" }
$MutekiRoot = if ($env:MUTEKI_ROOT) { $env:MUTEKI_ROOT } else { "D:\codex\output\muteki" }
$ToolRoot = Join-Path $Root "muteki-tool-root"

function Invoke-Kali([string]$Script) {
    & $WslExe -d $Distro -u ctf -- bash -lc $Script
    if (-not $?) { throw "ctf-kali command failed" }
}

function Show-Help {
    @"
Muteki CTF integration

  .\muteki-ctf.ps1 doctor          Check the ctf-kali CTF toolchain
  .\muteki-ctf.ps1 validate        Validate suite reports and locked inputs
  .\muteki-ctf.ps1 shell           Open ctf-kali
  .\muteki-ctf.ps1 exec CMD ...    Run one command inside ctf-kali
  .\muteki-ctf.ps1 new -Category web -Name demo -Target http://127.0.0.1:8000
  .\muteki-ctf.ps1 scope -Scope FILE -Host 127.0.0.1 -Port 8000
  .\muteki-ctf.ps1 journal -Path D:\codex\ctf-suite\workspace\web\demo
  .\muteki-ctf.ps1 env             Print environment values
  .\muteki-ctf.ps1 status          Show local paths
  .\muteki-ctf.ps1 run-web         Start Muteki with this tool root
"@ | Write-Host
}

switch ($Command) {
    "help" { Show-Help }
    "doctor" { Invoke-Kali "/opt/ctf/bin/ctf-doctor $($Rest -join ' ')" }
    "validate" { Invoke-Kali "/opt/ctf/bin/ctf-validate $($Rest -join ' ')" }
    "shell" { & $WslExe -d $Distro -u ctf --cd "~" }
    "exec" {
        if (-not $Rest -or $Rest.Count -lt 1) { throw "exec requires a command" }
        $cmd = $Rest[0]
        $args = @($Rest | Select-Object -Skip 1)
        & $WslExe -d $Distro -u ctf -- bash -lc ("exec " + $cmd + " " + (($args | ForEach-Object { "'" + $_.Replace("'", "'\''") + "'" }) -join " "))
        if (-not $?) { throw "ctf-kali command failed" }
    }
    "new" { Invoke-Kali "/opt/ctf/bin/ctf-new $($Rest -join ' ')" }
    "scope" { Invoke-Kali "/opt/ctf/bin/ctf-scope $($Rest -join ' ')" }
    "journal" { Invoke-Kali "/opt/ctf/bin/ctf-journal $($Rest -join ' ')" }
    "env" {
        "`$env:MUTEKI_LOCAL_WORKER_ROOT='$ToolRoot'"
        "`$env:MUTEKI_CTF_BRIDGE_ROOT='$Root'"
        "`$env:CTF_SUITE_ROOT='$SuiteRoot'"
        "`$env:MUTEKI_ROOT='$MutekiRoot'"
    }
    "status" {
        "integration=$Root"
        "distribution=$Distro"
        "ctf_suite=$SuiteRoot"
        "muteki_source=$MutekiRoot"
        "tool_root=$ToolRoot"
    }
    "run-web" {
        $env:MUTEKI_LOCAL_WORKER_ROOT = $ToolRoot
        $env:MUTEKI_CTF_BRIDGE_ROOT = $Root
        Push-Location $MutekiRoot
        try {
            & $WslExe -d $Distro -u ctf -- bash -lc "cd /mnt/d/codex/output/muteki && MUTEKI_LOCAL_WORKER_ROOT=/mnt/d/codex/output/muteki-ctf-integration/muteki-tool-root ./run.sh web"
        } finally { Pop-Location }
    }
}
