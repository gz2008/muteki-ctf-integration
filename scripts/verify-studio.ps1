[CmdletBinding()]
param(
    [int]$Port = 8877,
    [string]$Python = $env:CTF_LOCAL_PYTHON
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Token = "studio-verify-$([Guid]::NewGuid().ToString('N').Substring(0,12))"
$WorkRoot = if (Test-Path "D:\codex\.tmp") { "D:\codex\.tmp" } else { $env:TEMP }
$Work = Join-Path $WorkRoot ("ctf-studio-verify-" + [Guid]::NewGuid().ToString("N"))
$Runs = Join-Path $Work "runs"
$OutLog = Join-Path $Work "server.out.log"
$ErrLog = Join-Path $Work "server.err.log"
$Base = "http://127.0.0.1:$Port"
$Headers = @{ "X-Studio-Token" = $Token }
New-Item -ItemType Directory -Force -Path $Runs | Out-Null

if (-not $Python) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source }
}
if (-not $Python) {
    throw "python not found; set CTF_LOCAL_PYTHON"
}

function Wait-Status {
    param([int]$Seconds = 30)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            return Invoke-RestMethod -Uri "$Base/api/status" -Headers $Headers -TimeoutSec 5
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    throw "studio did not become ready"
}

function New-Run {
    param([string]$Title, [string]$Description)
    $body = @{
        title = $Title
        description = $Description
        mode = "local"
        category = "auto"
        flag_format = "flag{...}"
        workers = 1
        race_seconds = 60
        total_seconds = 0
        web_tools = $false
        offline = $true
    } | ConvertTo-Json
    return Invoke-RestMethod -Method Post -Uri "$Base/api/runs" -Headers $Headers -ContentType "application/json" -Body $body
}

function Upload-File {
    param([string]$RunId, [string]$Path)
    $name = [IO.Path]::GetFileName($Path)
    Invoke-WebRequest -Method Put -Uri "$Base/api/runs/$RunId/files?name=$([Uri]::EscapeDataString($name))" -Headers $Headers -InFile $Path -TimeoutSec 60 | Out-Null
}

function Dispatch-Run {
    param([string]$RunId)
    $body = @{ mode = "local" } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Uri "$Base/api/runs/$RunId/dispatch" -Headers $Headers -ContentType "application/json" -Body $body | Out-Null
}

function Wait-Run {
    param([string]$RunId, [int]$Seconds = 90)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $run = Invoke-RestMethod -Uri "$Base/api/runs/$RunId" -Headers $Headers
        if ($run.status -notin @("created", "queued", "running")) { return $run }
        Start-Sleep -Seconds 1
    }
    throw "run $RunId did not finish"
}

$proc = $null
$failures = @()
try {
    $proc = Start-Process -FilePath $Python -ArgumentList @(
        (Join-Path $Root "studio\server.py"),
        "--port", $Port,
        "--token", $Token,
        "--runs", $Runs
    ) -WindowStyle Hidden -PassThru -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog

    $status = Wait-Status
    if (-not $status.corpus_ready) {
        Write-Host "WARN corpus is not provisioned; run scripts\fetch-knowledge.ps1 for full search" -ForegroundColor Yellow
    }
    if (-not $status.wsl.ok) {
        Write-Host "WARN ctf-kali is not reachable; console verification will use Windows" -ForegroundColor Yellow
    }
    Write-Host "PASS status: corpus=$($status.corpus_ready) wsl=$($status.wsl.ok) codex=$($status.codex.ok)"

    # Auth: no token must be rejected; foreign Origin must be rejected.
    try {
        Invoke-RestMethod -Uri "$Base/api/status" -TimeoutSec 5 | Out-Null
        throw "unauthenticated status unexpectedly succeeded"
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 401) { throw $_ }
        Write-Host "PASS auth: missing token -> 401"
    }
    try {
        $badHeaders = @{ "X-Studio-Token" = $Token; "Origin" = "http://evil.example" }
        Invoke-RestMethod -Method Post -Uri "$Base/api/runs" -Headers $badHeaders -ContentType "application/json" -Body "{}" -TimeoutSec 5 | Out-Null
        throw "foreign origin unexpectedly succeeded"
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw $_ }
        Write-Host "PASS auth: foreign origin -> 403"
    }

    $challenge = Join-Path $Work "challenge.txt"
    [IO.File]::WriteAllText($challenge, "ZmxhZ3tzdHVkaW9fc21va2V9", (New-Object Text.UTF8Encoding($false)))
    $created = New-Run -Title "studio verify" -Description "A base64 text file contains a flag. Decode it."
    $runId = $created.run.id
    Upload-File -RunId $runId -Path $challenge
    Dispatch-Run -RunId $runId
    $run = Wait-Run -RunId $runId
    if ($run.facts.Count -lt 1) { throw "run produced no facts" }
    if ($run.actions.Count -lt 2) { throw "run produced too few actions" }
    Write-Host "PASS local run: facts=$($run.facts.Count) actions=$($run.actions.Count)"

    if ($status.wsl.ok) {
        $consoleCommand = "base64 -d challenge.txt"
        $consoleShell = "wsl"
    } else {
        $consoleCommand = "python -c `"import base64;print(base64.b64decode(open('challenge.txt').read()).decode())`""
        $consoleShell = "windows"
    }
    $body = @{ command = $consoleCommand; shell = $consoleShell } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Uri "$Base/api/runs/$runId/command" -Headers $Headers -ContentType "application/json" -Body $body | Out-Null
    Start-Sleep -Seconds 6
    $run = Invoke-RestMethod -Uri "$Base/api/runs/$runId" -Headers $Headers
    $verified = @($run.flags | Where-Object { $_.status -eq "verified" -and $_.value -eq "flag{studio_smoke}" })
    if ($verified.Count -ne 1) { throw "console flag was not verified" }
    Write-Host "PASS console: flag{studio_smoke} verified from real output"

    # Candidate review lifecycle: reject a decoy and confirm it never becomes verified.
    $decoy = Join-Path $Work "decoy.txt"
    [IO.File]::WriteAllText($decoy, "decoy flag{review_me}", (New-Object Text.UTF8Encoding($false)))
    $created2 = New-Run -Title "review verify" -Description "Review a decoy candidate."
    $run2 = $created2.run.id
    Upload-File -RunId $run2 -Path $decoy
    Dispatch-Run -RunId $run2
    $run2data = Wait-Run -RunId $run2
    $candidate = @($run2data.flags | Where-Object { $_.value -eq "flag{review_me}" })
    if ($candidate.Count -ne 1) { throw "decoy candidate was not recorded" }
    $review = @{ value = "flag{review_me}"; review = "reject" } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Uri "$Base/api/runs/$run2/flag" -Headers $Headers -ContentType "application/json" -Body $review | Out-Null
    $run2data = Invoke-RestMethod -Uri "$Base/api/runs/$run2" -Headers $Headers
    $reviewed = @($run2data.flags | Where-Object { $_.value -eq "flag{review_me}" -and $_.status -eq "rejected" })
    if ($reviewed.Count -ne 1) { throw "reject did not persist" }
    if ($run2data.solved) { throw "rejected candidate incorrectly marked run solved" }
    Write-Host "PASS review: candidate rejected, run not solved"

    if ($status.corpus_ready) {
        $searchBody = @{ query = "base64"; mode = "corpus"; category = "misc"; n = 5 } | ConvertTo-Json
        $search = Invoke-RestMethod -Method Post -Uri "$Base/api/search" -Headers $Headers -ContentType "application/json" -Body $searchBody -TimeoutSec 90
        if (-not $search.ok) { throw "corpus search failed" }
        Write-Host "PASS search: $($search.items.Count) corpus hits"
    } else {
        Write-Host "SKIP search: corpus not provisioned"
    }

    $js = (Invoke-WebRequest -Uri "$Base/static/app.js" -TimeoutSec 10).Content
    $css = (Invoke-WebRequest -Uri "$Base/static/styles.css" -TimeoutSec 10).Content
    if ($js -notmatch "magicTransform" -or $css -notmatch "toolbox") { throw "transform workbench assets missing" }
    Write-Host "PASS assets: transform workbench present"
} catch {
    $failures += $_.Exception.Message
} finally {
    if ($proc -and -not $proc.HasExited) {
        & taskkill.exe /PID $proc.Id /T /F 2>$null | Out-Null
    }
}

if ($failures.Count) {
    Write-Host "FAIL: $($failures -join '; ')" -ForegroundColor Red
    if (Test-Path $ErrLog) { Get-Content $ErrLog | Select-Object -Last 40 }
    exit 1
}
Write-Host "STUDIO VERIFY OK ($Work)" -ForegroundColor Green
exit 0
