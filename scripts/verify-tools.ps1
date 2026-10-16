[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$KaliDistro = if ($env:CTF_KALI_DISTRO) { $env:CTF_KALI_DISTRO } else { "ctf-kali" }
$KaliUser = if ($env:CTF_KALI_USER) { $env:CTF_KALI_USER } else { "ctf" }
$ToolRootWin = if ($env:CTF_TOOL_ROOT) { $env:CTF_TOOL_ROOT } else { Join-Path $Root "muteki-tool-root" }
$SuiteRoot = if ($env:CTF_SUITE_ROOT) { $env:CTF_SUITE_ROOT } else { "D:\codex\ctf-suite" }
$BinRoot = Join-Path $Root "bin"

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

$script:Failures = @()
function Add-Result {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    Write-Host ("  [{0}] {1} :: {2}" -f $(if ($Ok) { "PASS" } else { "FAIL" }), $Name, $Detail)
    if (-not $Ok) { $script:Failures += "$Name :: $Detail" }
}

Write-Host "Verifying pinned CTF tools and glibc data"

$probe = Invoke-Kali ("bash '" + (ConvertTo-WslPath (Join-Path $PSScriptRoot "provision-tool-gaps.sh")) + "' check")
if ($probe.Exit -ne 0 -and -not $probe.Output) {
    Add-Result "tools:probe" $false "provision helper produced no output"
}
$lines = $probe.Output -split "`r?`n" | Where-Object { $_.Trim() }
foreach ($line in $lines) {
    if ($line -match '^(?<name>[A-Za-z0-9_.\-]+)=(?<state>.*)$') {
        $name = $matches['name']
        $state = $matches['state']
        $ok = $state -eq "ok"
        Add-Result $name $ok $state
    } else {
        Write-Host "  [INFO] $line"
    }
}

$expectedLaunchers = @("ropper", "pwninit", "glibc-aio", "evtx_dump", "stegoveritas", "stegsolve",
                       "ysoserial", "marshalsec", "jndi-exploit", "ctf-corpus", "ctf-index",
                       "ctf-xor",
                       "ctf-hashpump",
                       "ctf-triage", "ctf-net",
                       "ctf-repair",
                       "diec", "kerbrute", "openstego", "pypykatz", "vmlinux-to-elf",
                       "forge", "cast", "anvil", "fchisel", "solar", "chainsaw", "hayabusa",
                       "pycdc", "pycdas", "jadx", "apktool", "d2j-dex2jar", "aapt", "apksigner",
                       "adb", "wpscan", "ncat", "chisel", "dotnet", "ilspycmd",
                       "uncompyle6", "decompyle3", "pyinstaller", "semgrep", "slither", "vyper",
                       "pacu", "scout", "prowler", "cloudsplaining", "cloudfox", "certipy",
                       "vol3", "bkcrack", "cfr", "tesseract", "wasm2wat", "multimon-ng",
                       "ecm", "nxc", "smbmap", "sqlite3",
                       "pyocd", "unblob", "gqrx", "openocd", "pulseview", "sigrok-cli",
                       "rtl_433", "gnuradio-config-info")
foreach ($launcher in $expectedLaunchers) {
    $wrapper = Join-Path $ToolRootWin "bin\$launcher"
    Add-Result "toolbox:$launcher" (Test-Path -LiteralPath $wrapper) "projected wrapper"
}

Write-Host ""
Write-Host "Verifying Windows command entries"
# Existence is not enough. These entries used to route their arguments through
# "powershell.exe -File <name>.ps1", which parsed the python-style options
# before the analyser saw them: "ctf-net --out carved" died with "parameter
# name 'out' is ambiguous" and "ctf-repair --write fixed.bin" with "cannot find
# parameter '-write'". Call each documented form and require exit code 0.
$expectedEntries = @("ctf-triage", "ctf-net", "ctf-repair", "ctf-corpus", "ctf-index",
                     "ctf-xor", "ctf-hashpump", "ctf-linux", "muteki-ctf")
foreach ($entry in $expectedEntries) {
    Add-Result "entry:$entry.cmd" (Test-Path -LiteralPath (Join-Path $BinRoot "$entry.cmd")) "present"
}

$fixtureDir = Join-Path $env:TEMP ("ctf-verify-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $fixtureDir -Force | Out-Null
try {
    # ctf-triage exits 2 on a directory with nothing to look at, so give it a file.
    Set-Content -LiteralPath (Join-Path $fixtureDir "sample.txt") -Encoding UTF8 `
        -Value "flag{verify_tools_probe}"
    & (Join-Path $BinRoot "ctf-triage.cmd") $fixtureDir "--json" 2>&1 | Out-Null
    Add-Result "entry:ctf-triage.cmd --json" ($LASTEXITCODE -eq 0) "python-style option reaches the analyser"

    # ctf-linux is the only route to run a Linux ELF from a normal session; if it
    # breaks, pwn and reverse tasks silently become read-only exercises.
    $linuxOutput = (& (Join-Path $BinRoot "ctf-linux.cmd") $fixtureDir "echo ctf-linux-reachable" 2>&1 | Out-String)
    Add-Result "entry:ctf-linux.cmd" ($LASTEXITCODE -eq 0 -and $linuxOutput -match "ctf-linux-reachable") `
        "runs a command inside ctf-kali with the pinned PATH"

    # A real capture from the local set exercises reassembly and carving at once.
    $pcap = Join-Path $SuiteRoot "benchmarks\local\forensics-http-pcap\capture.pcap"
    if (Test-Path -LiteralPath $pcap) {
        $carved = Join-Path $fixtureDir "carved"
        & (Join-Path $BinRoot "ctf-net.cmd") $pcap "--out" $carved 2>&1 | Out-Null
        Add-Result "entry:ctf-net.cmd --out" ($LASTEXITCODE -eq 0) "python-style option reaches the analyser"
        $carvedFiles = @(Get-ChildItem -LiteralPath $carved -File -ErrorAction SilentlyContinue)
        Add-Result "entry:ctf-net.cmd carve" ($carvedFiles.Count -gt 0) "carved $($carvedFiles.Count) object(s) from a real capture"
    } else {
        Add-Result "entry:ctf-net.cmd --out" $false "no fixture capture at $pcap"
    }
} finally {
    # Only ever remove the scratch directory this block created.
    $resolved = [IO.Path]::GetFullPath($fixtureDir)
    $tempRoot = [IO.Path]::GetFullPath($env:TEMP)
    if ($resolved.StartsWith($tempRoot) -and (Test-Path -LiteralPath $resolved)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
if ($script:Failures.Count -eq 0) {
    Write-Host "verify-tools: OK"
    exit 0
}
Write-Host "verify-tools: $($script:Failures.Count) failure(s)"
foreach ($failure in $script:Failures) { Write-Host "  - $failure" }
exit 1
