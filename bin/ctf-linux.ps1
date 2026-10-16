# Run a command inside the ctf-kali distribution with a challenge directory as
# the working directory.
#
# Why this exists: the agent sandbox cannot execute a Linux ELF (wsl.exe fails
# with Wsl/Service/E_ACCESSDENIED inside it) and the Windows host has no Linux
# ABI, so a pwn or reverse task can be analysed but never actually run. From a
# normal session the distribution is reachable; this entry makes that one call
# instead of a hand-built "wsl.exe ... bash -c" line plus Windows-to-WSL path
# conversion.
#
# Usage:
#   ctf-linux.cmd <directory> <command>
#   ctf-linux.cmd D:\path\to\chall "checksec ./chall"
#   ctf-linux.cmd . "python3 solve.py"
#
# Keep the command free of nested quotes. Measured: `python3 -c "print(1)"`
# reaches bash as `python3 -c print(1)` because cmd.exe passes %* through
# without escaping, and the call then fails on the shell's own syntax. That is a
# Windows command-line limit, not something this wrapper can repair - so put
# anything longer than a word or two, or anything containing a quote, in a .py
# or .sh file next to the challenge and run that instead:
#   ctf-linux.cmd . "python3 solve.py"
#   ctf-linux.cmd . "bash exploit.sh"
#
# The command runs with /opt/ctf/bin and the pinned venv on PATH, so python3
# already carries pwntools, z3 and scapy.
#
# Deliberately a simple script with no param block: PowerShell then leaves
# options inside the command ("-c", "--flag") untouched in $args.
[string[]]$Rest = @($args)
$ErrorActionPreference = "Stop"
$Distro = if ($env:CTF_KALI_DISTRO) { $env:CTF_KALI_DISTRO } else { "ctf-kali" }
$KaliUser = if ($env:CTF_KALI_USER) { $env:CTF_KALI_USER } else { "ctf" }
$WslExe = Join-Path $env:SystemRoot "System32\wsl.exe"

# The command is written to a temporary script and executed by path rather than
# handed to "bash -c". Passing it inline fails under Windows PowerShell 5.1:
# that host re-quotes arguments for the native process, the embedded double
# quotes come out escaped, bash parses the "safe" PATH assignment as several
# statements and the whole call dies silently with exit code 0. pwsh 7 escapes
# differently, so the same line works there - which is exactly the kind of
# difference that turns into a mysterious "it does nothing" report.
function ConvertTo-WslPath {
    param([string]$WindowsPath)
    $full = [IO.Path]::GetFullPath($WindowsPath)
    $drive = $full.Substring(0, 1).ToLowerInvariant()
    return "/mnt/$drive" + $full.Substring(2).Replace("\", "/")
}

if ($Rest.Count -lt 2) {
    Write-Host "usage: ctf-linux <directory> <command>"
    Write-Host '  ctf-linux.cmd D:\path\to\chall "checksec ./chall"'
    Write-Host '  ctf-linux.cmd . "python3 solve.py"'
    Write-Host ""
    Write-Host "Runs <command> inside $Distro with <directory> as the working directory."
    Write-Host "python3 there is /opt/ctf/venvs/core/bin/python (pwntools, z3, scapy)."
    Write-Host ""
    Write-Host "Keep <command> free of nested quotes; put longer work in a .py or .sh"
    Write-Host "file and run that (ctf-linux.cmd . ""python3 solve.py"")."
    exit 2
}

$directory = $Rest[0]
$command = ($Rest[1..($Rest.Count - 1)] -join ' ')

if ($directory -like '/*') {
    $wslDir = $directory
} else {
    if (-not (Test-Path -LiteralPath $directory)) {
        Write-Host "no such directory: $directory"
        exit 2
    }
    $wslDir = ConvertTo-WslPath $directory
}

$prefix = 'export PATH="/opt/ctf/bin:/opt/ctf/venvs/core/bin:$PATH"' + "`n" +
          'cd "' + $wslDir + '" || exit 3' + "`n"
$tempScript = Join-Path $env:TEMP ("ctf-linux-" + [Guid]::NewGuid().ToString("N") + ".sh")
# LF line endings and no BOM: bash rejects a script that starts with one.
[IO.File]::WriteAllText($tempScript, $prefix + $command + "`n", (New-Object Text.UTF8Encoding($false)))
try {
    & $WslExe -d $Distro -u $KaliUser -- bash (ConvertTo-WslPath $tempScript)
    $code = $LASTEXITCODE
} finally {
    # Only ever remove the scratch file this script created.
    if (Test-Path -LiteralPath $tempScript) {
        Remove-Item -LiteralPath $tempScript -Force -ErrorAction SilentlyContinue
    }
}
exit $code
