<#
.SYNOPSIS
  Kestrel agent smoke test for a real Windows host (CI windows job, or a lab VM).

.DESCRIPTION
  Self-contained, no server needed:
    1. `kestrel-agent.exe --version` works and prints a version.
    2. Starts `kestrel-agent.exe sensors-test --seconds N` (hidden subcommand: starts only
       WindowsPlatform::start_sensors - ETW + event-log sessions - and prints JSON event
       counts by kind when done).
    3. While it runs, launches `cmd /c echo hi` and `Resolve-DnsName example.com`
       (DNS-Client service path, so the DNS-Client ETW provider sees it; nslookup would not).
    4. Asserts >= 1 process_start and >= 1 dns_query were observed, and prints sensor health.
    5. State-directory hardening (security review H4): the sensors-test state dir is
       SYSTEM-owned; a pre-created directory that standard users can write to is moved
       aside (and its planted agent.toml is not used) the next time the agent touches it.

  Requires an elevated shell (kernel/ETW sessions). GitHub-hosted Windows runners are elevated.
  If the KestrelAgent service is running on this machine its ETW sessions have the same
  names; stop it first (sc.exe stop KestrelAgent) or the sensors-test may fail to start.

.PARAMETER AgentExe
  Path to kestrel-agent.exe (default: target\release\kestrel-agent.exe).

.PARAMETER Seconds
  How long the sensors run (default 25).

.EXAMPLE
  ./scripts/windows-smoke.ps1
  ./scripts/windows-smoke.ps1 -AgentExe 'C:\Program Files\Kestrel\kestrel-agent.exe' -Seconds 40
#>
[CmdletBinding()]
param(
    [string]$AgentExe = (Join-Path $PSScriptRoot '..\target\release\kestrel-agent.exe'),
    [ValidateRange(10, 600)][int]$Seconds = 25
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$failures = [System.Collections.Generic.List[string]]::new()
function Pass([string]$m) { Write-Host "  PASS $m" -ForegroundColor Green }
function Fail([string]$m) { Write-Host "  FAIL $m" -ForegroundColor Red; $failures.Add($m) }
function Warn([string]$m) { Write-Host "  WARN $m" -ForegroundColor Yellow }

$AgentExe = (Resolve-Path -LiteralPath $AgentExe -ErrorAction Stop).Path
Write-Host "[smoke] agent: $AgentExe"

# --- 1. --version ------------------------------------------------------------
$ver = (& $AgentExe --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -eq 0 -and $ver -match '^kestrel-agent \d+\.\d+\.\d+') { Pass "--version: $ver" }
else { Fail "--version returned exit $LASTEXITCODE / '$ver'" }

# --- 2. elevation --------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'not running elevated: ETW sensors need Administrator (or SYSTEM)'
    Write-Host 'RESULT: FAIL'
    exit 1
}

$svc = Get-Service -Name KestrelAgent -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Warn 'KestrelAgent service is running; its ETW sessions share names with sensors-test'
}

# --- 3. sensors-test ---------------------------------------------------------
$work = Join-Path ([IO.Path]::GetTempPath()) ("kestrel-smoke-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$state = Join-Path $work 'state'
$outFile = Join-Path $work 'sensors.json'
$errFile = Join-Path $work 'sensors.log'
$proc = $null
try {
    $agentArgs = "--state-dir `"$state`" sensors-test --seconds $Seconds"
    $proc = Start-Process -FilePath $AgentExe -ArgumentList $agentArgs -NoNewWindow -PassThru `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $null = $proc.Handle  # cache the handle so ExitCode is available later

    # Wait until the sensors report ready (or the process dies).
    $readyBy = (Get-Date).AddSeconds(60)
    $ready = $false
    while ((Get-Date) -lt $readyBy) {
        if ((Test-Path $errFile) -and (Select-String -Path $errFile -Pattern 'KESTREL-SENSORS-READY' -Quiet)) { $ready = $true; break }
        if ($proc.HasExited) { break }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        Fail "sensors did not start (exit: $(if ($proc.HasExited) { $proc.ExitCode } else { 'still running' }))"
        if (Test-Path $errFile) { Get-Content $errFile -Tail 40 | ForEach-Object { Write-Host "    $_" } }
        throw 'sensors-test did not become ready'
    }
    Pass 'sensors started'
    Start-Sleep -Seconds 3   # let ETW sessions settle

    # --- 4. generate activity (a few rounds, in case the first is missed) -------
    $nonce = [guid]::NewGuid().ToString('N').Substring(0, 10)
    for ($i = 0; $i -lt 3; $i++) {
        & cmd.exe /c echo hi | Out-Null
        & powershell.exe -NoProfile -NonInteractive -Command "Clear-DnsClientCache; Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null; Resolve-DnsName kestrel-smoke-$nonce-$i.example.com -DnsOnly -ErrorAction SilentlyContinue | Out-Null" | Out-Null
        Start-Sleep -Seconds 2
    }

    if (-not $proc.WaitForExit(($Seconds + 60) * 1000)) {
        Fail 'sensors-test did not exit in time'
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        throw 'timeout'
    }
    if ($proc.ExitCode -ne 0) {
        Fail "sensors-test exited with $($proc.ExitCode)"
        Get-Content $errFile -Tail 40 | ForEach-Object { Write-Host "    $_" }
        throw 'sensors-test failed'
    }

    $r = Get-Content -Raw $outFile | ConvertFrom-Json
    Write-Host '[smoke] sensors-test output:'
    Get-Content $outFile | ForEach-Object { Write-Host "    $_" }

    $ps = [int64]$r.counts.process_start
    $dns = [int64]$r.counts.dns_query
    if ($ps -ge 1) { Pass "process_start events: $ps" } else { Fail 'no process_start events observed' }
    if ($dns -ge 1) { Pass "dns_query events: $dns" } else { Fail 'no dns_query events observed' }
    if ($r.process_images -contains 'cmd.exe') { Pass 'saw cmd.exe start' } else { Warn 'cmd.exe start not among sampled process images' }
    if (@($r.dns_qnames | Where-Object { $_ -like '*example.com' }).Count -ge 1) { Pass 'saw example.com lookup' }
    else { Warn 'example.com lookup not among sampled DNS names' }
    if ($r.stats.etw_ok) { Pass 'ETW sessions healthy' } else { Fail 'stats.etw_ok = false' }
    if ([int64]$r.stats.events_lost -gt 0) { Warn "ETW reported $($r.stats.events_lost) events lost" }

    # --- 5. state directory hardening (H4) -------------------------------------
    $owner = (Get-Acl -LiteralPath $state).Owner
    if ($owner -match 'SYSTEM') { Pass "state dir owner: $owner" } else { Fail "state dir owner is $owner (expected SYSTEM)" }
    $insecure = Join-Path $work 'insecure-state'
    New-Item -ItemType Directory -Path $insecure | Out-Null
    Set-Content -LiteralPath (Join-Path $insecure 'agent.toml') -Value 'server = "attacker:8443"'
    & icacls.exe $insecure /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null   # BUILTIN\Users: modify
    & $AgentExe --state-dir $insecure enroll --token smoke-not-a-token 2>&1 | Out-Null   # fails (not installed) after securing the dir
    $aside = @(Get-ChildItem -LiteralPath $work -Directory -Filter 'insecure-state.untrusted-*')
    if ($aside.Count -ge 1) { Pass "untrusted pre-created state dir moved aside ($($aside[0].Name))" }
    else { Fail 'untrusted pre-created state dir was not moved aside' }
    if (Test-Path -LiteralPath (Join-Path $insecure 'agent.toml')) { Fail 'planted agent.toml still present in the state dir' }
    else { Pass 'planted agent.toml not carried over' }
    $owner2 = (Get-Acl -LiteralPath $insecure).Owner
    if ($owner2 -match 'SYSTEM') { Pass "re-created state dir owner: $owner2" } else { Fail "re-created state dir owner is $owner2" }
}
catch {
    if ($failures.Count -eq 0) { Fail "$_" }
}
finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force -LiteralPath $work -ErrorAction SilentlyContinue
}

Write-Host ''
if ($failures.Count -eq 0) { Write-Host 'RESULT: PASS' -ForegroundColor Green; exit 0 }
Write-Host "RESULT: FAIL ($($failures.Count))" -ForegroundColor Red
$failures | ForEach-Object { Write-Host "  - $_" }
exit 1
