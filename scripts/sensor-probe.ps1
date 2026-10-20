<#
.SYNOPSIS
  Read-only probe of Kestrel's real ETW sensors (known Windows-layer risks 1-7 in docs/HANDOFF.md).

.DESCRIPTION
  Runs `kestrel-agent sensors-test --detect --events-out` (sensors + engine with every rule forced
  to Audit; no response action is ever executed) and, while it runs, generates benign activity:

    * risk 3  network byte order   Test-NetConnection example.com:443 (compare with Resolve-DnsName)
    * risk 2  registry watcher     reg add + delete of a throwaway value in HKCU ...\CurrentVersion\Run
    * risk 4  DPAPI 16385          ProtectedData.Protect/Unprotect of a random blob (own data)
    * risk 6  short-lived cmdline  cmd /c echo kestrel-probe-<nonce>
    * risk 7  nslookup vs DNS      nslookup (expected: no dns_query) and Resolve-DnsName (expected: one)
    * audit   OpenProcess          OpenProcess(0x1010) on a child notepad-free process (own ping.exe)
    * risk 1  volume               optional -Load: writes/reads 5000 small temp files

  Then prints a verdict per risk from the captured events. Safe on a workstation: it changes nothing
  except one throwaway HKCU key and temp files, both removed. Requires an elevated shell.
#>
[CmdletBinding()]
param(
    [string]$AgentExe = (Join-Path $PSScriptRoot '..\target\release\kestrel-agent.exe'),
    [int]$Seconds = 45,
    [string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) ("kestrel-probe-" + (Get-Date -Format yyyyMMdd-HHmmss))),
    [switch]$Load
)
$ErrorActionPreference = 'Stop'
$AgentExe = (Resolve-Path -LiteralPath $AgentExe).Path
New-Item -ItemType Directory -Force $OutDir | Out-Null
$events = Join-Path $OutDir 'events.jsonl'
$report = Join-Path $OutDir 'sensors.json'
$errLog = Join-Path $OutDir 'agent.log'
$nonce = [guid]::NewGuid().ToString('N').Substring(0, 8)

$p = Start-Process $AgentExe -ArgumentList "--state-dir `"$OutDir\state`" sensors-test --seconds $Seconds --detect --events-out `"$events`"" `
    -NoNewWindow -PassThru -RedirectStandardOutput $report -RedirectStandardError $errLog
$null = $p.Handle
$until = (Get-Date).AddSeconds(60)
while (-not (Select-String -Path $errLog -Pattern 'KESTREL-SENSORS-READY' -Quiet -ErrorAction SilentlyContinue)) {
    if ($p.HasExited -or (Get-Date) -gt $until) { Get-Content $errLog -Tail 30; throw 'sensors did not start' }
    Start-Sleep -Milliseconds 250
}
Start-Sleep 3
Write-Host "[probe] sensors up; generating activity (nonce $nonce)"

# risk 6: short-lived process command line
& cmd.exe /c "echo kestrel-probe-$nonce" | Out-Null

# risk 7: nslookup (bypasses the DNS Client service) vs Resolve-DnsName
& nslookup.exe "nslookup-$nonce.example.com" 2>&1 | Out-Null
Clear-DnsClientCache
Resolve-DnsName "resolve-$nonce.example.com" -DnsOnly -ErrorAction SilentlyContinue | Out-Null
$exIps = @(Resolve-DnsName example.com -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object IPAddress | ForEach-Object IPAddress)

# risk 3: network address / port byte order
$tnc = Test-NetConnection example.com -Port 443 -WarningAction SilentlyContinue
$tncIp = "$($tnc.RemoteAddress)"

# risk 2: registry watcher + writer attribution (throwaway value in HKCU Run,
# removed again; reg.exe so the writer is a distinct, short-lived process)
$runKey = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
& reg.exe add $runKey /v "KestrelProbe$nonce" /t REG_SZ /d notepad.exe /f | Out-Null
Start-Sleep -Seconds 3
& reg.exe delete $runKey /v "KestrelProbe$nonce" /f | Out-Null

# risk 4: DPAPI unprotect of our own blob (does 16385 arrive?)
Add-Type -AssemblyName System.Security
try {
    $blob = [Security.Cryptography.ProtectedData]::Protect([byte[]](1..32), $null, 'CurrentUser')
    [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'CurrentUser') | Out-Null
} catch {
    # No user DPAPI keys in a network logon (e.g. SSH); use the machine scope.
    $blob = [Security.Cryptography.ProtectedData]::Protect([byte[]](1..32), $null, 'LocalMachine')
    [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'LocalMachine') | Out-Null
}

# Audit-API OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION) on our own child
$child = Start-Process ping.exe -ArgumentList '-n 6 127.0.0.1' -WindowStyle Hidden -PassThru
Add-Type -Name K -Namespace KestrelProbe -MemberDefinition '[DllImport("kernel32")] public static extern System.IntPtr OpenProcess(uint a,bool i,int p); [DllImport("kernel32")] public static extern bool CloseHandle(System.IntPtr h);'
[void][KestrelProbe.K]::CloseHandle([KestrelProbe.K]::OpenProcess(0x1010, $false, $child.Id))

if ($Load) {
    $d = Join-Path $OutDir 'load'; New-Item -ItemType Directory $d | Out-Null
    1..5000 | ForEach-Object { [IO.File]::WriteAllText("$d\f$_.txt", "x$_") }
    Get-ChildItem $d | ForEach-Object { [IO.File]::ReadAllText($_.FullName) | Out-Null }
    Remove-Item $d -Recurse -Force
}

$p.WaitForExit(($Seconds + 90) * 1000) | Out-Null
$r = Get-Content -Raw $report | ConvertFrom-Json
$ev = Get-Content $events | ForEach-Object { $_ | ConvertFrom-Json }
Write-Host "[probe] $($ev.Count) events; counts: $(($r.counts | ConvertTo-Json -Compress))"
Write-Host "[probe] stats: $(($r.stats | ConvertTo-Json -Compress))"

function Verdict($name, $ok, $detail) {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("  {0} {1}: {2}" -f $tag, $name, $detail) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
}
$cmdEv = $ev | Where-Object { $_.type -eq 'process_start' -and $_.cmdline -like "*kestrel-probe-$nonce*" }
Verdict 'risk 6 short-lived cmdline' ([bool]$cmdEv) ("cmd.exe start with cmdline: " + ($cmdEv | Select-Object -First 1 -ExpandProperty cmdline))

$dnsNs = $ev | Where-Object { $_.type -eq 'dns_query' -and $_.qname -like "nslookup-$nonce*" }
$dnsRs = $ev | Where-Object { $_.type -eq 'dns_query' -and $_.qname -like "resolve-$nonce*" }
Verdict 'risk 7 Resolve-DnsName seen' ([bool]$dnsRs) "dns_query events: $(@($dnsRs).Count)"
Write-Host "    info: nslookup produced $(@($dnsNs).Count) dns_query events (expected 0: bypasses DNS Client)"

$net = @($ev | Where-Object { $_.type -eq 'net_connect' -and $_.dst_port -eq 443 -and $_.dst_ip -eq $tncIp })
$swapped = @($ev | Where-Object { $_.type -eq 'net_connect' -and $_.dst_port -eq 47873 })
Verdict 'risk 3 network byte order' ($net.Count -gt 0 -and $swapped.Count -eq 0) "Test-NetConnection $tncIp:443 seen $($net.Count)x; example.com A=$($exIps -join ','); swapped-port events=$($swapped.Count)"

$reg = @($ev | Where-Object { $_.type -eq 'registry_set' -and $_.value_name -eq "KestrelProbe$nonce" })
$regSet = $reg | Where-Object { -not $_.op -or $_.op -eq 'set' } | Select-Object -First 1
$regDel = $reg | Where-Object { $_.op -eq 'delete_value' } | Select-Object -First 1
$regKey = $regSet.key
Verdict 'risk 2 registry full key' ([bool]$regSet -and $regKey -match '^HKU\\S-1-[\d-]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Run$') "key='$regKey' data='$($regSet.data)'"
Verdict 'risk 2 registry writer attributed' ([bool]$regSet -and $regSet.pid -ne 0) "set pid=$($regSet.pid); delete pid=$($regDel.pid)"
Verdict 'risk 2 registry delete seen' ([bool]$regDel) "delete_value events: $(@($reg | Where-Object { $_.op -eq 'delete_value' }).Count)"

$dp = @($ev | Where-Object { $_.type -eq 'dpapi_unprotect' })
Write-Host "    info: risk 4 dpapi_unprotect events: $($dp.Count) (channel enabled: $($r.stats.dpapi_channel_enabled))"

$pa = @($ev | Where-Object { $_.type -eq 'process_access' -and $_.target_pid -eq $child.Id })
Verdict 'Audit-API OpenProcess seen' ($pa.Count -gt 0) ("access=0x{0:x}" -f [int]($pa | Select-Object -First 1).granted_access)

Write-Host "    info: alerts (Audit only): $(@($r.alerts).Count)"
$r.alerts | Select-Object -First 15 | ForEach-Object { Write-Host "      $($_.rule_id) $($_.image) :: $($_.summary)" }
Write-Host "[probe] output: $OutDir"
