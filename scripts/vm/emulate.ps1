<#
.SYNOPSIS
  Benign rule emulations for the disposable Kestrel lab VM. NEVER run on a real machine.

.DESCRIPTION
  Each id runs one harmless emulation from docs/TESTING-ON-WINDOWS.md (adapted to Microsoft Edge,
  which ships with the Windows 11 evaluation image) or for the RW/CD/PS families. Nothing here is
  malware: "stealer" steps read dummy browser data with a renamed copy of PowerShell (labsim.exe),
  "ransomware" steps XOR-rename a seeded corpus of lab files, "credential dumping" steps target
  notepad or only *open* lsass with query+read rights, persistence steps point at lab binaries and
  are removed again by -Cleanup.

  Steps marked User run as the standard user `employee` in its interactive session (scheduled task
  with /IT); the others run as the calling administrator (SSH session of labadmin).

    emulate.ps1 -Setup                 # lab folder, labsim.exe, unsigned exe, Edge dummy profile data
    emulate.ps1 -Id ST-01              # one emulation (prints START/END markers with timestamps)
    emulate.ps1 -Id all-audit          # every emulation in sequence (Audit pass)
    emulate.ps1 -Cleanup               # remove lab persistence / settings
#>
[CmdletBinding()]
param(
    [string]$Id,
    [switch]$Setup,
    [switch]$Cleanup,
    [string]$UserPasswordFile = 'C:\kestrel-lab\user_pw.txt'
)
$ErrorActionPreference = 'Continue'
$Root = 'C:\kestrel-lab'
$EmpProfile = 'C:\Users\employee'
$Lab = "$EmpProfile\AppData\Local\KestrelLab"
$EdgeUD = "$EmpProfile\AppData\Local\Microsoft\Edge\User Data"
$Edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
New-Item -ItemType Directory -Force $Root | Out-Null

function Mark($what) { Write-Output ("{0} {1} {2}" -f $what, $Id, [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) }

# Run a script block as `employee` in its interactive session; waits for it to finish.
function Invoke-AsUser([string]$Name, [string]$Script, [int]$TimeoutSec = 120) {
    $pw = (Get-Content $UserPasswordFile -Raw).Trim()
    $ps1 = "$Root\u-$Name.ps1"
    $done = "$Root\u-$Name.done"
    Remove-Item $done -ErrorAction SilentlyContinue
    Set-Content -Path $ps1 -Encoding UTF8 -Value ($Script + "`nSet-Content -Path '$done' -Value ok")
    $tn = "KestrelLabUser-$Name"
    schtasks /delete /tn $tn /f 2>$null | Out-Null
    schtasks /create /tn $tn /tr "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $ps1" /sc once /st 23:59 /ru employee /rp $pw /it /f | Out-Null
    schtasks /run /tn $tn | Out-Null
    $end = (Get-Date).AddSeconds($TimeoutSec)
    while (-not (Test-Path $done) -and (Get-Date) -lt $end) { Start-Sleep -Milliseconds 500 }
    schtasks /delete /tn $tn /f 2>$null | Out-Null
    if (-not (Test-Path $done)) { Write-Warning "$Name did not finish within $TimeoutSec s" }
}

# Run as employee through labsim.exe (a copy of PowerShell in a user-writable folder).
function Invoke-Labsim([string]$Name, [string]$Command, [int]$TimeoutSec = 120) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    Invoke-AsUser $Name "& '$Lab\labsim.exe' -NoProfile -EncodedCommand $enc" $TimeoutSec
}

if ($Setup) {
    Invoke-AsUser 'setup' @"
New-Item -ItemType Directory -Force '$Lab' | Out-Null
Copy-Item "`$PSHOME\powershell.exe" '$Lab\labsim.exe' -Force
# Edge profile with dummy stores (Edge must have run once to create User Data).
Start-Process '$Edge' '--no-first-run --headless=new about:blank'; Start-Sleep 8; Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force '$EdgeUD\Default\Network' | Out-Null
foreach (`$f in 'Login Data','Web Data','Network\Cookies') { if (-not (Test-Path "$EdgeUD\Default\`$f")) { Set-Content "$EdgeUD\Default\`$f" 'SQLite format 3 dummy' } }
New-Item -Force "`$env:APPDATA\Exodus\exodus.wallet\seed.seco" -Value x | Out-Null
# Unsigned test exe in Downloads and in the lab folder.
Add-Type -OutputType ConsoleApplication -OutputAssembly "`$env:USERPROFILE\Downloads\kestrel-unsigned.exe" -TypeDefinition 'public static class P{public static void Main(){System.Console.WriteLine(1);}}'
Copy-Item "`$env:USERPROFILE\Downloads\kestrel-unsigned.exe" '$Lab\kestrel-unsigned.exe' -Force
# Seed corpus for the ransomware emulation: 4 folders x 20 small documents.
1..4 | % { `$d = "`$env:USERPROFILE\Documents\KestrelLabData\dir`$_"; New-Item -ItemType Directory -Force `$d | Out-Null; 1..20 | % { Set-Content "`$d\report`$_.docx" ("lab document " + `$_) } }
"@ 180
    Copy-Item $UserPasswordFile "$Root\user_pw.txt" -ErrorAction SilentlyContinue
    Write-Output 'setup done'
    return
}

if ($Cleanup) {
    $hkuEmp = (New-Object Security.Principal.NTAccount('employee')).Translate([Security.Principal.SecurityIdentifier]).Value
    reg delete "HKU\$hkuEmp\Software\Microsoft\Windows\CurrentVersion\Run" /v KestrelLabRun /f 2>$null
    reg delete "HKU\$hkuEmp\Software\Microsoft\Windows\CurrentVersion\Run" /v KestrelLabPs /f 2>$null
    reg delete "HKU\$hkuEmp\Software\Classes\CLSID\{0E5AAE11-A475-4C5B-AB00-C66DE400274E}" /f 2>$null
    Remove-Item "$EmpProfile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\kestrel-lab.vbs" -ErrorAction SilentlyContinue
    schtasks /delete /tn KestrelLab /f 2>$null
    sc.exe delete KestrelLabSvc 2>$null | Out-Null
    reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' /v Debugger /f 2>$null
    reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe' /f 2>$null
    reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
    reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v Userinit /t REG_SZ /d 'C:\Windows\system32\userinit.exe,' /f | Out-Null
    bcdedit /set '{default}' recoveryenabled yes | Out-Null
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | ? { "$($_.Filter)" -match 'KestrelLab' } | Remove-WmiObject
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | ? Name -eq 'KestrelLab' | Remove-WmiObject
    Get-WmiObject -Namespace root\subscription -Class __EventFilter | ? Name -eq 'KestrelLab' | Remove-WmiObject
    Remove-Item C:\kestrel-lab\*.hiv, C:\kestrel-lab\*.dmp -ErrorAction SilentlyContinue
    Write-Output 'cleanup done'
    return
}

$ST = [ordered]@{
    'ST-01' = { Invoke-Labsim 'st01' "Copy-Item '$EdgeUD\Default\Login Data' '$Lab\ld.bin' -Force" }
    'ST-02' = { Invoke-Labsim 'st02' "foreach(`$f in '$EdgeUD\Default\Login Data','$EdgeUD\Default\Network\Cookies','$EdgeUD\Default\Web Data',`"`$env:APPDATA\Exodus\exodus.wallet\seed.seco`"){ [IO.File]::ReadAllBytes(`$f) | Out-Null }; Start-Sleep 5" }
    'ST-04' = { Invoke-Labsim 'st04' "[IO.File]::ReadAllBytes('$EdgeUD\Default\Login Data') | Out-Null; try { Invoke-WebRequest https://example.com -Method Post -Body x -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {}; Start-Sleep 3" }
    'ST-05' = { Invoke-Labsim 'st05' "Start-Process '$Edge' '--headless=new --remote-debugging-port=9222 --user-data-dir=$Lab\cdp about:blank'; Start-Sleep 15" 60 }
    'ST-06' = { Invoke-Labsim 'st06' "Start-Process '$Edge' '--headless=new --remote-debugging-port=9223 --user-data-dir=$Lab\cdp2 about:blank'; Start-Sleep 6; try { Invoke-RestMethod http://127.0.0.1:9223/json/version | Out-Null } catch {}; Get-Process msedge -ErrorAction SilentlyContinue | ? { `$_.Path -eq '$Edge' } | Out-Null" 60 }
    'ST-07' = { Invoke-Labsim 'st07' "Start-Process '$Edge' '--no-first-run about:blank'; Start-Sleep 6; Add-Type -Name K -Namespace W -MemberDefinition '[DllImport(\`"kernel32\`")] public static extern System.IntPtr OpenProcess(uint a,bool i,int p); [DllImport(\`"kernel32\`")] public static extern bool CloseHandle(System.IntPtr h);'; `$p=(Get-Process msedge)[0].Id; [W.K]::CloseHandle([W.K]::OpenProcess(0x1010,`$false,`$p)) | Out-Null" 60 }
    'ST-11' = { Invoke-AsUser 'st11' "Start-Process cmd.exe '/c nslookup example.com 8.8.8.8'; Start-Sleep 5" }
    'ST-12' = { Invoke-AsUser 'st12' "& `"`$env:USERPROFILE\Downloads\kestrel-unsigned.exe`" | Out-Null" }
    'ST-14' = { Invoke-Labsim 'st14' "Resolve-DnsName api.telegram.org -ErrorAction SilentlyContinue | Out-Null; try { Invoke-WebRequest https://api.telegram.org -Method Head -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {}" }
    'ST-16' = { Invoke-Labsim 'st16' "`$d = Get-ChildItem '$EdgeUD' -Directory | ? Name -match '^Profile (5[1-9]|[6-8]\d|9[0-8])$' | Select -First 1; if (`$d) { Get-Content -Encoding Byte -TotalCount 16 (Join-Path `$d.FullName 'Login Data') | Out-Null }" }
    'TP-01' = { logman stop Kestrel-IO -ets | Out-Null }
    'TP-03' = { reg add HKLM\SOFTWARE\Microsoft\AMSI /v FeatureBits /t REG_DWORD /d 2 /f | Out-Null; Start-Sleep 2; reg delete HKLM\SOFTWARE\Microsoft\AMSI /v FeatureBits /f | Out-Null }
    'TP-04' = { reg add HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent /v LabTest /t REG_SZ /d x /f 2>&1 | Out-Null; Start-Sleep 2; reg delete HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent /v LabTest /f 2>&1 | Out-Null }
}
$RW = [ordered]@{
    'RW-01' = { Invoke-Labsim 'rw01' "vssadmin.exe delete shadows /all /quiet | Out-Null; Start-Sleep 2" }
    'RW-02' = { Invoke-Labsim 'rw02' "Start-Sleep 1" ; bcdedit /set '{default}' recoveryenabled no | Out-Null; Start-Sleep 2; bcdedit /set '{default}' recoveryenabled yes | Out-Null }
    'RW-04' = { wevtutil cl 'Windows PowerShell' }
    'RW-05' = { foreach ($s in 'MSSQLSERVER','SQLWriter','VeeamBackupSvc','memtas','mepocs','BackupExecVSSProvider') { sc.exe stop $s 2>&1 | Out-Null } }
    'RW-06' = { Invoke-Labsim 'rw06' "Get-ChildItem `"`$env:USERPROFILE\Documents\KestrelLabData`" -Recurse -File -Filter *.docx | % { `$b=[IO.File]::ReadAllBytes(`$_.FullName); for(`$i=0;`$i -lt `$b.Length;`$i++){`$b[`$i]=`$b[`$i] -bxor 0x5A}; [IO.File]::WriteAllBytes(`$_.FullName,`$b); Rename-Item `$_.FullName (`$_.Name + '.k3str') }; Start-Sleep 3" 180 }
    'RW-07' = { Invoke-Labsim 'rw07' "Get-ChildItem `"`$env:USERPROFILE\Documents`",`"`$env:USERPROFILE\Desktop`" -File -Force | ? { `$_.Name -match '^[!0_]' } | Select -First 1 | % { Add-Content `$_.FullName 'x' }" }
    'RW-08' = { Invoke-Labsim 'rw08' "1..6 | % { `$d=`"`$env:USERPROFILE\Documents\KestrelLabData\note`$_`"; New-Item -ItemType Directory -Force `$d | Out-Null; Set-Content `"`$d\README_RESTORE_FILES.txt`" 'lab note' }; Start-Sleep 3" }
}
$CD = [ordered]@{
    'CD-01' = { $n = Start-Process notepad -PassThru; Start-Sleep 2; rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $n.Id C:\kestrel-lab\notepad.dmp full; Start-Sleep 2; Stop-Process $n -Force -ErrorAction SilentlyContinue }
    'CD-03' = { Invoke-Labsim 'cd03' "Add-Type -Name L -Namespace W -MemberDefinition '[DllImport(\`"kernel32\`")] public static extern System.IntPtr OpenProcess(uint a,bool i,int p); [DllImport(\`"kernel32\`")] public static extern bool CloseHandle(System.IntPtr h);'; `$p=(Get-Process lsass).Id; [W.L]::CloseHandle([W.L]::OpenProcess(0x1010,`$false,`$p)) | Out-Null" }
    'CD-07' = { reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe' /v ReportingMode /t REG_DWORD /d 2 /f | Out-Null; Start-Sleep 2; reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe' /f | Out-Null }
    'CD-10' = { reg save HKLM\SAM C:\kestrel-lab\sam.hiv /y | Out-Null; Start-Sleep 1; Remove-Item C:\kestrel-lab\sam.hiv -ErrorAction SilentlyContinue }
    'CD-12' = { reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential /t REG_DWORD /d 1 /f | Out-Null }
}
$PS = [ordered]@{
    'PS-01' = { Invoke-AsUser 'ps01' "Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name KestrelLabRun -Value '`"$Lab\kestrel-unsigned.exe`"'" }
    'PS-02' = { Invoke-AsUser 'ps02' "`$c = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output lab')); Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name KestrelLabPs -Value `"powershell.exe -w hidden -enc `$c`"" }
    'PS-03' = { Invoke-Labsim 'ps03' "Set-Content `"`$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\kestrel-lab.vbs`" 'WScript.Echo 1'" }
    'PS-05' = { schtasks /create /tn KestrelLab /tr "$Lab\kestrel-unsigned.exe" /sc onlogon /ru employee /f | Out-Null }
    'PS-07' = { Copy-Item "$Lab\kestrel-unsigned.exe" C:\Users\Public\kestrel-svc.exe -Force; sc.exe create KestrelLabSvc binPath= C:\Users\Public\kestrel-svc.exe start= demand | Out-Null }
    'PS-08' = {
        $f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{ Name = 'KestrelLab'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 3" }
        $c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{ Name = 'KestrelLab'; CommandLineTemplate = 'cmd.exe /c exit' }
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter = $f; Consumer = $c } | Out-Null
    }
    'PS-09' = { reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' /v Debugger /t REG_SZ /d 'C:\Windows\System32\cmd.exe' /f | Out-Null }
    'PS-10' = { reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,$Lab\kestrel-unsigned.exe," /f | Out-Null }
    'PS-11' = { Invoke-AsUser 'ps11' "New-Item -Force 'HKCU:\Software\Classes\CLSID\{0E5AAE11-A475-4C5B-AB00-C66DE400274E}\InprocServer32' | Out-Null; Set-ItemProperty 'HKCU:\Software\Classes\CLSID\{0E5AAE11-A475-4C5B-AB00-C66DE400274E}\InprocServer32' -Name '(default)' -Value '$Lab\lab.dll'" }
}
$All = [ordered]@{}
foreach ($t in $ST, $RW, $CD, $PS) { foreach ($k in $t.Keys) { $All[$k] = $t[$k] } }

if ($Id -eq 'all-audit') {
    foreach ($k in $All.Keys) { $script:Id = $k; Mark START; & $All[$k]; Mark END; Start-Sleep 4 }
    return
}
if (-not $All.Contains($Id)) { throw "unknown id $Id (known: $($All.Keys -join ', '))" }
Mark START
& $All[$Id]
Mark END
