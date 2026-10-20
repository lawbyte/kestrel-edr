<#
  First-logon setup for the disposable Kestrel lab VM (runs once as labadmin, elevated).
  * OpenSSH Server with key-only auth for labadmin (key from the setup CD)
  * network profile Private, no sleep, no screen lock
  * autologon switched to the standard user `employee` (the tray runs in that session)
  * writes C:\kestrel-lab\firstboot.done, then reboots
  Lab only. Never run on a real machine.
#>
param([string]$Src = 'E:\')
$ErrorActionPreference = 'Continue'
$log = 'C:\kestrel-lab\firstboot.log'
New-Item -ItemType Directory -Force C:\kestrel-lab | Out-Null
Start-Transcript -Path $log -Append | Out-Null

# Network + power
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization' /v NoLockScreen /t REG_DWORD /d 1 /f | Out-Null

# OpenSSH server (Feature on Demand; downloaded from Windows Update)
for ($i = 0; $i -lt 5; $i++) {
    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
    if ($cap.State -eq 'Installed') { break }
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
    Start-Sleep 10
}
$pub = Get-Content (Join-Path $Src 'lab_key.pub') -Raw
Set-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value $pub.Trim() -Encoding ascii -Force -ErrorAction SilentlyContinue
if (-not (Test-Path C:\ProgramData\ssh)) { New-Item -ItemType Directory C:\ProgramData\ssh | Out-Null; Set-Content C:\ProgramData\ssh\administrators_authorized_keys $pub.Trim() -Encoding ascii }
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd
# PowerShell as the default SSH shell
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null
if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

# Autologon as the standard user from now on
$w = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$userPw = (Get-Content (Join-Path $Src 'user_pw.txt') -Raw).Trim()
Set-ItemProperty $w AutoAdminLogon '1'
Set-ItemProperty $w DefaultUserName 'employee'
Set-ItemProperty $w DefaultPassword $userPw
Remove-ItemProperty $w AutoLogonCount -ErrorAction SilentlyContinue

Set-Content C:\kestrel-lab\firstboot.done (Get-Date -Format o)
Stop-Transcript | Out-Null
shutdown /r /t 5 /c "Kestrel lab first boot complete"
