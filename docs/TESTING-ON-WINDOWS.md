# Validating Kestrel on a real Windows 11 VM

This is a lab plan for checking the Windows layer end to end on real hardware or a VM. The detection engine, server and agent core are covered by unit tests and by `scripts/e2e.sh`, which uses recorded telemetry. The ETW decoding, path and registry resolution, WFP and hardening code can only be proven on Windows. Each step lists the **expected rule ids**, so a miss points at a specific part of the sensor layer.

> Use a **disposable VM with snapshots**, not a work machine. Several steps kill processes, quarantine files or isolate the host. Use a browser profile with dummy logins only.

## Automated disposable lab (QEMU/KVM in WSL2)

On a Windows 11 *Home* workstation (no Hyper-V Manager, no Windows Sandbox) the lab runs as a QEMU/KVM guest inside the WSL2 Kali distro, which exposes `/dev/kvm`. Everything is scripted in `scripts/vm/`:

| Script | What it does |
|---|---|
| `vm.sh install` | Unattended Windows 11 Enterprise **Evaluation** install from `~/kestrel-vm/win11.iso` (90-day eval from the Microsoft Evaluation Center): `autounattend.xml` + `firstboot.ps1` create `labadmin` (SSH key auth, OpenSSH Server) and the standard user `employee` (autologon), then snapshot `clean`. About 20 minutes with KVM. |
| `vm.sh start \| stop \| snapshot NAME \| revert NAME \| ssh \| put \| get \| screenshot` | Lifecycle, qcow2 snapshots, PowerShell over SSH, file copy, PNG of the console. `stop` shuts Windows down over SSH and waits; a hard kill can leave a disk that no longer boots. |
| `api.sh login \| get \| post \| put` | Minimal REST client (session cookie + CSRF) for creating enrollment tokens, switching policies, reading alerts and hunting. |
| `emulate.ps1 -Setup \| -Id <rule> \| -Id all-audit \| -Cleanup` | Benign emulations. Steps that must run as the standard user go through an interactive scheduled task in `employee`'s session; the "stealer" is `labsim.exe` (a copy of PowerShell in `%LOCALAPPDATA%\KestrelLab`). |
| `emulate-cmd.cmd <rule>` | Command-line emulations (vssadmin, bcdedit, wevtutil, sc, reg, comsvcs on **notepad**). Batch files are not AMSI-scanned, so Defender does not block the lab script itself; it may still block a step, which is worth knowing. |

The guest reaches the server at `10.0.2.2` (QEMU user networking → WSL2 localhost → Docker Desktop), so `KESTREL_PUBLIC_HOSTNAME` must include `10.0.2.2`.

Lab facts learned on real Windows (2026-10-21):
* Defender flags `kestrel-agent.exe` as `Trojan:Win32/Cryware.B` (heuristic on the credential-store path tables). In the lab, `C:\Program Files\Kestrel` is excluded; production needs signing + a Microsoft false-positive submission (see HANDOFF).
* A clean Windows has no `VCRUNTIME140.dll`: binaries are linked with the static CRT (`.cargo/config.toml`).
* OpenSSH sessions have no console: `timeout.exe` refuses to run (use `ping -n`), and `ProtectedData` `CurrentUser` fails (network logon).

**Between passes:** containment persists by design. Image blocks from a Protect pass (ST-02/ST-07/ST-16) stay until an analyst lifts them, and they will silently stop the network parts of the next pass (ST-04, ST-06, ST-14). Lift them with the `unblock_network` action (device page > Actions > *Lift block*, or `POST /api/devices/{id}/actions` with `{"action":{"type":"unblock_network"}}`), or reinstall the agent. Results of the v1.1.0-rc1 lab run are in `docs/HANDOFF.md`.

## 0. Lab layout

| Machine | Role |
|---|---|
| Linux VM (2 vCPU, 4 GB) | `kestrel-server` via Docker Compose (or `E2E_KEEP=1 scripts/e2e.sh` for a throwaway server) |
| Windows 11 VM (Pro and, if you can, Enterprise; 4 vCPU, 8 GB) | Agent + tray. Chrome and Edge installed. Firefox optional (ST-09). Sysmon optional (cross-check) |

Take a snapshot of the Windows VM **before** installing the agent, and again after installing it.

## 1. Install the server

```bash
cd deploy && cp .env.example .env
sed -i "s|^KESTREL_MASTER_KEY=.*|KESTREL_MASTER_KEY=$(openssl rand -base64 32)|" .env
# KESTREL_PUBLIC_HOSTNAME = a DNS name or IP the Windows VM uses to reach this host (IPs are fine: they become IP SANs)
$EDITOR .env
docker compose up -d --build
curl -k https://localhost/api/healthz
```

Complete first-run setup at `https://<host>/` to create the organisation and admin user. Put the CI-built `KestrelAgent.msi` in `deploy/installers/`.

## 2. Install the agent

1. In the console, go to **Devices**, **Install agent**, create an installer and copy the install command (or download the `.cmd`).
2. On the Windows VM, in an **elevated** PowerShell, run it. Download the MSI from `https://<host>/downloads/KestrelAgent.msi` first:

   ```powershell
   msiexec.exe /i KestrelAgent.msi /qn /l*v $env:TEMP\kestrel-msi.log SERVER=<host>:8443 TOKEN=kst_enr_… CA_B64=…
   ```

   The uninstall token is issued by the server at enrollment (one per device). Copy it from **Devices → <VM> → Uninstall token** in the console; it is needed for `msiexec /x`, `kestrel-agent uninstall` and the isolation break-glass. The agent stores only its Argon2id hash and never prints it.

3. Check the installation:

   ```powershell
   Get-Service KestrelAgent                                   # Running
   & 'C:\Program Files\Kestrel\kestrel-agent.exe' status      # JSON health from the running agent
   logman query -ets | Select-String Kestrel                  # Kestrel-Core, Kestrel-IO (and Kestrel-ProcCmd)
   Select-String -Path $env:TEMP\kestrel-msi.log -Pattern 'kst_enr_|kun_|--token' # must find nothing (hidden properties)
   (Get-Acl C:\ProgramData\Kestrel).Owner                     # NT AUTHORITY\SYSTEM
   (Get-Acl C:\ProgramData\Kestrel).Access | ft IdentityReference,FileSystemRights   # SYSTEM and Administrators only
   ```

4. Check the self-protection:

   ```powershell
   sc.exe stop KestrelAgent                                   # expect: Access is denied (service DACL, even as admin)
   & 'C:\Program Files\Kestrel\kestrel-agent.exe' uninstall --token wrong   # expect: invalid uninstall token
   ```

5. Check the tray. It should start at logon with a green shield showing "Protected". Its **Help & privacy** tab shows the notice from **Policies → Branding & notice**.

### Check ETW health on the device page

Open **Devices → <VM>**. In the **Sensor health** card, every row should be green:

| Row | What it means | What to do if it is not green |
|---|---|---|
| Kernel telemetry (ETW) | All sessions running; events/min > 0 | `logman query Kestrel-Core -ets`; check the agent log in `C:\ProgramData\Kestrel\logs` |
| Events lost (1 h) | ETW events or buffers lost | See §4 (measurements) and the known risks in §5 |
| DPAPI audit channel | `Microsoft-Windows-Crypto-DPAPI/Debug` enabled (needed by ST-03) | Set Hardening → DPAPI audit channel to **Enforce**; `wevtutil gl Microsoft-Windows-Crypto-DPAPI/Debug` |
| AMSI provider | AMSI registered | |
| Outbox | queued messages; should drain to ~0 while online | |

The **Hardening** tab lists each control as desired, applied and its source. The **Event timeline** should show process starts as you open programs.

## 3. Benign emulations, one per rule

Run two passes:

* **Pass A (detection).** In **Policies → Default → Detection rules**, set every rule to **Audit**, including the four day-one Protect rules ST-02, ST-04, ST-07 and ST-16. You get alerts without kills, so one script can exercise everything.
* **Pass B (containment).** Restore the defaults, or set rules to Protect, and repeat the steps for ST-01/02/03/04/07/16. Check the kill, suspend and resume behaviour and the quarantine, network-block and isolation actions on the incident page, then use **Release host** and **Restore** to clean up.

Everything below runs as the **normal (non-admin) user** unless it says otherwise. To keep containment away from the real system binaries, the "stealer" is a copy of PowerShell in a user-writable folder. Kestrel then treats it as an untrusted user-path process, and Protect actions such as quarantine and image network blocks hit the copy, not `System32\WindowsPowerShell`.

```powershell
$lab = "$env:LOCALAPPDATA\KestrelLab"; New-Item -ItemType Directory -Force $lab | Out-Null
Copy-Item "$PSHOME\powershell.exe" "$lab\labsim.exe"
$chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data"
# Run Chrome once and save a dummy password so Login Data / Cookies / Web Data / Local State exist, then close it.
```

The lab folder is under `AppData\Local`, which is *UserWritable*. Temp and Downloads would be blocked once the `block_user_path_exec` AppLocker control is enforced. Run each snippet as `& "$lab\labsim.exe" -NoProfile -Command { … }` so the acting process is `labsim.exe`.

| # | Emulation (benign) | Expected |
|---|---|---|
| ST-01 | `& "$lab\labsim.exe" -NoProfile -c "Copy-Item '$chrome\Default\Login Data' '$lab\ld.bin'"` | **ST-01** (credential-store read by untrusted process; medium). In Protect, labsim is suspended for about 3 s and then resumed, because it is signed |
| ST-02 | One labsim process reads Login Data, `Default\Network\Cookies`, `Default\Web Data` and a wallet file within 60 s. First create a dummy wallet from *your* shell: `New-Item -Force "$env:APPDATA\Exodus\exodus.wallet\seed.seco" -Value x`. Then: `& "$lab\labsim.exe" -NoProfile -c "foreach(`$f in '$chrome\Default\Login Data','$chrome\Default\Network\Cookies','$chrome\Default\Web Data','$env:APPDATA\Exodus\exodus.wallet\seed.seco'){ [IO.File]::ReadAllBytes(`$f) | Out-Null }; Start-Sleep 5"` | **ST-01, ST-02** (critical). `data_at_risk` shows browser_passwords, browser_cookies, browser_autofill and crypto_wallet. In Protect: kill tree, block network for `labsim.exe`, quarantine `labsim.exe` |
| ST-03 | Chrome closed, DPAPI channel enforced: `& "$lab\labsim.exe" -NoProfile -c "Add-Type -AssemblyName System.Security; `$k=[Convert]::FromBase64String((Get-Content '$chrome\Local State' -Raw | ConvertFrom-Json).os_crypt.encrypted_key)[5..999]; [Security.Cryptography.ProtectedData]::Unprotect(`$k,`$null,'CurrentUser') | Out-Null"` (the decrypted key is discarded) | **ST-01** (Local State) and **ST-03** (foreign DPAPI unprotect, description "Google Chrome"). If ST-03 is missing, see known risk 4 |
| ST-04 | Same labsim process: read Login Data, then within 300 s `Invoke-WebRequest https://example.com -Method Post -Body x -UseBasicParsing` | **ST-01, ST-04** (steal-then-send). The incident priority is ≥ 90 and the Network tab lists example.com's IP. In Protect: kill, block destination, quarantine |
| ST-05 | `& "$lab\labsim.exe" -NoProfile -c "Start-Process 'C:\Program Files\Google\Chrome\Application\chrome.exe' '--headless=new --remote-debugging-port=9222 --user-data-dir=$lab\cdp about:blank'; Start-Sleep 20"` | **ST-05** (parent is not explorer or a browser). In Protect: kill the Chrome tree and labsim |
| ST-06 | While ST-05's Chrome runs (Audit pass): `& "$lab\labsim.exe" -NoProfile -c "Invoke-RestMethod http://127.0.0.1:9222/json/version"` | **ST-06** (local CDP client) |
| ST-07 | Chrome open. `& "$lab\labsim.exe" -NoProfile -c "Add-Type -Name K -Namespace W -MemberDefinition '[DllImport(\"kernel32\")] public static extern System.IntPtr OpenProcess(uint a,bool i,int p); [DllImport(\"kernel32\")] public static extern bool CloseHandle(System.IntPtr h);'; `$p=(Get-Process chrome)[0].Id; [W.K]::CloseHandle([W.K]::OpenProcess(0x1010,`$false,`$p))"` | **ST-07** (VM_READ + QUERY_LIMITED on a browser, through Kernel-Audit-API-Calls). In Protect: kill labsim |
| ST-08 | (Optional, admin.) From labsim: `Stop-Process -Name chrome -Force` twice within a few seconds (restart Chrome in between), then `Start-Service GoogleChromeElevationService` | **ST-08** |
| ST-09 | (Firefox installed.) `& "$lab\labsim.exe" -NoProfile -c "Add-Type -Name L -Namespace W -MemberDefinition '[DllImport(\"kernel32\",CharSet=CharSet.Unicode)] public static extern System.IntPtr LoadLibraryExW(string f,System.IntPtr h,uint fl);'; [W.L]::LoadLibraryExW('C:\Program Files\Mozilla Firefox\nss3.dll',[IntPtr]::Zero,8)"` | **ST-09** (foreign nss3.dll load) |
| ST-10, ST-11 | Press **Win+R** and run: `powershell -w h -c "Write-Output 'irm https://example.invalid/v.txt' # I am not a robot - Cloudflare verification"` (it only prints). Clean up: `Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -Name a,b,c -ErrorAction SilentlyContinue` | **ST-10** (RunMRU artefact; checks the registry KeyName resolution, known risk 2) and **ST-11** (explorer started powershell with a lure comment and a hidden window). These alerts and the follow-on activity are grouped into one incident |
| ST-11 (nslookup) | From a cmd window: `cmd /c nslookup example.com 8.8.8.8` | **ST-11** (nslookup against a hard-coded external resolver) |
| ST-12 | Build an unsigned exe in Downloads and run it: `Add-Type -OutputType ConsoleApplication -OutputAssembly "$env:USERPROFILE\Downloads\kestrel-unsigned.exe" -TypeDefinition 'public static class P{public static void Main(){System.Console.WriteLine(1);}}'; & "$env:USERPROFILE\Downloads\kestrel-unsigned.exe"` | **ST-12** (low). If `block_user_path_exec` is enforced, AppLocker blocks the exe instead, which also validates that control |
| ST-13 | MSBuild inline task that makes one HTTPS request, started by labsim (an unusual parent). Save a `.proj` with a `RoslynCodeTaskFactory` task calling `new System.Net.WebClient().DownloadString("https://example.com")`, then: `& "$lab\labsim.exe" -NoProfile -c "& 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe' $lab\t.proj"` | **ST-13** (.NET LOLBin with an unusual parent, then an external connection). Atomic Red Team T1127.001 has ready-made inline-task projects; add the request to them |
| ST-14 | `& "$lab\labsim.exe" -NoProfile -c "Resolve-DnsName api.telegram.org; Invoke-WebRequest https://api.telegram.org -Method Head -UseBasicParsing"`. **Do not use `nslookup`**: it talks to the DNS server directly, bypasses the DNS Client service and produces no DNS-Client ETW event | **ST-14** (dead-drop service from non-browser), once from DNS and once from the connection |
| ST-15 | No safe one-liner (it needs a copied Defender or Edge binary that loads a planted `MpClient.dll`). Covered by unit tests; validate later with the Unit 42 Vidar sideload pattern if needed | ST-15 |
| ST-16 | The decoy is `%LOCALAPPDATA%\Kometa\User Data\Default` (and `7Star\7Star\User Data\Default`; since 2026-10-21 no decoy is planted under Chrome). Run `& "$lab\labsim.exe" -NoProfile -c "Get-Content -Encoding Byte -TotalCount 16 '$env:LOCALAPPDATA\Kometa\User Data\Default\Login Data'"`. Negative check: opening `Preferences` / a profile picture there, or starting Edge (its import scan), must raise nothing | **ST-16** (critical). In Protect: kill tree, block the image's network (24 h), quarantine (user-writable paths only). The host is **isolated only when the reader is unsigned / unknown and runs from a user-writable folder** — labsim is a Microsoft-signed copy, so expect no isolation; repeat with the unsigned exe from the ST-12 step to see isolation (the server stays reachable; use **Release host** in the console) |
| TP-01 | Admin: `logman stop Kestrel-IO -ets` | **TP-01**. The watchdog restarts the session; check `logman query -ets` again a few seconds later |
| TP-02 | Admin: first `auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable`. Only filters at the ALE connect/accept layers from a **non-Windows-Firewall provider**, or changes to Kestrel's own objects, count. Windows Firewall rules do not. In the lab, run EDRSilencer (`EDRSilencer.exe block "C:\Program Files\Kestrel\kestrel-agent.exe"`, then `unblockall`) | **TP-02**. The agent removes the foreign filter |
| TP-03 | Admin: `reg add HKLM\SOFTWARE\Microsoft\AMSI /v FeatureBits /t REG_DWORD /d 2 /f`, then `reg delete HKLM\SOFTWARE\Microsoft\AMSI /v FeatureBits /f` | **TP-03** (AMSI tampering). Also checks registry KeyName resolution for HKLM |
| TP-04 | Admin: `reg add HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent /v LabTest /t REG_SZ /d x /f`, then delete it | **TP-04** |
| TP-05 | Generate a burst of file and process activity (see §4, load test) until the device page shows events lost | **TP-05** / server `TP-SRV-EVENTS-LOST` (> 500 lost between heartbeats) |

**Response from the console.** On any incident, test the following:

* **Kill process**
* **Quarantine file**, then **Quarantine → Restore**
* **Block destination**, then check that `Test-NetConnection <ip> -Port 443` fails until the TTL expires
* **Isolate host**: only the Kestrel server stays reachable (`Test-NetConnection example.com -Port 443` fails, while the console still shows the device online). Then **Release host**
* **Collect triage**
* **Scan**

Also disconnect the VM's network, issue an action, reconnect, and check that it reaches `succeeded`.

### Security-review regression checks (2026-10-21)

Run these once per release on the lab VM (standard user unless noted). Each line names the finding it covers.

| Finding | Steps | Expected |
|---|---|---|
| H1 / L11 look-alikes | Copy labsim to `%TEMP%\Windows Defender\setup.exe` and to `%TEMP%\x\MsMpEng.exe`; run the ST-02 emulation from each (Protect) | Kill succeeds (no "refusing to act on protected …"). A kill aimed at the real `explorer.exe` / `MsMpEng.exe` from the console is refused |
| H1 other volume | Mount an ISO / VHD containing `Windows\System32\lsass.exe` (any copied exe), run it, trigger ST-02 | Killed; timeline `path_class` is not `system` |
| H4 pre-created state dir | On a fresh snapshot, as a standard user: `mkdir C:\ProgramData\Kestrel; echo x > C:\ProgramData\Kestrel\agent.toml`; then install as admin | Install log says the folder was moved to `C:\ProgramData\Kestrel.untrusted-<ms>`; the new folder is owned by SYSTEM with a protected DACL; the planted `agent.toml` is not used |
| H7 first run | Build a new unsigned exe in Downloads (ST-12 step) and add its sha256 as a **Block** IOC first | `IOC-HASH` fires on the **first** run, the alert carries the sha256 and `signed: unsigned` |
| H8 junction swap | In Pass B, while ST-12/ST-02 suspends `Downloads\x\kestrel-unsigned.exe`, replace `Downloads\x` with a junction to `C:\Windows` (`cmd /c rmdir x & mklink /J x C:\Windows`) | Quarantine fails with "resolves to … (redirected by a link)" or "junction"; nothing under `C:\Windows` changes |
| H8 restore | Quarantine a file from Downloads, replace `Downloads` subfolder with a junction, then **Restore** in the console | Restore refused ("junction / symbolic link" or "owner changed"); restoring into `C:\Program Files\…` is always refused |
| H9 AppLocker + GPO | Join a test domain (or `gpedit.msc` → AppLocker on a *GPO*), create an Exe allowlist, then set `block_mshta` = Enforce | Device hardening note: `skipped: domain policy present`; `Get-AppLockerPolicy -Local -Xml` contains no Kestrel allow rule. Without any policy, Kestrel writes the three default rules (Program Files, Windows, Administrators), never `*` for Everyone |
| H10 roaming | Isolate the host, then change the VM's adapter DNS server (`Set-DnsClientServerAddress`) | Within ~1 min the agent log shows "re-planned"; the device stays online |
| H10 break-glass | Isolate, disconnect the server, then as admin: `& 'C:\Program Files\Kestrel\kestrel-agent.exe' release-isolation --token <uninstall token>` | "network isolation released locally"; network works; the service does not re-apply the filters |
| H10 auto-release | Set `isolation_auto_release_hours` = 1 in the policy, isolate, stop the server for > 1 h | The agent releases isolation and the tray shows "Network access restored automatically" |
| M3 tray | Log on a second user (RDP / fast user switching) and open the tray | Each user sees only their own alerts plus machine-wide items; a review request for another user's alert says "unknown alert"; a 6th review request within an hour is refused; a second Quick check within 5 min returns the previous result |
| M5 / M6 | Search the MSI log (`/l*v`) and the Hunt view (`cmdline ~ "TOKEN="`) | No enrollment / uninstall token values anywhere (`[redacted]`) |
| H3 renewal | Server: issue the device a certificate with < 30 days left (or send `RenewCertificate` from the server) | Agent log: "client certificate renewal requested" → "renewed client certificate installed" → reconnect → "confirmed"; `keys\agent.crt` changed |

### Atomic Red Team cross-reference

Use [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) for a second, independent opinion. List tests with `Invoke-AtomicTest <id> -ShowDetailsBrief`, check them with `-CheckPrereqs`, and clean up with `-Cleanup`. Some tests run real credential dumpers such as LaZagne and WebBrowserPassView, so use dummy browser data only.

| Technique | What it exercises |
|---|---|
| T1555.003 Credentials from Web Browsers | ST-01, ST-02, ST-03, ST-04 (and ST-09 for Firefox tests) |
| T1539 Steal Web Session Cookie | ST-01/02 (cookie stores), ST-05/06 (DevTools-based tests) |
| T1185 Browser Session Hijacking | ST-05, ST-06 |
| T1204.004 Malicious Copy and Paste (ClickFix) | ST-10, ST-11 |
| T1059.001 PowerShell (download cradles) | ST-11 when launched from explorer/Run |
| T1218.005 Mshta | ST-11; hardening `block_mshta` |
| T1127.001 MSBuild | ST-13 |
| T1102 / T1567 Web Service / Exfiltration Over Web Service | ST-14, ST-04 |
| T1055 Process Injection (against a browser target) | ST-07 |
| T1562.006 Indicator Blocking (ETW) | TP-01 |
| T1562.001 Impair Defenses (AMSI) | TP-03 |
| T1562.004 Disable or Modify System Firewall | TP-02 (only non-Windows-Firewall WFP filters) |

## 4. What to measure

Record these numbers on both Pro and Enterprise if you can, and for both an idle VM and a busy one:

| Metric | How |
|---|---|
| Agent CPU / memory | Device page (Agent CPU, memory). `Get-Counter '\Process(kestrel-agent)\% Processor Time','\Process(kestrel-agent)\Working Set - Private' -SampleInterval 5 -MaxSamples 120` |
| ETW events lost / buffers lost | Device page (Events lost, 1 h). `logman query Kestrel-Core -ets` and `logman query Kestrel-IO -ets` (Events Lost, Buffers Lost). `kestrel-agent status` |
| Event rate | Device page events/min; Hunt `device_id = <id>` over 1 h |
| Detection latency | Alert `ts` minus the emulation's process start (both in the incident timeline) |
| Containment latency (ST-04) | Bytes sent before the kill: the Network tab / storyline "N bytes sent" |
| Suspend impact | Time a password-manager import or backup tool stalls when ST-01 is in Protect (it should be about `suspend_window_ms`) |
| Outbox | Disconnect the network for 10 minutes while active; outbox depth grows; after reconnect it drains, and Hunt shows events from the offline window |
| Load test | Run `git clone` of a large repo, a full Defender scan, `robocopy` of 50k small files, and browser use at the same time. Watch Kestrel-IO events lost and CPU |

Good targets for v1 are idle CPU under 1%, busy CPU under 5%, working set under 150 MB, and no events lost on Kestrel-Core under normal use.

### Sensor fixes of 2026-10-22 (owner-PC triage): what to verify

Run these in the VM with the agent installed (Audit policy), Docker Desktop running (it starts `docker-*.exe` CLI plugins every few seconds that read `%USERPROFILE%\.docker\config.json`) and a Rust toolchain plus VS Build Tools installed.

1. **PID-reuse attribution under a parallel build.**
   * Clone any large Rust workspace (or this repo) and run `cargo build -j 8` (then `cargo clippy --all-targets`) three times in a row while Docker Desktop is up.
   * *Pass:* no ST-01 "read Docker registry credentials" alert names `rustc.exe`, `cargo.exe`, `clippy-driver.exe`, `build-script-build.exe`, `cl.exe`, `link.exe`, `lib.exe`, `conhost.exe` or `wsl.exe`. A `docker-*.exe` / `com.docker.*` reader may still appear (that is the detection team's allow-list question, not attribution).
   * *Also check:* `kestrel-agent` log line "sensor health" every 5 min: `pid_reuse_dropped` (events whose pid was reused and whose owner at the event time was unknown; expected small, not growing without bound) and `file_prefiltered` (large during a build).
   * *Positive control:* from a labsim-style unsigned test binary, read the dummy `.docker\config.json` while the build runs; the ST-01 alert must name the test binary.
2. **Events lost during a large build.**
   * Before and during the build: `logman query Kestrel-File -ets`, `logman query Kestrel-Core -ets` (Buffer Size, Buffers Written, Events Lost, number of buffers; the pool may now grow from the minimum to the maximum in `kestrel_win::consts::buffers`: Core 32 to 256, File 64 to 512, IO 128 to 256 buffers of 64 KB).
   * Device page / heartbeat: `etw_events_lost` should stay 0, and if not, `etw_kernel_events_lost` (ETW buffers full) and `sensor_internal_dropped` (Kestrel's own queues) say which side lost them. Record both with the build's duration.
   * Record the agent's nonpaged-pool use during the build (`poolmon` or Task Manager > Performance > Memory > Non-paged pool before/after): the worst case is +46 MB over the old fixed plan, and it should return to about 15 MB for the sessions when idle.
3. **Store app signer.**
   * Install WhatsApp (or any Store app with an `.exe`, e.g. Windows Terminal) from the Microsoft Store and start it.
   * *Pass:* its ProcessStart in Hunt shows `signed: valid` and a signer. For Store-signed third-party packages the certificate subject is the Store publisher id (e.g. `24803D75-212C-471A-BC57-9EF86AB91435` for WhatsApp), not the company name; Microsoft's own packages show `Microsoft Corporation`. An app sideloaded with a self-signed certificate stays `unsigned` (catalog chain not trusted), never `valid`.
   * Developer check without a VM (read-only): `$env:KESTREL_TEST_MSIX_EXE='<path of a packaged .exe>'; cargo test -p kestrel-win --lib msix_packaged_exe` (verified on the owner PC with WhatsApp.Root.exe: Valid, source PackageCatalog).

## 5. Known risks in the Windows layer (check these first)

These parts of `kestrel-win` are implemented from documentation and manifests but have not yet been proven on real hardware. Each one has a specific check.

1. **Kernel-File volume.**
   * *Risk:* Kernel-File Create is enabled system-wide on `Kestrel-IO`. Every file open crosses the ETW buffer before the user-mode sensitivity filter drops it. Heavy I/O (builds, AV scans, indexing) can cause CPU spikes and lost buffers. Read events are **off** (`FILE_READ_EVENTS = false`), so rules key on the open, and a stealer reading through an already-open handle is not seen as a separate read.
   * *Second risk:* NT device paths (`\Device\HarddiskVolumeN`) are mapped with a table built at start. Volumes mounted later (USB, VHD, BitLocker unlock) may be unmapped, so path rules miss.
   * *Check:* run the §4 load test and watch Kestrel-IO events lost and CPU. Mount a VHD, copy a dummy `Login Data` onto it, read it from labsim, and confirm the timeline path starts with a drive letter.
2. **Registry KeyName resolution.**
   * *Risk:* Kernel-Registry `SetValueKey` reports `KeyName`. The code only normalises full `\REGISTRY\MACHINE\…` and `\REGISTRY\USER\…` names and then matches substrings such as `\currentversion\explorer\runmru`. If Windows delivers a relative or handle-based name, ST-10, TP-03 and TP-04 silently miss.
   * *Check:* after the ST-10 step, the device timeline must show a `Registry set` event with key `HKU\S-1-5-21-…\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`. Do the same check for the TP-03 and TP-04 HKLM keys.
3. **Network byte order.**
   * *Risk:* Kernel-Network `daddr` and `dport` are decoded as network byte order (big-endian), and WFP conditions are built in host order. If either assumption is wrong, the following happen:
     * IPs appear reversed, for example `34.216.184.93` instead of `93.184.216.34`
     * ports appear swapped, for example `47873` instead of `443`
     * ST-04, ST-06, ST-13 and ST-14 matching breaks
     * blocks hit the wrong address
   * *Check:* run `Test-NetConnection example.com -Port 443` and compare the timeline's Network connect IP and port with `Resolve-DnsName example.com`. Then issue **Block destination** for that IP and confirm the connection now fails.
4. **DPAPI event 16385 without the debug channel.**
   * *Risk:* Crypto-DPAPI 16385 (SPCryptUnprotect, with `DataDescription` and `CallerProcessID`) is a Debug-channel event. Its fields come from Google's 2024 write-up, and the build-18990 manifest predates the event. The real-time session enables the provider with all keywords, but it is unverified whether events flow when the `Microsoft-Windows-Crypto-DPAPI/Debug` channel is **disabled**.
   * *Check:* run the ST-03 emulation twice, once with Hardening → DPAPI audit channel set to Enforce, and once with it Off plus `wevtutil sl Microsoft-Windows-Crypto-DPAPI/Debug /e:false`. If ST-03 only fires with the channel on, keep it enforced. If it never fires, ST-01, ST-02 and ST-04 still cover the theft.
5. **AppLocker edition limits.**
   * *Risk:* the `block_mshta` and `block_user_path_exec` controls write the local AppLocker policy (Exe collection only) and rely on the Application Identity service (`AppIDSvc`). They are skipped entirely (`skipped: domain policy present`) when the effective policy contains GPO / MDM rules, and on a machine with no policy at all they enable the Exe collection with the standard default rules (Program Files, Windows, Administrators), which also blocks per-user installs in AppData for standard users. Windows Home has no AppLocker. Microsoft's support for AppLocker *enforcement* on Pro has changed between releases. The agent's "in effect" check only confirms that the effective policy contains Kestrel's rules and that AppIDSvc is running. It cannot tell whether the edition actually enforces them.
   * *Check:* set Hardening to **Enforce**, then as a standard user run `mshta.exe about:blank` and an exe copied into Downloads. Both should be blocked. Check *Event Viewer → AppLocker → EXE and DLL* (events 8004). Compare Pro and Enterprise and record the results.

Other things to watch:

* **First-start enrichment.** The first `process_start` of a new image is held for up to 750 ms while a priority worker computes its signature and (for files ≤ 100 MB) its sha256. If that budget is exceeded the event carries `signed: unknown`, which the engine never trusts; the facts reach the engine later and hash IOCs, ST-12 and ST-08(b) are evaluated again. Watch for unusual process-start latency under heavy I/O.
* **Revocation.** Images in user-writable locations are verified with whole-chain revocation checking (cache-only first, then an online check on a background worker with a 20 s timeout). On an offline VM, revocation stays unknown and the signature counts as valid.
* **Short-lived processes.** The command line comes from the callback or from the `Kestrel-ProcCmd` session. Check that `cmd /c echo hi` shows a command line in the timeline.
* **ETW session conflicts.** Other EDR or performance tools that stop all sessions trigger TP-01. Check coexistence with Defender (it is fine) and with any other EDR you deploy.
* **Uninstall token.** The token comes from the server at enrollment and is shown on the device page. If the server is too old to issue one, the agent writes a locally generated token to `C:\ProgramData\Kestrel\uninstall-token.txt` (administrators only) instead of printing it. To check rotation, click **Rotate** on the device page while the agent is online: within seconds the pending marker disappears, `kestrel-agent release-isolation --token <old>` (elevated) reports `invalid uninstall token`, and the new token is accepted.

## 6. Clean up

1. Run `msiexec /x KestrelAgent.msi /qn UNINSTALL_TOKEN=<token from the device page>`.
2. Check that nothing is left behind:
   * the `KestrelAgent` service is gone
   * `logman query -ets` shows no Kestrel sessions
   * no Kestrel WFP filters remain (`netsh wfp show filters` and search for "Kestrel")
   * the host is not isolated
3. Revert the VM snapshot.
