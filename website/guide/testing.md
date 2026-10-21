# Testing safely

::: danger Never on a daily-use PC
Kestrel kills processes, quarantines files, installs WFP filters that can cut network access, edits AppLocker, plants decoy files in user profiles and installs a SYSTEM service with a locked-down DACL. Install and test it only in a disposable VM that you can revert. Never run real malware; use the benign emulations below, inside the VM only.
:::

## What is safe where

| Activity | Your workstation | Disposable VM |
|---|---|---|
| Build, unit tests, clippy, fmt | yes | yes |
| Server in Docker, console and tray in dev or mock mode | yes | yes |
| `kestrel-agent simulate` (replays recorded telemetry, touches nothing real) | yes | yes |
| `scripts/windows-smoke.ps1` and `kestrel-agent sensors-test` (read-only ETW, elevated) | yes | yes |
| `scripts/e2e.sh` (real server, simulated agents) | yes (Linux or WSL2) | yes |
| Installing the MSI or service, `kestrel-agent run` or `install` | **no** | yes |
| Hardening in Enforce, isolation, quarantine, kill, emulations | **no** | yes |

## Without Windows: the end-to-end test

`scripts/e2e.sh` runs the real server and the real agent core in simulator mode on Linux or WSL2. Three simulated endpoints replay recorded attacks (Lumma ClickFix, Vidar smash-and-grab, a benign workday) from `crates/kestrel-agent/replays/*.jsonl`. The script then checks incidents, data at risk, response-action delivery, the audit chain, hunting and remote access through the REST API. See [Build from source](../build/#_9-linux-and-wsl2-builds-end-to-end-test).

To replay one recording against any server:

```bash
cargo run -p kestrel-agent -- --state-dir ./simstate simulate \
  --server 127.0.0.1:18444 --server-name localhost --ca ca.pem --token kte_... \
  --replay crates/kestrel-agent/replays/lumma_clickfix.jsonl --exit-after-replay 10
```

Get `ca.pem` from the `ca_pem` field of `GET /api/agent/installer`. `--server-name` must be one of the names in `KESTREL_PUBLIC_HOSTNAME`.

## The disposable Windows lab (`scripts/vm`)

On a Windows 11 Home workstation there is no Hyper-V Manager or Windows Sandbox, so the repository scripts a QEMU/KVM Windows 11 guest inside WSL2 (any Linux host with `/dev/kvm` also works). On Windows Pro or Enterprise you can use Windows Sandbox or a Hyper-V VM with checkpoints instead.

| Script | What it does |
|---|---|
| `scripts/vm/vm.sh install` | Unattended install of Windows 11 Enterprise **Evaluation** from `~/kestrel-vm/win11.iso` (90-day evaluation from the Microsoft Evaluation Center). Creates the admin `labadmin` (SSH key auth) and the standard user `employee` (automatic sign-in), then takes snapshot `clean`. |
| `vm.sh start`, `stop`, `snapshot NAME`, `revert NAME` | Lifecycle and qcow2 snapshots. `stop` shuts Windows down cleanly; a hard kill can leave a disk that does not boot. |
| `vm.sh ssh`, `put`, `get`, `screenshot`, `wait-ssh` | PowerShell over SSH, file copy, a PNG of the guest display. |
| `scripts/vm/api.sh login`, `get`, `post`, `put` | Minimal REST client (session cookie and CSRF) for tokens, policies, alerts and hunting. |
| `scripts/vm/emulate.ps1` | Benign emulations, one per rule (below). |
| `scripts/vm/emulate-cmd.cmd <id>` | Command-line emulations used by `emulate.ps1`. |

Settings come from environment variables: `KVM_DIR` (default `~/kestrel-vm`), `SSH_PORT` (2222), `CPUS` (4), `MEM` (8192). Inside the guest the host is `10.0.2.2`, so `KESTREL_PUBLIC_HOSTNAME` must include `10.0.2.2` for a server running in WSL2 or Docker Desktop.

A typical run:

```bash
scripts/vm/vm.sh install              # once
scripts/vm/vm.sh start && scripts/vm/vm.sh wait-ssh
scripts/vm/vm.sh put KestrelAgent.msi 'C:/kestrel-lab/KestrelAgent.msi'
scripts/vm/vm.sh ssh                  # install the agent, then run emulate.ps1
scripts/vm/vm.sh stop && scripts/vm/vm.sh revert clean
```

Take a snapshot before installing the agent, and again after.

## Benign emulations

`emulate.ps1` never runs malware. The "stealer" is `labsim.exe`, a copy of PowerShell in `%LOCALAPPDATA%\KestrelLab` that reads dummy browser data; "ransomware" steps XOR-rename a seeded set of lab files; "credential dumping" steps target Notepad or only open LSASS with query and read rights; persistence steps point at lab binaries and are removed by `-Cleanup`.

```powershell
.\emulate.ps1 -Setup           # lab folder, labsim.exe, an unsigned test exe, dummy Edge profile data
.\emulate.ps1 -Id ST-02        # one emulation, with START/END markers
.\emulate.ps1 -Id all-audit    # every emulation in sequence
.\emulate.ps1 -Cleanup         # remove lab persistence and settings
```

| Ids | What the emulation does |
|---|---|
| ST-01, ST-02, ST-04 | labsim reads Edge `Login Data` (ST-01); reads passwords, cookies, autofill and a dummy wallet within 60 s (ST-02); reads `Login Data` then posts to example.com (ST-04) |
| ST-05, ST-06, ST-07 | starts headless Edge with a remote-debugging port (ST-05), queries the DevTools port (ST-06), opens Edge with memory-read rights (ST-07) |
| ST-11, ST-12, ST-14, ST-16 | `nslookup` against a hard-coded resolver from cmd (ST-11), runs an unsigned exe from Downloads (ST-12), looks up and contacts `api.telegram.org` (ST-14), reads a decoy `Login Data` (ST-16) |
| RW-01, RW-02, RW-04, RW-05 | `vssadmin delete shadows`, `bcdedit` recovery off and back on, `wevtutil cl`, `sc stop` of backup and database services |
| RW-06, RW-07, RW-08 | XOR-renames seeded `.docx` files, touches a ransomware decoy, writes ransom-note files into six folders |
| CD-01, CD-03, CD-07, CD-10, CD-12 | comsvcs MiniDump of **Notepad**, opens LSASS with query and read rights, SilentProcessExit key for lsass, `reg save HKLM\SAM`, WDigest `UseLogonCredential = 1` |
| PS-01 to PS-03, PS-05, PS-07 to PS-11 | Run key to an unsigned exe, Run key with hidden PowerShell, Startup-folder script, scheduled task, service, WMI subscription, IFEO debugger, Winlogon `Userinit`, COM hijack in HKCU |
| TP-01, TP-03, TP-04 | `logman stop Kestrel-IO -ets`, AMSI `FeatureBits`, a value under the agent's service key |

Run two passes:

* **Pass A (detection):** set every rule to Audit in the policy (including the Protect defaults) and run `-Id all-audit`. Check that each rule fires.
* **Pass B (containment):** restore the defaults and repeat the Protect rules. Check kill, quarantine, network block and isolation on the incident page, then clean up with **Release host**, **Restore** and **Lift network block**.

Containment persists by design: image blocks from Pass B stop the network parts of the next Pass A (ST-04, ST-06, ST-14) until you lift them.

Some rules have no safe one-line emulation (for example ST-15, a trusted-binary sideload) and are covered by unit tests and fixtures. Atomic Red Team tests are a useful second opinion inside the VM; some of them run real credential tools, so use dummy browser data only.

## Response checks in the VM

* Kill, quarantine and restore from the console.
* Block a destination and confirm `Test-NetConnection <ip> -Port 443` fails.
* Isolate the host: `Test-NetConnection example.com -Port 443` fails while the device stays online in the console; then **Release host**.
* Break-glass: isolate, stop the server, then `kestrel-agent release-isolation --token <uninstall token>` as administrator.
* Self-protection: `sc.exe stop KestrelAgent` must fail with access denied, and `kestrel-agent uninstall --token wrong` must be refused.
* Disconnect the VM's network, issue an action, reconnect, and check that it reaches `succeeded`.

## Clean up

1. `msiexec /x KestrelAgent.msi /qn UNINSTALL_TOKEN=<token from the device page>`
2. Check that the `KestrelAgent` service is gone, `logman query -ets` shows no Kestrel sessions, `netsh wfp show filters` has no Kestrel filters, and the host is not isolated.
3. Revert the VM snapshot.

The full lab plan with expected rule ids per step is in `docs/TESTING-ON-WINDOWS.md` in the repository.
