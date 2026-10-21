# Handoff — state of Kestrel EDR v1.1.0-rc1 (2026-10-21)

Read `CLAUDE.md` first. This run took Kestrel from "compiled and simulated" to "validated on real Windows, broader malware coverage, release candidate". Decisions with reasons are in `docs/DECISIONS.md`; the security reviews are `docs/security-review-2026-10-21.md` (v1.0) and `docs/security-review-v1.1-2026-10-21.md` (v1.1, independent).

## Remote access run (2026-10-21, after v1.1.0-rc1) — remote desktop, file manager, install profiles

**What was added.** Admin-only remote desktop and a remote file manager, chosen per install through remote-access profiles. Not committed yet; owner reviews first.
* **Profiles and ceiling:**
  * Enrollment tokens carry a `RemoteAccessProfile`: *none*, *unrestricted* or *guarded*, all customisable.
  * The agent pins the profile at enrollment as a ceiling that the server can never raise.
  * The effective profile is `ceiling ∩ policy`, and the agent enforces it.
  * Existing devices and policies default to **none**.
  * The console has an **Install agent** wizard (Devices page / Settings → Enrollment). It produces a token plus a one-time `Install-Kestrel-<profile>.cmd`: self-elevating, downloads the MSI into an admin-only folder, pins its SHA-256, runs msiexec.
* **Guardrails:** employee consent via the tray (Allow/Deny, deny on timeout or no user), reason, MFA re-auth (`POST /me/reauth`, 10 min), upload / delete (overwrite counts as delete), session and idle limits, allowed hours (device local time), blocked paths.
* **Always on, in every profile:** the on-screen banner and the tray notification.
* **Remote desktop:**
  * A SYSTEM helper runs in the console session (`kestrel-agent desktop-helper`), started from the agent's own token with `TokenSessionId` set and placed in a kill-on-close job object. It talks to the agent over a SYSTEM-only pipe with PID checks both ways.
  * Capture is GDI with JPEG, sending only changed frames, with at most 3 frames in flight.
  * Input uses `SendInput` with scan codes. Input-desktop switches (UAC, lock screen) are followed.
  * The banner is topmost, click-through and cannot be closed.
  * Switching view-only → control asks for consent again.
* **File manager:**
  * Runs as SYSTEM; paths must be `X:\…` only.
  * Every operation is handle-based and never follows links on Windows (`kestrel-win/src/win/hardfs.rs`). The guard sees the final path of the handle that is acted on.
  * Kestrel's own folders and their ancestors are protected, and so are blocked paths and their ancestors. Network / device final paths are refused.
  * Uploads go through a temp file plus a SHA-256 check and an atomic rename. Downloads stream from the agent.
  * RedirectionGuard is enabled for the agent process (Windows 11 22H2+). Side effect: hashing and signature facts for files behind junctions created by non-admin users show as unknown.
* **Server:** REST `/devices/:id/files…`, WebSocket `/devices/:id/remote-desktop` (Origin + CSRF + session checks, revalidated every 60 s), live hub with size caps, every operation and consent result in the hash-chained audit log (audit is written even when the client aborts).
* **Privileges:** `remote.desktop` / `remote.files` (admin only) and interactive session only (API tokens 403).
* **Console and tray:**
  * Console: device tabs Remote desktop and Files, a remote-access summary (ceiling / policy / effective), a policy editor section, and mock support.
  * Tray: an "IT is connected" banner and the consent prompt. Allow is armed only after 1 s; Escape = Deny.
* **Contracts:** `kestrel_common::remote`, the Live payloads, `Hello.capabilities` / `remote_ceiling`, `AgentHealth.remote_ceiling` / `remote_effective`, `EnrollResponse.remote_profile`, tray `SubscribeWith` / `ConsentRequest` / `ConsentResponse` / `RemoteSession`. Documented in `docs/contracts.md` "Remote access" and `docs/ARCHITECTURE.md`.
* **New dependency:** `jpeg-encoder` 0.7.1 (MIT/Apache + IJG; `IJG` added to `deny.toml`, notice in the README).

**Security review.**
* An independent hostile review of this feature found 3 High, 7 Medium, 9 Low and 5 Info:
  * H1: TOCTOU junction swap during delete / rename / upload;
  * H2: view-only silently switched to control;
  * H3: audit skipped by aborting the request;
  * M1–M6: consent reuse across admins, self-approval via injected input, symlink to UNC, blocked-path ancestor rename, live-message memory exhaustion, installer MSI swap in a user-writable folder.
* All High and Medium findings are fixed with regression tests. M7 ("full file manager with upload ≈ SYSTEM code execution", so soft guardrails are no hard boundary) is documented in contracts and in the console.
* Lows fixed: L1–L3, L5, L6, L8, L9.

**Verification (final code).**

| Check | Where | Result |
|---|---|---|
| `cargo fmt --all -- --check` | Windows | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | Windows | PASS |
| `cargo test --workspace` incl. Postgres integration tests (new `tests/remote_access.rs`) | Windows | PASS — 42 suites, 657 tests, 0 failed |
| `kestrel-win` pure tests + junction tests (temp dirs only) | Windows | PASS — 170 |
| Console `npm test` / `lint` / `build` | Windows | PASS — 149 tests |
| Tray `npm test` / `build`, Rust fmt / clippy / tests (incl. contract round-trip) | Windows | PASS — 62 + 18 |
| `scripts/e2e.sh` (real server + 4 simulated agents; new remote section: profile token, ceiling `none` refusal, reason required, upload/download SHA-256, rename/delete/mkdir, protected + blocked paths, desktop WebSocket with consent, frames, input and stop, foreign Origin refused, audit rows, no file data in logs) | WSL2 Kali | PASS — 64/64 |
| Console screenshots (mock), light + dark: `docs/screenshots/remote-desktop-*`, `remote-files-*`, `remote-summary-*`, `installer-step{1,2,3}-*` | Windows (Edge, Playwright) | PASS, inspected |
| Real screen capture / input / banner / helper spawn | — | **NOT RUN** (never on the owner's PC; lab VM) |

**Lab VM checklist for the owner.** Everything Win32 in the desktop path, and the handle-based file manager under SYSTEM, is unit-tested only. Run with an agent installed from an *unrestricted* and a *guarded* token.
1. **Session start:** start from the console → `kestrel-agent.exe desktop-helper` runs as SYSTEM in session 1, the banner shows the admin and reason, frames arrive. Guarded: the tray prompt appears, and Deny / timeout refuse.
2. **View-only switch:** view-only → control asks again (guarded); the banner text changes; held keys are released when switching back.
3. **Input:** mouse incl. X1/X2, wheel and horizontal wheel; arrows, Delete, NumpadEnter, Win, AltGr; paste text with emoji / line breaks.
4. **UAC prompt:** frames show the secure desktop (`secure_desktop: true`); clicking Yes works; the banner is absent while it is up.
5. **Lock and log-off:** Win+L, then type the password; log-off or switch user ends the session.
6. **Display setups:** two monitors (one left of / above the primary); 150 % and 200 % scaling.
7. **Ctrl+Alt+Del:** test with and without `SoftwareSASGeneration` = 1.
8. **Process lifetime:** killing the agent makes the helper and banner vanish; killing the helper makes the console see `ended`; Disconnect leaves no stuck keys.
9. **Load:** 4K at quality 90 / 15 fps keeps frames < 1 MiB with sane CPU.
10. **Drive list:** empty DVD drive / card reader, a mapped network drive (hidden) and a SUBST drive.
11. **Protected and blocked folders:** `Program Files\Kestrel` and `ProgramData\Kestrel` are refused, and so are their parents for rename / delete. A blocked path refuses its parents too.
12. **Junction swap:** as a standard user, create a junction inside a folder the admin deletes, then swap a subfolder for a junction mid-delete (oplock tool). Only the link is removed and nothing outside the folder is touched. Plant a symlink to `\??\UNC\host\share` and confirm the open is refused with no outbound SMB.
13. **RedirectionGuard:** on 22H2+ it is active (`Get-ProcessMitigation -Name kestrel-agent.exe`); check that enrichment of images behind user junctions only degrades to unknown.
14. **Installer script:** `Install-Kestrel-guarded.cmd` from the wizard on a clean VM elevates, the folder ACL is SYSTEM + Administrators only, the hash is checked, the install succeeds, and the device shows that ceiling.
15. **Reinstall:** reinstall with a different profile only after uninstall (with the token). The same server + CA keeps the old identity and ceiling.

**Residual risks (remote access).**
* **Full file manager is SYSTEM code execution.** A malicious admin with *full* files + upload can rewrite the agent's config and widen the ceiling, so hours, blocked paths and consent are soft against them. The hard boundaries are the install ceiling (`none` / view-only / read-only) and admin MFA.
* **Listing race:** folder listing still enumerates by path after a handle check (`verify_dir`). A racing swap can only reveal names and sizes elsewhere; reads and writes are handle-based. Fix: a `RemoteFs::list_dir` hook.
* **Hard links:** reading a protected file through a hard link the reader could already write is not detected (low).
* **Allowed hours** use the device's local time zone, which a standard user can change.
* **Desktop idle timeout** is enforced by the server only; the agent enforces max duration and 90 s server silence.
* **The ceiling does not cover older response actions** (kill, quarantine, isolate, triage), which remain governed by RBAC.
* **The desktop WebSocket takes the CSRF token in the query string** (may appear in reverse-proxy access logs). The session cookie is SameSite=Strict and Origin is checked.
* **The enrollment token is on the msiexec command line** in the generated script (same as `install_command`).
* **The banner cannot appear on the secure desktop** (UAC / lock); the tray notification still does.
* **The mouse pointer is not drawn into frames**, and there is no clipboard or audio.

**Decisions log.** The integration choices (one live channel, capability flags in `Hello`, interactive session only, server + agent checks, network paths refused, protected-folder rules, tray opt-in features, `jpeg-encoder` + IJG) still need entries in `docs/DECISIONS.md` (owned by the coordinator).

## What changed in the v1.1 run

**Windows for real.** Toolchain installed (Rust 1.99 MSVC, VS 2022 Build Tools, protoc, .NET 8 + WiX 6.0.2, Docker Desktop already present). Native build/test/clippy/fmt green; MSI, tray (Tauri MSI/NSIS) and the Docker image build. The agent now runs on a **clean** Windows 11 (static CRT — it needed `VCRUNTIME140.dll` before).

**Disposable lab VM.** The host is Windows 11 *Home* (no Hyper-V Manager / Windows Sandbox), so the lab is a QEMU/KVM Windows 11 Enterprise Evaluation guest inside WSL2 (`scripts/vm/`, documented in `docs/TESTING-ON-WINDOWS.md`). Everything destructive ran there, never on the host.

**Real-Windows bugs found and fixed** (all have regression tests):
* Kernel-Registry `SetValueKey` has an **empty `KeyName`** on Win11 (known risk 2): new `RegNotifyChangeKeyValue` watcher + ETW join for the writer; attribution exact/heuristic/none.
* An event with a **NUL character** (real command lines) made PostgreSQL reject the batch and the agent re-sent it forever → all later alerts stuck (attacker-triggerable). Server strips NULs and dead-letters data errors; agent strips NULs.
* Cross-session ETW ordering: file events overtook `ProcessStart` → alerts on an empty placeholder process. Translator holds early pids.
* False positives on a quiet Windows: OneDrive (lsass VM_READ, "terminate" bit), Optimize Drives (`defragsvc`) and MRT reading decoys, Edge/WAM reading the token-broker cache, agent's own hardening PowerShell vs SigmaHQ, Sigma `Signed:'false'` on unverified DLLs, RW-05 on browsers closing their own tree, TP-04 on `KestrelLab*` services.
* File-activity sensor: no second summary for a fast burst (RW-06 never fired), then a summary flood; Startup-folder writes reported as `open` (PS-03 blind).
* Audit-API noise: ~500 OpenProcess events/s (`0x1200`) dropped at the source; NXDOMAIN DNS kept.
* MSI: WiX v6 needed a fixed GUID and cp1252; **M6** reworked (registry hand-off leaked into verbose logs) → native custom-action DLL, tokens on stdin only; upgrades work; the uninstall token can't be skipped with `UPGRADINGPRODUCTCODE`.

**Broader malware coverage (Phase 3).** Research: `docs/research/general-malware-report.md` (+4 notes). New rule families behind a `Family` seam in `kestrel-detect`: **RW-01..08, RW-12** (ransomware), **CD-01..13** (credential dumping), **PS-01..05, 07..11, 15** (persistence, incl. rollback); new sensors (aggregated file activity + ransomware decoys, Task Scheduler / SCM / WMI-Activity, failed lsass opens); `RemoveAutorun` response (vault backup first, allow-list, OS-default restores only); hardening: WDigest off, ASR LSASS, LSA protection (reports "pending reboot", never reboots), driver-blocklist report, TaskScheduler log. **70-rule SigmaHQ Audit pack** (DRL 1.1, author + pinned upstream link shown). Console: rules catalog by family, policy sensors/hardening, incidents/storylines/checklists for the new families.

**Open items closed (Phase 4).** H10 (DNS while isolated: agent image + service SID only), M6 (above), M10 (deleting a Block IOC lifts its WFP blocks), policy version after DB restore (server catch-up, bounded), **signed auto-update with rings** (canary/early/broad, promote/halt, owner-held Ed25519 key, `update-keygen`/`update-sign`), YARA-X moved to `kestrel-scan.exe` (agent 52 MB → ~19 MB), CI Windows job builds the scanner and runs the smoke test.

**Found in the final lab run and fixed:** no console action could lift a network block (a false positive on a business app needed a reinstall) → new `unblock_network` action (device/incident pages, incident checklist item; restoring a quarantined file lifts its blocks); incident titles read "by  on" for unattributed writers; overview chart axis labels clipped.

**Independent security review (Phase 5).** 0 Critical / 10 High / 12 Medium / 18 Low found by a reviewer who wrote none of the code; two fix rounds; a fresh re-review verified the fixes and found 2 regressions that were then fixed. Residuals are listed below.

## Verification matrix (final code, 2026-10-21)

| Check | Where | Result |
|---|---|---|
| `cargo fmt --all -- --check` | Windows | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | Windows (rustc 1.99 MSVC) | PASS |
| `cargo test --workspace` incl. server integration tests on Postgres 16 | Windows | PASS — 41 suites, 559 tests, 0 failed |
| Console `npm test` / `lint` / `build` | Windows | PASS — 93 tests |
| Tray `npm test` / `build`, Rust fmt / clippy / tests, `npm run tauri build` | Windows | PASS — 30 + 8 tests (tray crate formatted and 2 clippy lints fixed this run) |
| Release build: agent 19.5 MB, scanner 18.2 MB, CA DLL | Windows | PASS |
| WiX v6 MSI `KestrelAgent-1.1.0.msi` (13.9 MB) | Windows | PASS |
| `docker compose up -d --build` + first-run setup, `/api/healthz` | Docker Desktop | PASS |
| `scripts/e2e.sh` (real server + 3 simulated agents) | WSL2 Kali | PASS — 40/40 |
| Smoke test + sensor probe (known risks 2–7) | Lab VM | PASS (risk 4: DPAPI events flow without the Debug channel) |
| MSI install, tamper (`sc stop` denied), wrong uninstall token refused, uninstall cleans up, no token in verbose logs | Lab VM | PASS |
| In-place upgrade 0.1.0 → 1.1.0 (same device id, service running) | Lab VM | PASS |
| Pass A, all rules Audit (benign emulations) | Lab VM | 32 built-in rules fired + 7 SigmaHQ rules (see below) |
| Pass B, Protect: ST-02 kill + image block + quarantine; PS-02 removes Run value / tasks with vault backup; RW-06 kills the encryptor tree; CD-01 | Lab VM | PASS |
| Analyst `unblock_network` lifts image blocks (5 filters → server permit only) | Lab VM | PASS |
| Isolation / release from console; break-glass `release-isolation --token` sticks | Lab VM | PASS |
| Tray app in the standard user's session (named pipe to the agent) | Lab VM | PASS — `docs/screenshots/lab-tray-employee.png` |
| Console screenshots against the live server holding lab data, light + dark | Windows (Edge, Playwright) | PASS — `docs/screenshots/lab-*.png`, inspected |
| Performance: idle 0.10 % CPU / 41 MB private; load 0.31 %; 0 events lost | Lab VM (4 vCPU) | PASS |
| GitHub Actions CI | — | NOT RUN (no remote configured) |

**Rules seen firing on real Windows (Pass A + targeted reruns):** ST-01, 02, 04, 05, 06, 11, 12, 14 · RW-01, 02, 04, 05, 06, 12 · CD-01, 06, 07, 10, 12 · PS-01, 02, 03, 05, 07, 08, 09, 10, 11 · TP-01, 02, 03, 04. **Not observed in the lab** (covered by unit tests and fixtures): ST-03 (needs the DPAPI audit channel enabled by hardening), ST-07, ST-08, ST-09, ST-10, ST-13, ST-15, ST-16 (lab harness), RW-03, RW-07, RW-08, CD-02..05, CD-08, CD-09, CD-11, CD-13, PS-04, PS-15, TP-05.

**Lab note:** containment persists by design. Image blocks from Pass B stopped ST-04/ST-06 traffic in the next Pass A until they were lifted with `unblock_network`. Lift blocks (or reinstall) between passes.

## Lab results (QEMU Windows 11 Enterprise Eval 26100, Defender on)

* Smoke test (`scripts/windows-smoke.ps1`): PASS. Sensor probe: risks 2, 3, 6, 7 PASS; risk 4: DPAPI 16385 flows **without** the Debug channel; risk 5 holds.
* Pass A (all rules Audit, 34 benign emulations): see matrix. Idle baseline: 0 alerts in 5 minutes.
* Pass B (Protect): ST-02 killed + network-blocked + quarantined the "stealer"; PS-02 removed the Run value and the hidden-PowerShell tasks (XML backed up).
* Isolation from the console: example.com and DNS blocked, device "isolated", release restores; **break-glass** `release-isolation --token` removed the 15 filters and the service did not re-apply them.
* MSI install (token not in the verbose log), `sc stop` denied, wrong uninstall token refused, `msiexec /x UNINSTALL_TOKEN=…` removes service, ETW sessions, WFP filters and files.
* Performance (4 vCPU): idle 0.10 % CPU, 41 MB private / 62 MB working set; under 20k file writes+reads and 200 process launches 0.31 % CPU; 0 events / buffers lost.

## Things only the owner can do

1. **Code signing.** Defender flags the unsigned agent as `Trojan:Win32/Cryware.B` (heuristic on the credential-store path tables) and quarantines it on install. Sign `kestrel-agent.exe`, `kestrel-scan.exe`, `kestrel_msica.dll`, `kestrel-tray.exe` and the MSI (Azure Artifact Signing — a Singapore entity is eligible; see BUILDING.md), then submit the signed binaries to Microsoft as a false positive (https://www.microsoft.com/wdsi/filesubmission). Until then, deployments need a Defender exclusion for `C:\Program Files\Kestrel` (GPO/Intune). On this PC a Defender exclusion exists only for `D:\project\kestrel\target`, `D:\project\kestrel\tray\src-tauri\target` and `D:\kestrel-build`.
2. **Update signing key.** Run `kestrel-agent update-keygen` on a trusted offline machine, back up the private key, build agents with `KESTREL_UPDATE_PUBKEY`, put the same value in `deploy/.env`. Optionally set `KESTREL_UPDATE_REQUIRE_SIGNED` once MSIs are Authenticode-signed.
3. **CI.** No git remote is configured; nothing was pushed. Add a remote and enable GitHub Actions (`windows-2025` runner runs the smoke test).
4. **Windows Sandbox / Hyper-V** are not available on Windows 11 Home; the QEMU lab replaces them. The Enterprise Evaluation ISO expires 90 days after install — re-run `scripts/vm/vm.sh install` (ISO at `~/kestrel-vm/win11.iso` in WSL Kali).
5. Lab credentials (not in git): console admin `D:\kestrel-build\admin.txt`; VM passwords and SSH key in WSL `~/kestrel-vm/`; `deploy/.env` holds the master key — back it up separately.
6. OIDC login and outgoing notifications (Slack/Teams/SMTP/syslog) are still untested against real endpoints (need the owner's tenants).

## Residual risks (accepted for v1.1, see the v1.1 review)

* User mode cannot prevent: an admin can still stop or blind the agent (TP rules make it loud); BYOVD agent-killers; encryption from another host over SMB is seen as the System process (RW alerts say so, no local kill).
* V-M2 residual: an *administrator* can build an MSI with Kestrel's UpgradeCode to waive the uninstall-token check. Admin-level tamper is out of scope for user mode.
* Registry attribution is a join (exact only for a sole writer); a set-and-revert inside the watcher debounce (50-750 ms) is invisible.
* Decoy names are fixed fleet-wide; RW-07 in-place hits are alert-only.
* Rules not observed in the VM (list in the matrix above) are covered by unit tests and fixtures only; ST-07 and ST-16 emulations in the lab harness did not trigger and need a closer look in the next lab run.
* Automatic image blocks (ST-02/ST-07/ST-16) are permanent until an analyst lifts them (`unblock_network`, or restoring the quarantined file).
* Enrollment/uninstall tokens still appear on the **msiexec** command line typed by the admin (the custom-action hop is fixed); a `TOKEN_FILE=` property would remove that.

## Backlog (next)

P1: AMSI provider DLL; live response with signed scripts; device control (USB); dead-letter API; `agent_spawned` on alert process info; lab coverage for ST-07/ST-16/PS-03 and an upgrade 1.1.0 → 1.1.1 run; performance on low-end hardware with Office/OneDrive workloads. P2/P3 unchanged from the research report (MSP multi-tenancy, NATS, identity integrations, v3 signed driver → MVI).

## Remote access — lab results (Windows 11 VM, 2026-10-21)

| Check | Result |
|---|---|
| Install wizard → `Install-Kestrel-<profile>.cmd` (`/quiet`) downloads, verifies SHA-256, installs, enrolls with the profile | PASS (after fixing the self-signed download and the `pause`) |
| Real uninstall retires the identity, so a reinstall enrolls as a new device with the new ceiling | PASS (after fixing the locked-outbox uninstall failure; a package left half-removed can now be uninstalled) |
| **Unrestricted:** file manager list / 3 MB upload + download (SHA-256 match) / mkdir / rename / recursive delete | PASS |
| **Unrestricted:** remote desktop view (frames in the portal; employee banner "IT (name) is viewing this PC — Reason: …") | PASS |
| **Unrestricted:** control mode (banner switches to "controlling"; clicking Start in the portal opens the Start menu) | PASS |
| Tray shows "IT ended the remote session" | PASS |
| **Guarded:** missing reason refused; upload/mkdir wait for the employee's consent and time out after 60 s; delete/rename refused; `System32\config` blocked; Kestrel folders refused; consent results audited | PASS |
| **None:** every file and desktop operation refused by the install ceiling even though the policy allowed full access | PASS |
| Ceiling AND policy: an Unrestricted device refuses while its policy says off (`disabled_by_policy`) | PASS |

Not yet exercised in the lab: an employee clicking **Allow** on the consent prompt, the UAC secure desktop/lock screen during a session, multi-monitor/DPI, `Ctrl+Alt+Del` (needs the `SoftwareSASGeneration` policy).

**Admin notes:**
* A device needs both an install profile and a policy that allow remote access. Existing policies default to *no remote access*.
* The generated installer uses the first name in `KESTREL_PUBLIC_HOSTNAME`, which must be an address the endpoints can reach.
