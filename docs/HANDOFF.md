# Handoff â€” state of Kestrel EDR v1.1.0-rc1 (2026-10-21)

Read `CLAUDE.md` first. This run took Kestrel from "compiled and simulated" to "validated on real Windows, broader malware coverage, release candidate". Decisions with reasons are in `docs/DECISIONS.md`; the security reviews are `docs/security-review-2026-10-21.md` (v1.0) and `docs/security-review-v1.1-2026-10-21.md` (v1.1, independent).

## Kestrel 1.1.7 (2026-10-25): summary and verification

1.1.7 combines the sections below: readable evidence in the incident view, evidence capture, lower footprint (uploader, ETW pump, tray), the file-manager banner, sensor issuing-thread attribution and `Local State` opens, the detection-quality harness and the detection fix round. The 8.3 short-name prefilter gap from the fix round is closed in `kestrel-win` `filters::may_be_sensitive`. An independent hostile review of the whole 1.1.7 diff found 0 Critical/High, 4 Medium, 3 Low, 2 Info; all are fixed (DECISIONS "Review of the 1.1.7 integration").

| Check | Result |
|---|---|
| `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `cargo test --workspace` on Windows (server against Postgres 16 in Docker) | pass |
| Linux (WSL Kali) tests for common, detect, platform, agent | pass |
| `scripts/e2e.sh` (WSL, real server + simulated agents) | pass, 64/64 |
| Corpus gate: malicious / benign / benign-lookalike | 127/127, 47/47, 16/16; ratchet empty |
| Owner export (5.0 M events), Default policy | 463 alerts, 13 containment actions (was 668 / 549); 0 with the two missing signatures filled in (assumption, DETECTION-QUALITY.md section 8) |
| Console tests / lint / build | pass (247 tests) |
| Tray tests / clippy / build | pass |
| Website build and style check | pass |
| Real Windows (lab VM) | **not run**: no lab VM exists at the moment. 1.1.6 and 1.1.7 are validated by tests and replays only. The owner's own PC runs it audit-only. |

**After 1.1.7 (in `main`, not in a release yet):** the agent starts the tray in signed-in user sessions when the service starts, so the icon comes back right after an install or upgrade (DECISIONS 2026-10-25 "The agent starts the tray"). Lab check: upgrade with a user signed in, and confirm the tray appears without signing out, runs non-elevated under that user, and shows only one icon after the next logon.

**Needs the owner:** rebuild a lab VM (TESTING-ON-WINDOWS.md) and run the lab checklists in the sections below before moving any PC out of audit-only.

## Evidence capture for suspected data theft (2026-10-25) - agent, Windows, server, console

Owner decision and design in `docs/DECISIONS.md` (2026-10-25 "Evidence capture" + review addendum); contract in `docs/contracts.md` "Evidence capture for suspected data theft".

* **Contracts:** `kestrel_common::evidence` (policy, manifest, report, limits, `KEB1` container), `kestrel_common::seal` (`KSE1` streaming AES-256-GCM, feature `seal`), `ResponseAction::{CollectEvidence, DeleteEvidence}`, `AgentPayload::Evidence`, `LiveServerMsg::EvidenceRead` / `LiveAgentMsg::EvidenceData`, `Policy.evidence`, `Settings.retention_days.evidence`, `kestrel_platform::evidence` (`EvidenceHost`, `PacketCapture`, `WriteHint`, `SensorConfig.write_tx`), console types. No tray protocol change (existing notification).
* **Detection / agent:** `kestrel-detect/src/evidence.rs` (bounded journal: written files, credential-store reads, connection tuples; tree membership); `kestrel-agent/src/evidence.rs`, `evidence_bundle.rs`, `sim_evidence.rs`, privacy `scrub_evidence_manifest`. ST-02 / ST-04 → capture (120 s back, 60 s forward) → sealed bundle on the PC → `Ready` report with the filtered manifest; `CollectEvidence` → tray notice → server pulls; `DeleteEvidence`; local retention; per-program / global / disk caps; restart and shutdown handling. Capability `evidence.v1`.
* **Windows:** `kestrel-win/src/evidence_plan.rs` (pure), `win/evidence.rs` (link-safe, oplock-safe source opens, DPAPI key, free space), `win/pktmon.rs` (PktMon capture), `win/writehint.rs` + `win/translate/write_hints.rs` (CreateNewFile-only write hints, never events).
* **Server:** `src/evidence.rs`, `src/api/evidence.rs`, migration `0010_evidence.sql`; pull + verification + re-validation, per-bundle keys wrapped by the master key (crypto-shredding), AES-256 zip downloads (crate `zip` 9.1, `aes-crypto` only; MIT tree), single-use same-session tickets, MFA step-up, audit `evidence.*`, retention, `KESTREL_EVIDENCE_DIR` / `KESTREL_EVIDENCE_MAX_GB`, docker volume `evidence`.
* **Console:** `components/evidence-panel.tsx`, `evidence-dialogs.tsx`, `evidence-policy-editor.tsx`, `lib/evidence.ts`, `mock/evidence.ts`; mounted in `pages/incident.tsx`; policy editor section; Settings retention. Screenshots `website/public/img/console/evidence-{panel,collect,password,policy}-{light,dark}.png`.
* **Docs:** `website/console/evidence.md` (new, sidebar), `website/console/policies.md`, `website/console/settings.md`, `website/guide/privacy.md`, research `docs/research/notes/evidence-pcap.md`.
* **Review:** independent hostile review, 2 High / 7 Medium / 8 Low, all fixed or accepted with reasons (DECISIONS addendum).

**Verification (this PC):**

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `cargo test --workspace` (Postgres 16 in Docker) incl. `kestrel-common` evidence / seal, `kestrel-detect` `tests/evidence.rs`, `kestrel-agent` `evidence_tests`, `kestrel-win` evidence_plan / pktmon planner, `kestrel-server` `tests/evidence.rs` | pass (949 tests) |
| Console tests / lint / build | pass (244 tests) |
| Website `npm run check` / build | pass |

**Needs lab validation (Windows VM, never this PC):**
* A benign stealer emulation (TESTING-ON-WINDOWS.md) that reads browser stores and writes `%TEMP%\x\Passwords.txt` + a zip, then connects out: ST-02 / ST-04 → `capturing` → `ready_on_device` in the console within ~70 s; manifest lists the staged files, secrets read and pcap filters; locked Chrome `Cookies` shows `locked`.
* Kernel-File CreateNewFile (30) hints arrive with the right paths and pids; hint volume during builds in the profile stays low; nothing from hints appears in telemetry / hunt.
* pktmon: real `status` / `filter list` text and exit codes, IPv6 in `-i`, circular 50 MB ETL and `_1.etl` naming, `etl2pcap` duration for 50 MB, a running admin capture → `busy` and untouched, crash of the agent mid-capture → `cleanup_stale` stops it at next start, no filters left behind, Defender / other EDR reaction to PktMon started by the service (SigmaHQ "PktMon.EXE Execution" will alert in SIEMs).
* `open_source`: junction / symlink / hard link / ADS refusals, oplock (BaitAndSwitch-style) returns `locked` without waiting, cloud placeholders refused (OneDrive "always keep on this device" files are lost coverage), the 30 s `CancelSynchronousIo` watchdog interrupts a stuck read, other users' profiles and machine-secret folders never copied.
* DPAPI bundle key created once and reloaded across a service restart; bundles open only on that PC.
* Collect from the console (with MFA step-up): tray notice "IT collected evidence from this PC for a security investigation", upload, `stored`, PC copy deleted; download opens in 7-Zip with the shown password (and not in Windows Explorer, as documented); delete and retention remove the server copy.
## Remove device: remote uninstall (2026-10-22) - server, agent, uninstaller, console

Owner-agreed design; as-built contract in `docs/contracts.md` "Remove device (remote uninstall)", decisions in `docs/DECISIONS.md` (2026-10-22 "Remove device").

* **Console:** device page danger zone "Remove device" (admin, `devices.remove`): purge checkbox (off), typed hostname, comment, MFA step-up via the existing reauth dialog; banners for pending (Cancel removal), removing, failed (Try again), expired, removed (read-only page). Devices list: "Removal pending" / "Removing" / "Removal failed" badges, "Show removed devices" toggle. Disabled with "agent too old" when the agent lacks `agent.uninstall`. Mock mode covers all states. Action statuses `running` / `cancelled`.
* **Server:** `POST/DELETE /api/devices/:id/remove`, `include_removed` on the list, migration 0009 (`capabilities`, `removal_action_id`, `removed_at`, `removed_by`), `crate::removal` (request checks, cancel, outcomes, finalisation after 10 min of silence, certificate revocation 7 days later, undo when a removed PC reconnects, token rotation after a failed removal). Token attached only at delivery (`Command.secret`). Audit `device.remove.{requested,cancelled,started,failed,completed,expired}`.
* **Agent:** `remote_uninstall.rs`: verify token (Argon2id), outcome `uninstall_started`, tray notice, wait for the server's ack, start the detached helper; watch it; report failures (also after an installer rollback via a store marker). Capability `agent.uninstall`. Refused from engine / tray / without the secret.
* **Windows:** `kestrel-win/src/win/uninstall_helper.rs` (private SYSTEM-only copy of `kestrel-uninstall.exe`, detached, breakaway from job, token on stdin).
* **Uninstaller:** `kestrel-uninstall.exe --quiet --token-stdin [--purge]` (no UI, exit codes 0/1/2, result file on failure, self-delete at reboot).
* **Docs:** `website/console/devices.md` (Remove device), `website/deploy/enroll.md` (uninstall options in order), `website/console/settings.md` (privilege), `website/guide/quick-start.md`, README, contracts. Screenshots `website/public/img/console/device-remove-dialog-{light,dark}.png`, `devices-removal-{light,dark}.png`.
* **Review:** independent hostile review: F1 (offline PC marked removed and locked out) and F2 (cancel race) fixed with tests; F3 (token exposed after a failed removal) fixed by automatic rotation; F4 (unreadable token broke Hello) fixed; F5 (no step-up for admins without MFA) accepted as designed, recorded in DECISIONS; F6 comment fixed.

**Verification (this PC, unless noted):**

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `kestrel-server` tests incl. new `tests/device_removal.rs` (3 tests, Postgres 16 in Docker) | pass |
| `kestrel-agent` `remote_uninstall` tests (8) | pass |
| `kestrel-uninstall` tests (19, incl. quiet args, stdin token, result file) | pass |
| `kestrel-common` wire / response tests | pass |
| `kestrel-detect` tests | pass in WSL Kali; on this PC Defender blocks the test executables (os error 225) |
| Console tests / lint / build | pass (189 tests) |
| Website `npm run check` / build | pass |

**Needs lab validation (Windows VM, never this PC):**

* Remove an online VM: tray notice, helper copy under `C:\Windows\SystemTemp\kestrel-remote-uninstall-*` (ACL SYSTEM + Administrators only), the helper survives the service stop, `MsiConfigureProductExW` removes the product, console goes pending â†’ removing â†’ removed after 10 minutes, `--purge` deletes `C:\ProgramData\Kestrel` without following links, helper copy deleted after reboot.
* Offline VM: queue, boot, removal on connect.
* Failure paths: rotate the token while the VM is offline then remove (both tokens sent; must succeed); force a 1618 (another msiexec running) and check the failure outcome with the log path; shut the VM down mid-uninstall and check that a reconnect within 7 days restores the device.
* Token never on a command line (Sysmon 1 / 4688 of the helper and msiexec) and never in the MSI log.
* An older agent (1.1.5) shows "agent too old" and never receives the command.

## Local "turn protection off" switch (2026-10-21) - tray, agent, server, console

Owner request; design and as-built decisions are in `docs/DECISIONS.md` (entry "local turn protection off switch" and its addenda). Contract: `docs/contracts.md` "Local turn-off (tray switch)".

* **Tray:** "Turn off protection" asks for the uninstall token, the mode (detection only; completely off only if the policy allows it) and the duration (15 min, 1 h, 4 h, 8 h capped by policy; "until turned back on" only if allowed). The amber "Protection is off" card has "Turn protection back on" (no token).
* **Agent** (`crates/kestrel-agent/src/pause.rs`):
  * Checks the token with Argon2id. Wrong tokens: 5, then a lockout of 1 min that doubles up to 1 h, per device, persisted.
  * The pause is persisted and auto-resumes, also after downtime. Policy changes end or clamp it.
  * Detection only = engine gate plus agent gate, so no automatic action runs and hardening is not enforced. Full = sensors stopped.
  * Reports: `TP-06` alerts and `AgentPayload::Pause` reports.
* **Engine:** `Engine::set_paused` and output gate; `TP-06` in the catalog.
* **Server:**
  * Device status `paused` (migration 0008) and `pause` in the device API; `protection_off` on alerts.
  * The `resume_protection` action (`response.collect`).
  * Audit entries `device.protection_off`, `device.protection_on`, `device.protection_off_clamped` and `device.protection_off_denied`.
  * `TP-SRV-PAUSE-OVERDUE`. ETW heuristics stay quiet while the device is completely off.
* **Console:**
  * Device banner with the turn-on button.
  * Paused badge and filter.
  * Policy editor "Local turn-off" section.
  * Alert note.
  * Mock data.
* **Docs:** `website/guide/tray.md`, `website/console/devices.md`, `website/console/policies.md`, `website/reference/rules.md`, README, ARCHITECTURE. Screenshots are in `website/public/img/tray/` (turn-off-dialog, turn-off-dialog-full, turn-off-wrong-token, protection-off) and `website/public/img/console/` (device-protection-off, policy-local-turnoff, devices-paused).
* **Review:** an independent hostile review was run and the findings were fixed. The rest are recorded in DECISIONS:
  * the tray verifies the pipe server image before sending the token;
  * `TP-06` fires again when the agent starts while protection is off;
  * a failed sensor restart after a full pause still raises `TP-SRV-ETW`;
  * an overdue pause raises an alert;
  * the lockout escalation survives a clock rollback;
  * the sensor restart check now runs under the lock.

**Verification (this PC):**

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --workspace --all-targets -- -D warnings` | pass |
| `cargo test --workspace` (with Postgres) | pass; new tests in `kestrel-common` `pause`, `kestrel-detect` `tests/pause.rs` + catalog, `kestrel-agent` `pause` + `pause_tests.rs`, `kestrel-server` `tests/local_pause.rs` |
| Console tests / lint / build | pass (177 tests) |
| Tray tests / build | pass (87 tests) |
| `tray/src-tauri` fmt / clippy / test | pass |
| Website `npm run build` (style check) | pass |

**Needs lab validation (Windows VM, never this PC):**

* **Real turn-off over the named pipe.** Includes the new server image check in the tray: `kestrel-tray.exe` must sit next to `kestrel-agent.exe`, and a standard user must be able to `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` the SYSTEM service.
* **Full mode stops the ETW sessions cleanly** without raising `TP-01` or `TP-05`, and they restart on resume.
* **Hardening is not re-applied while off** and is re-applied after turn-on.
* **The pause survives a reboot** and auto-resumes after one.
* **TP-06 shows in the console end to end**, with the audit entries.

## Fresh-install fixes (2026-10-21, after 1.1.2) â€” hidden decoys, "degraded" at install, ST-01 on Widgets

Three findings from a fresh 1.1.2 install in the lab VM. Details and evidence are in `docs/DECISIONS.md` (entry "fresh install of 1.1.2").

1. **Ransomware decoys were visible; RW-07 fired when an employee tidied up.**
   * Decoys are now `FILE_ATTRIBUTE_HIDDEN` (not SYSTEM). The research is in `docs/research/notes/ransomware-decoy-attributes.md`: no family found skips hidden files by default, and LockBit 2.0 handles SYSTEM files differently.
   * Decoys are no longer planted on the Desktop: 3 in Documents, 2 in Pictures.
   * On upgrade:
     * existing decoys that are still exactly Kestrel's get the attribute through the verified handle, without being rewritten;
     * the 1.1.2 Desktop decoys are removed;
     * user-changed decoys are never touched.
   * The decoy poller no longer reports a decoy that *disappeared* as an in-place rewrite blamed on the last opener. It waits for the Kernel-File rename/delete, which names the real actor.
   * Explorer was already protected and alert-only for RW-07. Its alert wording now says it was the signed-in user's file manager.
2. **"Degraded" right after install (`etw_events_lost: 3390`).**
   * Root cause: an internal artefact, not kernel loss.
     * The first server policy always restarted the sensors.
     * On stop, the translator exited before the ETW sessions did. Every event in that gap counted as "dropped".
   * Fixes:
     * producers stop first, then the translator drains (`kestrel-win/src/pump.rs`);
     * shutdown stragglers are counted separately, outside `events_lost`;
     * kernel loss carries over sensor restarts;
     * sensors restart only when what they collect changes.
   * There is no grace period. Real drops are still reported.
3. **ST-01 on Windows Widgets reading the WAM cache.** "Microsoft Windows" (the signer of Windows inbox / WindowsApps components) is now a WAM-client signer under the same constraints. The result is Low / Audit.

4. **Follow-up after the 1.1.3 lab run (same day; details in the DECISIONS addendum):**
   * *Decoy ownership.* A file at a decoy path is armed, hidden or removed only when Kestrel can prove it planted it. Proof is either the hash recorded in `rcanaries.json`, or the content of any released version (`KNOWN_DECOY_SHA256`, append-only).
     * A file with unknown content is never armed or touched; the decoy moves to `â€¦ 2.docx` etc.
     * Legacy decoys are adopted and hidden without being rewritten.
     * Uninstall scans every decoy path of every version in every profile, not only the registry, so lost records no longer leave decoys behind.
   * *PS-07 on Kestrel's own install.* The SCM record of the `KestrelAgent` / `Kestrel EDR Agent` service with the running agent's binary, and the HKLM Run value `KestrelTray` â†’ `kestrel-tray.exe --background` next to the agent, are dropped before any rule.
     * Kestrel's name on another binary, or the agent binary under another name, now alerts.
     * Before this fix, Kestrel's service name on another binary was silent.

**Verification (final code).**

| Check | Where | Result |
|---|---|---|
| `cargo fmt --all -- --check` | Windows | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | Windows | PASS |
| `cargo test --workspace` incl. Postgres integration tests | Windows | Items 1-3: PASS, 710 passed, 0 failed. After item 4: **NOT RE-RUN** â€” the full run was stopped by the host for low memory while still compiling |
| `cargo test --workspace --no-fail-fast` (server DB tests skip without `DATABASE_URL`) | WSL2 Kali | Items 1-3: PASS, 702 passed. After item 4: only `-p kestrel-win --lib rcanary` (13) and `-p kestrel-detect` (all suites) were run, and they PASS. The full run was stopped for low memory |
| Console `npm run lint` / `npm test` (two strings changed) | Windows | PASS â€” 159 tests |
| Agent on a real install (decoy attributes, poller, sensor restart, heartbeat) | â€” | **NOT RUN** (lab VM only) |

**Lab checks for the owner (fresh install of the next build):**
* **Decoys:**
  * `Documents\!Payroll Q3.xlsx` etc. are hidden (`attrib`), and nothing is planted on the Desktop.
  * A VM upgraded from 1.1.2 loses its two Desktop decoys, and its Documents / Pictures decoys become hidden with unchanged mtime.
  * With "show hidden files" on, deleting a decoy in Explorer gives one RW-07 **High** with no action.
* **Events lost:**
  * The device stays **online** after install, with no `TP-SRV-EVENTS-LOST`.
  * The agent log shows `sensors stopped â€¦ discarded_at_stop=` only on a sensor restart.
  * `logman query Kestrel-Core -ets` (and `Kestrel-IO`, `Kestrel-File`) shows Events Lost 0. If the kernel count is non-zero, that is a genuine burst and needs buffer sizing.
* **Widgets:** opening the Widgets board gives at most an ST-01 **Low / Audit**.
* **Follow-up (not done):** decoys are 2â€“13 KB. Clop reportedly skips files up to ~17 KB, so consider â‰¥ 64 KB decoys (this changes their hash, so every installed decoy is rewritten once).

## Remote access run (2026-10-21, after v1.1.0-rc1) â€” remote desktop, file manager, install profiles

**What was added.** Admin-only remote desktop and a remote file manager, chosen per install through remote-access profiles.
* **Profiles and ceiling:**
  * Enrollment tokens carry a `RemoteAccessProfile`: *none*, *unrestricted* or *guarded*, all customisable.
  * The agent pins the profile at enrollment as a ceiling that the server can never raise.
  * The effective profile is `ceiling âˆ© policy`, and the agent enforces it.
  * Existing devices and policies default to **none**.
  * The console has an **Install agent** wizard (Devices page / Settings â†’ Enrollment). It produces a token plus a one-time `Install-Kestrel-<profile>.cmd`: self-elevating, downloads the MSI into an admin-only folder, pins its SHA-256, runs msiexec.
* **Guardrails:** employee consent via the tray (Allow/Deny, deny on timeout or no user), reason, MFA re-auth (`POST /me/reauth`, 10 min), upload / delete (overwrite counts as delete), session and idle limits, allowed hours (device local time), blocked paths.
* **Always on, in every profile:** the on-screen banner and the tray notification.
* **Remote desktop:**
  * A SYSTEM helper runs in the console session (`kestrel-agent desktop-helper`), started from the agent's own token with `TokenSessionId` set and placed in a kill-on-close job object. It talks to the agent over a SYSTEM-only pipe with PID checks both ways.
  * Capture is GDI with JPEG, sending only changed frames, with at most 3 frames in flight.
  * Input uses `SendInput` with scan codes. Input-desktop switches (UAC, lock screen) are followed.
  * The banner is topmost, click-through and cannot be closed.
  * Switching view-only â†’ control asks for consent again.
* **File manager:**
  * Runs as SYSTEM; paths must be `X:\â€¦` only.
  * Every operation is handle-based and never follows links on Windows (`kestrel-win/src/win/hardfs.rs`). The guard sees the final path of the handle that is acted on.
  * Kestrel's own folders and their ancestors are protected, and so are blocked paths and their ancestors. Network / device final paths are refused.
  * Uploads go through a temp file plus a SHA-256 check and an atomic rename. Downloads stream from the agent.
  * RedirectionGuard is enabled for the agent process (Windows 11 22H2+). Side effect: hashing and signature facts for files behind junctions created by non-admin users show as unknown.
* **Server:** REST `/devices/:id/filesâ€¦`, WebSocket `/devices/:id/remote-desktop` (Origin + CSRF + session checks, revalidated every 60 s), live hub with size caps, every operation and consent result in the hash-chained audit log (audit is written even when the client aborts).
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
  * M1â€“M6: consent reuse across admins, self-approval via injected input, symlink to UNC, blocked-path ancestor rename, live-message memory exhaustion, installer MSI swap in a user-writable folder.
* All High and Medium findings are fixed with regression tests. M7 ("full file manager with upload â‰ˆ SYSTEM code execution", so soft guardrails are no hard boundary) is documented in contracts and in the console.
* Lows fixed: L1â€“L3, L5, L6, L8, L9.

**Verification (final code).**

| Check | Where | Result |
|---|---|---|
| `cargo fmt --all -- --check` | Windows | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | Windows | PASS |
| `cargo test --workspace` incl. Postgres integration tests (new `tests/remote_access.rs`) | Windows | PASS â€” 42 suites, 657 tests, 0 failed |
| `kestrel-win` pure tests + junction tests (temp dirs only) | Windows | PASS â€” 170 |
| Console `npm test` / `lint` / `build` | Windows | PASS â€” 149 tests |
| Tray `npm test` / `build`, Rust fmt / clippy / tests (incl. contract round-trip) | Windows | PASS â€” 62 + 18 |
| `scripts/e2e.sh` (real server + 4 simulated agents; new remote section: profile token, ceiling `none` refusal, reason required, upload/download SHA-256, rename/delete/mkdir, protected + blocked paths, desktop WebSocket with consent, frames, input and stop, foreign Origin refused, audit rows, no file data in logs) | WSL2 Kali | PASS â€” 64/64 |
| Console screenshots (mock), light + dark: `docs/screenshots/remote-desktop-*`, `remote-files-*`, `remote-summary-*`, `installer-step{1,2,3}-*` | Windows (Edge, Playwright) | PASS, inspected |
| Real screen capture / input / banner / helper spawn | â€” | **NOT RUN** (never on the owner's PC; lab VM) |

**Lab VM checklist for the owner.** Everything Win32 in the desktop path, and the handle-based file manager under SYSTEM, is unit-tested only. Run with an agent installed from an *unrestricted* and a *guarded* token.
1. **Session start:** start from the console â†’ `kestrel-agent.exe desktop-helper` runs as SYSTEM in session 1, the banner shows the admin and reason, frames arrive. Guarded: the tray prompt appears, and Deny / timeout refuse.
2. **View-only switch:** view-only â†’ control asks again (guarded); the banner text changes; held keys are released when switching back.
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

**Windows for real.** Toolchain installed (Rust 1.99 MSVC, VS 2022 Build Tools, protoc, .NET 8 + WiX 6.0.2, Docker Desktop already present). Native build/test/clippy/fmt green; MSI, tray (Tauri MSI/NSIS) and the Docker image build. The agent now runs on a **clean** Windows 11 (static CRT â€” it needed `VCRUNTIME140.dll` before).

**Disposable lab VM.** The host is Windows 11 *Home* (no Hyper-V Manager / Windows Sandbox), so the lab is a QEMU/KVM Windows 11 Enterprise Evaluation guest inside WSL2 (`scripts/vm/`, documented in `docs/TESTING-ON-WINDOWS.md`). Everything destructive ran there, never on the host.

**Real-Windows bugs found and fixed** (all have regression tests):
* Kernel-Registry `SetValueKey` has an **empty `KeyName`** on Win11 (known risk 2): new `RegNotifyChangeKeyValue` watcher + ETW join for the writer; attribution exact/heuristic/none.
* An event with a **NUL character** (real command lines) made PostgreSQL reject the batch and the agent re-sent it forever â†’ all later alerts stuck (attacker-triggerable). Server strips NULs and dead-letters data errors; agent strips NULs.
* Cross-session ETW ordering: file events overtook `ProcessStart` â†’ alerts on an empty placeholder process. Translator holds early pids.
* False positives on a quiet Windows: OneDrive (lsass VM_READ, "terminate" bit), Optimize Drives (`defragsvc`) and MRT reading decoys, Edge/WAM reading the token-broker cache, agent's own hardening PowerShell vs SigmaHQ, Sigma `Signed:'false'` on unverified DLLs, RW-05 on browsers closing their own tree, TP-04 on `KestrelLab*` services.
* File-activity sensor: no second summary for a fast burst (RW-06 never fired), then a summary flood; Startup-folder writes reported as `open` (PS-03 blind).
* Audit-API noise: ~500 OpenProcess events/s (`0x1200`) dropped at the source; NXDOMAIN DNS kept.
* MSI: WiX v6 needed a fixed GUID and cp1252; **M6** reworked (registry hand-off leaked into verbose logs) â†’ native custom-action DLL, tokens on stdin only; upgrades work; the uninstall token can't be skipped with `UPGRADINGPRODUCTCODE`.

**Broader malware coverage (Phase 3).** Research: `docs/research/general-malware-report.md` (+4 notes). New rule families behind a `Family` seam in `kestrel-detect`: **RW-01..08, RW-12** (ransomware), **CD-01..13** (credential dumping), **PS-01..05, 07..11, 15** (persistence, incl. rollback); new sensors (aggregated file activity + ransomware decoys, Task Scheduler / SCM / WMI-Activity, failed lsass opens); `RemoveAutorun` response (vault backup first, allow-list, OS-default restores only); hardening: WDigest off, ASR LSASS, LSA protection (reports "pending reboot", never reboots), driver-blocklist report, TaskScheduler log. **70-rule SigmaHQ Audit pack** (DRL 1.1, author + pinned upstream link shown). Console: rules catalog by family, policy sensors/hardening, incidents/storylines/checklists for the new families.

**Open items closed (Phase 4).** H10 (DNS while isolated: agent image + service SID only), M6 (above), M10 (deleting a Block IOC lifts its WFP blocks), policy version after DB restore (server catch-up, bounded), **signed auto-update with rings** (canary/early/broad, promote/halt, owner-held Ed25519 key, `update-keygen`/`update-sign`), YARA-X moved to `kestrel-scan.exe` (agent 52 MB â†’ ~19 MB), CI Windows job builds the scanner and runs the smoke test.

**Found in the final lab run and fixed:** no console action could lift a network block (a false positive on a business app needed a reinstall) â†’ new `unblock_network` action (device/incident pages, incident checklist item; restoring a quarantined file lifts its blocks); incident titles read "by  on" for unattributed writers; overview chart axis labels clipped.

**Independent security review (Phase 5).** 0 Critical / 10 High / 12 Medium / 18 Low found by a reviewer who wrote none of the code; two fix rounds; a fresh re-review verified the fixes and found 2 regressions that were then fixed. Residuals are listed below.

## Verification matrix (final code, 2026-10-21)

| Check | Where | Result |
|---|---|---|
| `cargo fmt --all -- --check` | Windows | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | Windows (rustc 1.99 MSVC) | PASS |
| `cargo test --workspace` incl. server integration tests on Postgres 16 | Windows | PASS â€” 41 suites, 559 tests, 0 failed |
| Console `npm test` / `lint` / `build` | Windows | PASS â€” 93 tests |
| Tray `npm test` / `build`, Rust fmt / clippy / tests, `npm run tauri build` | Windows | PASS â€” 30 + 8 tests (tray crate formatted and 2 clippy lints fixed this run) |
| Release build: agent 19.5 MB, scanner 18.2 MB, CA DLL | Windows | PASS |
| WiX v6 MSI `KestrelAgent-1.1.0.msi` (13.9 MB) | Windows | PASS |
| `docker compose up -d --build` + first-run setup, `/api/healthz` | Docker Desktop | PASS |
| `scripts/e2e.sh` (real server + 3 simulated agents) | WSL2 Kali | PASS â€” 40/40 |
| Smoke test + sensor probe (known risks 2â€“7) | Lab VM | PASS (risk 4: DPAPI events flow without the Debug channel) |
| MSI install, tamper (`sc stop` denied), wrong uninstall token refused, uninstall cleans up, no token in verbose logs | Lab VM | PASS |
| In-place upgrade 0.1.0 â†’ 1.1.0 (same device id, service running) | Lab VM | PASS |
| Pass A, all rules Audit (benign emulations) | Lab VM | 32 built-in rules fired + 7 SigmaHQ rules (see below) |
| Pass B, Protect: ST-02 kill + image block + quarantine; PS-02 removes Run value / tasks with vault backup; RW-06 kills the encryptor tree; CD-01 | Lab VM | PASS |
| Analyst `unblock_network` lifts image blocks (5 filters â†’ server permit only) | Lab VM | PASS |
| Isolation / release from console; break-glass `release-isolation --token` sticks | Lab VM | PASS |
| Tray app in the standard user's session (named pipe to the agent) | Lab VM | PASS â€” `docs/screenshots/lab-tray-employee.png` |
| Console screenshots against the live server holding lab data, light + dark | Windows (Edge, Playwright) | PASS â€” `docs/screenshots/lab-*.png`, inspected |
| Performance: idle 0.10 % CPU / 41 MB private; load 0.31 %; 0 events lost | Lab VM (4 vCPU) | PASS |
| GitHub Actions CI | â€” | NOT RUN (no remote configured) |

**Rules seen firing on real Windows (Pass A + targeted reruns):** ST-01, 02, 04, 05, 06, 11, 12, 14 Â· RW-01, 02, 04, 05, 06, 12 Â· CD-01, 06, 07, 10, 12 Â· PS-01, 02, 03, 05, 07, 08, 09, 10, 11 Â· TP-01, 02, 03, 04. **Not observed in the lab** (covered by unit tests and fixtures): ST-03 (needs the DPAPI audit channel enabled by hardening), ST-07, ST-08, ST-09, ST-10, ST-13, ST-15, ST-16 (lab harness), RW-03, RW-07, RW-08, CD-02..05, CD-08, CD-09, CD-11, CD-13, PS-04, PS-15, TP-05.

**Lab note:** containment persists by design. Image blocks from Pass B stopped ST-04/ST-06 traffic in the next Pass A until they were lifted with `unblock_network`. Lift blocks (or reinstall) between passes.

## Lab results (QEMU Windows 11 Enterprise Eval 26100, Defender on)

* Smoke test (`scripts/windows-smoke.ps1`): PASS. Sensor probe: risks 2, 3, 6, 7 PASS; risk 4: DPAPI 16385 flows **without** the Debug channel; risk 5 holds.
* Pass A (all rules Audit, 34 benign emulations): see matrix. Idle baseline: 0 alerts in 5 minutes.
* Pass B (Protect): ST-02 killed + network-blocked + quarantined the "stealer"; PS-02 removed the Run value and the hidden-PowerShell tasks (XML backed up).
* Isolation from the console: example.com and DNS blocked, device "isolated", release restores; **break-glass** `release-isolation --token` removed the 15 filters and the service did not re-apply them.
* MSI install (token not in the verbose log), `sc stop` denied, wrong uninstall token refused, `msiexec /x UNINSTALL_TOKEN=â€¦` removes service, ETW sessions, WFP filters and files.
* Performance (4 vCPU): idle 0.10 % CPU, 41 MB private / 62 MB working set; under 20k file writes+reads and 200 process launches 0.31 % CPU; 0 events / buffers lost.

## Things only the owner can do

1. **Code signing.** Defender flags the unsigned agent as `Trojan:Win32/Cryware.B` (heuristic on the credential-store path tables) and quarantines it on install. Sign `kestrel-agent.exe`, `kestrel-scan.exe`, `kestrel_msica.dll`, `kestrel-tray.exe` and the MSI (Azure Artifact Signing â€” a Singapore entity is eligible; see BUILDING.md), then submit the signed binaries to Microsoft as a false positive (https://www.microsoft.com/wdsi/filesubmission). Until then, deployments need a Defender exclusion for `C:\Program Files\Kestrel` (GPO/Intune). On this PC a Defender exclusion exists only for `D:\project\kestrel\target`, `D:\project\kestrel\tray\src-tauri\target` and `D:\kestrel-build`.
2. **Update signing key.** Run `kestrel-agent update-keygen` on a trusted offline machine, back up the private key, build agents with `KESTREL_UPDATE_PUBKEY`, put the same value in `deploy/.env`. Optionally set `KESTREL_UPDATE_REQUIRE_SIGNED` once MSIs are Authenticode-signed.
3. **CI.** No git remote is configured; nothing was pushed. Add a remote and enable GitHub Actions (`windows-2025` runner runs the smoke test).
4. **Windows Sandbox / Hyper-V** are not available on Windows 11 Home; the QEMU lab replaces them. The Enterprise Evaluation ISO expires 90 days after install â€” re-run `scripts/vm/vm.sh install` (ISO at `~/kestrel-vm/win11.iso` in WSL Kali).
5. Lab credentials (not in git): console admin `D:\kestrel-build\admin.txt`; VM passwords and SSH key in WSL `~/kestrel-vm/`; `deploy/.env` holds the master key â€” back it up separately.
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

P1: AMSI provider DLL; live response with signed scripts; device control (USB); dead-letter API; `agent_spawned` on alert process info; lab coverage for ST-07/ST-16/PS-03 and an upgrade 1.1.0 â†’ 1.1.1 run; performance on low-end hardware with Office/OneDrive workloads. P2/P3 unchanged from the research report (MSP multi-tenancy, NATS, identity integrations, v3 signed driver â†’ MVI).

## Remote access â€” lab results (Windows 11 VM, 2026-10-21)

| Check | Result |
|---|---|
| Install wizard â†’ `Install-Kestrel-<profile>.cmd` (`/quiet`) downloads, verifies SHA-256, installs, enrolls with the profile | PASS (after fixing the self-signed download and the `pause`) |
| Real uninstall retires the identity, so a reinstall enrolls as a new device with the new ceiling | PASS (after fixing the locked-outbox uninstall failure; a package left half-removed can now be uninstalled) |
| **Unrestricted:** file manager list / 3 MB upload + download (SHA-256 match) / mkdir / rename / recursive delete | PASS |
| **Unrestricted:** remote desktop view (frames in the portal; employee banner "IT (name) is viewing this PC â€” Reason: â€¦") | PASS |
| **Unrestricted:** control mode (banner switches to "controlling"; clicking Start in the portal opens the Start menu) | PASS |
| Tray shows "IT ended the remote session" | PASS |
| **Guarded:** missing reason refused; upload/mkdir wait for the employee's consent and time out after 60 s; delete/rename refused; `System32\config` blocked; Kestrel folders refused; consent results audited | PASS |
| **None:** every file and desktop operation refused by the install ceiling even though the policy allowed full access | PASS |
| Ceiling AND policy: an Unrestricted device refuses while its policy says off (`disabled_by_policy`) | PASS |

Not yet exercised in the lab: an employee clicking **Allow** on the consent prompt, the UAC secure desktop/lock screen during a session, multi-monitor/DPI, `Ctrl+Alt+Del` (needs the `SoftwareSASGeneration` policy).

**Admin notes:**
* A device needs both an install profile and a policy that allow remote access. Existing policies default to *no remote access*.
* The generated installer uses the first name in `KESTREL_PUBLIC_HOSTNAME`, which must be an address the endpoints can reach.

## Local "turn protection off" switch: lab results (1.1.4, Windows 11 VM, 2026-10-21)

Driven through `\.\pipe\kestrel-tray` as the standard-user employee, the same way the tray app talks to the agent.

| Check | Result |
|---|---|
| Wrong token refused, attempts left reported, TP-06 raised | PASS |
| Detection only, 15 min: console status `paused` with user, mode and end time; TP-06 Medium | PASS |
| Stealer emulation while off: ST-02 Critical, ST-01, PS-02 alerted in Audit with no actions | PASS |
| Turn back on from the tray without a token; TP-06 Info | PASS |
| Completely off: all Kestrel ETW sessions stopped; IT turns protection back on from the console (`resume_protection`): 5 sessions back | PASS |
| Pause survives a reboot (same end time); turn back on afterwards | PASS |
| Lockout after 5 wrong tokens (1 min, countdown), TP-06 High | PASS |
| Protection really resumed: Protect mode removed the lab harness's hidden PowerShell scheduled task right after turn-on | PASS |
