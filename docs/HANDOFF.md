# Handoff — state of Kestrel EDR v1.1.0-rc1 (2026-10-21)

Read `CLAUDE.md` first. This run took Kestrel from "compiled and simulated" to "validated on real Windows, broader malware coverage, release candidate". Decisions with reasons are in `docs/DECISIONS.md`; the security reviews are `docs/security-review-2026-10-21.md` (v1.0) and `docs/security-review-v1.1-2026-10-21.md` (v1.1, independent).

## What changed in this run

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
