# Handoff — state of Kestrel EDR (2026-10-21)

Built in a Linux cloud session (Claude), now continuing on the owner's Windows 11 PC. Read `CLAUDE.md` first.

## How v1 was built

1. Deep research (5 parallel researchers → report): `docs/research/edr-research-report.md` + `docs/research/notes/` — EDR agent architecture (ETW vs kernel, ETW-TI/PPL/ELAM/MVI realities), 2025-2026 infostealer TTPs and detections, the employer EDR feature set (MVP/standard/advanced, MAS TRM mapping, PDPA/UU PDP), tech stack + licences, console/tray UX patterns. **Read the report's "Recommended architecture and phased build plan" and "v1 detection rule set" sections before changing scope.**
2. Contracts first (`kestrel-common`, `proto/`, `docs/contracts.md`, `kestrel-platform`), then 6 components built in parallel by subagents, then integration (e2e), then an independent security review (`docs/security-review-2026-10-21.md`: 10 High / 12 Medium / 12 Low, 0 Critical) and two fix rounds.
3. Owner's decisions: self-hosted server per company (Docker), Rust agent, web console + Tauri tray, user-mode sensors first (no driver in v1).

## Verified in the cloud session (Linux)

| Check | Result |
|---|---|
| `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings` | pass |
| `cargo test --workspace` (with Postgres 16; ClickHouse 24.8 path also tested earlier) | pass |
| Windows cross-check (gnu target, build-std) + Windows-target clippy for agent + win | pass |
| Release `kestrel-agent.exe` cross-built and linked (only system DLLs) | pass (not run) |
| Console build/test(50)/lint, tray build/test(30), tray Rust contract tests | pass |
| `scripts/e2e.sh` — server + 3 simulated agents (Lumma ClickFix, Vidar smash-and-grab, benign workday) | 40/40 |
| Real-server console screenshots | `docs/screenshots/real-*.png` |
| Detection engine benchmark | ~1.1 M events/s quiet host |

## NOT verified yet (top priority on Windows)

* **Nothing Windows-specific has ever executed.** ETW sessions, enrichment, WFP, quarantine, AppLocker/hardening, tray pipe, service install, MSI — all compiled and unit-tested only. (README currently says the sensor layer was "smoke-tested in CI" — that is not true yet; fix the wording once it is.)
* **Docker image never built** (registries blocked in the cloud). `docker compose -f deploy/docker-compose.yml up -d --build` is untested.
* OIDC login and outgoing notifications (Slack/Teams/SMTP/syslog) never exercised against real endpoints.
* Tray app never run on Windows (Mica, flyout placement, toasts + AppUserModelID, session-0 pipe check).

### Known Windows-layer risks to check first (from the Windows-layer author)
1. Kernel-File `Create` + Audit-API `OpenProcess` event volume/CPU on a busy machine (Kernel-File Read events are off by default).
2. Kernel-Registry `SetValueKey` `KeyName` may be relative to a KeyObject (Velociraptor resolves via a KeyObject cache) — RunMRU/TypedPaths detection (ST-10) depends on it.
3. Kernel-Network addresses/ports byte order.
4. Whether DPAPI event 16385 reaches a real-time session without the Debug channel enabled.
5. `HistoricalContext` == LoggerId assumption in the provider-disabled watchdog.
6. Processes shorter than ~1 s may lose their command line.
7. `nslookup` bypasses the DNS Client service → no DNS-Client event (lab plan uses `Resolve-DnsName`).
8. AppLocker is only enforced on Enterprise/Education; `Add-MpPreference` loses to GPO/Intune.

`docs/TESTING-ON-WINDOWS.md` has the full lab plan (benign emulation per rule + expected rule id + what to measure). `scripts/windows-smoke.ps1` and `kestrel-agent sensors-test --seconds N` are the first steps (sensors-test is read-only and OK on the host, elevated).

## Open items from the security review

| Id | State | Remaining work |
|---|---|---|
| H10 isolation | Partial | DNS to configured resolvers is allowed for every process while isolated → restrict to the agent image (resolve server name via agent only) |
| M6 enrollment token on MSI command line | Partial | Pass the token via a protected file or `MsiHiddenProperties` + a deferred CA reading `CustomActionData`, never argv |
| M10 IOC delete doesn't lift blocks | Partial | Server should push an unblock (new command or policy-driven reconciliation of WFP IOC filters) |
| Info: policy.version after DB restore | Open | Use (policy epoch, version) or server-signed monotonic counter |
| Info: `ServerPayload::Update` never sent | Open | Wire agent auto-update end to end (manifest signed `kestrel-update-v1\n{version}\n{url}\n{sha256}`), rings (MVI 3.0-style staged rollout) |

## Backlog (owner's priorities in order)

### P0 — make it real on Windows
1. Toolchain up on Windows; baseline build + tests green natively (MSVC).
2. Docker image build + `docker compose up`; first-run setup with the setup code.
3. Windows validation in a disposable VM (Windows Sandbox / Hyper-V) per `docs/TESTING-ON-WINDOWS.md`: install MSI against the local server, sensors healthy on the device page, each ST rule's benign emulation fires the expected rule, Protect-mode actions work, isolation + release + break-glass, uninstall with token, tray app. Fix every sensor/parsing bug found; add regression fixtures from captured real events (`crates/kestrel-detect/tests/fixtures/`).
4. Performance: CPU %, memory, events/min, events lost on an idle and a busy VM; tune ETW filters.

### P1 — broader malware coverage (owner asked: "not only stealers")
Research first (deep research subagents), then build, each with fixtures + false-positive notes + console catalog entries:
* **Ransomware pack (RW-xx)**: canary documents, mass write/rename/extension-change rate per process, high-entropy writes if feasible from user mode, `vssadmin/wmic/wbadmin/bcdedit` recovery inhibition, service-stop sprees; automatic kill + isolate in Protect. Needs a new file-write/rename sensor mode with source-side aggregation (volume!).
* **Credential dumping (CD-xx)**: handles to `lsass.exe` with VM_READ (Audit-API / Sysmon 10), comsvcs.dll MiniDump, `procdump -ma lsass`, SAM/SYSTEM hive saves, NTDS.dit copies, DCSync-like activity is out of scope (no DC telemetry) — document.
* **Persistence (PS-xx)**: Run/RunOnce, services, scheduled tasks (TaskScheduler ETW/event log), WMI subscriptions, Startup folder, IFEO/AppInit/COM hijack — "new autorun pointing into a user-writable path" as the core signal.
* **Curated SigmaHQ pack**: pick rules whose logsources/fields the agent actually produces, map fields, test against benign baseline, ship enabled-in-Audit with DRL attribution.
* Consider an AMSI provider DLL (v1 reports `amsi_ok=false`) for script content.

### P2 — product quality
* Agent size (~52 MB, mostly YARA-X/wasmtime): feature-gate YARA into a separate on-demand scanner process.
* Missing sensors noted by the authors: `DebugAttach` (no user-mode source), registry *read* events (WinSCP/PuTTY sessions), NetConnect flow id/phase (byte-count updates appear as repeat events), structured `granted_access` (Audit-API gives *desired* access).
* Console: remaining UX polish; notification test buttons (needs server endpoints).
* CI: run `scripts/windows-smoke.ps1` for real on `windows-2025` runners; signing with Azure Artifact Signing (Singapore org eligible; individuals only US/CA).

### P3 — v2/v3 roadmap (from the research report)
Live response with signed script library + per-action RBAC; device control (USB); software inventory + CVE; investigation package; scheduled reports; MSP multi-tenancy; NATS scale-out; identity integrations (auto-revoke M365/Google sessions when cookies were at risk); v3 minimal WHCP-signed driver (ObRegisterCallbacks handle stripping for browsers + agent, minifilter deny on credential stores), lab certification → MVI → ELAM/AM-PPL → ETW-TI.

## Decisions log
Append future decisions to `docs/DECISIONS.md` (date, decision, why, alternatives).
