# Kestrel EDR — guide for Claude agents

Read this file fully before doing anything. Then read `docs/HANDOFF.md` (current state and backlog) and the docs it points to.

## What this is

Kestrel is a self-hosted Windows EDR for companies, focused on **infostealers** (Lumma, Vidar, StealC, Acreed…) and growing into general malware coverage. Owner: Azka (lawbyte), offensive-security consultant in Singapore — expect a technical, security-literate reviewer. The target buyer is an SMB / mid-market company in Singapore or Indonesia (PDPA, UU PDP, MAS TRM, OJK context).

v1 is **user-mode only** (no kernel driver): ETW sensors + on-device detection engine + fast containment (suspend / kill / quarantine / WFP block / isolation) + OS-native hardening. Be honest everywhere (UI, docs, alerts) that user mode cannot guarantee prevention.

## Repository layout

| Path | What |
|---|---|
| `crates/kestrel-common` | Shared types: events, alerts, policy, response actions, wire payloads, tray protocol. **Source of truth for every cross-component structure.** |
| `crates/kestrel-detect` | Detection engine (platform independent): process table, rules ST-01…ST-16 (stealer) and TP-01…TP-05 (tamper), IOCs, exclusions, Sigma via `rsigma`, canaries, protected-process list. |
| `crates/kestrel-platform` | `Platform` trait — the only way the agent core touches the OS. |
| `crates/kestrel-win` | Windows implementation: ETW (ferrisetw), enrichment (Authenticode/hash/MOTW), response, WFP, quarantine, hardening, canaries, tray named pipe, service. |
| `crates/kestrel-agent` | Agent binary: CLI, enrollment, mTLS gRPC transport, SQLite outbox, engine loop, privacy filters, tray handler, `simulate` mode (SimPlatform + `replays/*.jsonl`), `sensors-test`. |
| `crates/kestrel-server` | axum REST + tonic gRPC server, internal agent CA, Postgres (control plane) + optional ClickHouse (telemetry), incidents, RBAC, OIDC, audit chain, notifications. |
| `console/` | React 19 + Vite + Tailwind admin console. `npm run dev:mock` runs it without a server. |
| `tray/` | Tauri 2 employee tray app (own Cargo workspace in `tray/src-tauri`). |
| `proto/kestrel.proto` | gRPC envelope (payloads are JSON of `kestrel_common::wire`). |
| `installer/Kestrel.wxs` | WiX v6 MSI. |
| `deploy/` | Dockerfile, docker-compose, `.env.example`, deploy README. |
| `scripts/e2e.sh` | End-to-end test: real server + 3 simulated agents (bash; run it in the WSL Kali distro). |
| `scripts/windows-smoke.ps1` | Elevated smoke test of the real ETW sensors. |
| `docs/` | `contracts.md` (REST API + boundaries), `ARCHITECTURE.md`, `BUILDING.md`, `TESTING-ON-WINDOWS.md` (VM lab plan), `security-review-2026-10-21.md`, `research/` (deep-research report + notes), `HANDOFF.md`. |

## Contracts — do not break silently

* Cross-component types live in `kestrel-common`. Changing them means updating **every** caller (agent, server, console TS types in `console/src/api/types.ts`, tray mirror in `tray/src-tauri/src/protocol.rs` + `tray/src/protocol.ts`) in the same change.
* Prefer additive, `#[serde(default)]` changes. Agents in the field may be older than the server.
* REST API changes must be reflected in `docs/contracts.md` and the console types.
* Rule ids are stable: `ST-xx` stealer, `TP-xx` tamper, `IOC-*`, `SIG-<uuid8>` custom Sigma, server-side `TP-SRV-*`. New built-in families must get their own prefix (proposed: `RW-xx` ransomware, `CD-xx` credential dumping, `PS-xx` persistence, `EX-xx` generic execution/LOLBins) and appear in `Engine::catalog()` with full `RuleMeta` (ATT&CK ids, references, false positives, `protect_day_one`).

## Building and testing on Windows (native)

Toolchain (verify with `--version`; install with `winget` if missing — some installs need an elevated shell):
Rust stable MSVC (`rustup default stable-x86_64-pc-windows-msvc`, rustc ≥ 1.96), Visual Studio 2022 Build Tools (C++ workload), `protoc` (`winget install Google.Protobuf` or set `PROTOC`), Node 22+, WiX v6 (`dotnet tool install --global wix`), Docker Desktop or a native PostgreSQL 16 for server tests, Git, optionally WSL2 (for `scripts/e2e.sh`).

```powershell
cargo test -p kestrel-common -p kestrel-detect -p kestrel-platform -p kestrel-win -p kestrel-agent
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
$env:DATABASE_URL="postgres://user:pw@localhost:5432/postgres"; cargo test -p kestrel-server   # needs Postgres; skips without DATABASE_URL
cargo build -p kestrel-agent --release
cd console; npm ci; npm run build; npm test -- --run; npm run lint
cd tray; npm ci; npm run build; npm test -- --run; npm run tauri build
```

### Linux side: WSL2 (Kali)

The owner's PC has a WSL2 Kali distro you may use as the Linux server whenever Linux is easier: `wsl -d kali-linux -- bash -lc "<cmd>"` (check `wsl -l -v` for the exact distro name). Use it for `scripts/e2e.sh`, running Postgres/ClickHouse/the server natively, Linux builds and the Linux cross-check aliases. The repo is reachable from WSL at `/mnt/d/project/kestrel`; for heavy Rust builds inside WSL, use a target dir on the Linux filesystem (e.g. `CARGO_TARGET_DIR=$HOME/kestrel-target`) because builds on `/mnt/d` are slow. The sudo password is in `CLAUDE.local.md` (git-ignored — never copy it into tracked files, commits, logs or reports). Services in WSL are reachable from Windows at `localhost` (WSL2 localhost forwarding), which is how a Windows Sandbox/VM agent can reach a server running there — use the host's LAN/vEthernet IP from inside the VM.

`.cargo/config.toml` has `cargo win` / `cargo wincheck` aliases — those are for **cross-checking from Linux** (gnu target + build-std). On Windows just use normal cargo commands (MSVC target).

Release profile strips symbols with thin LTO. The agent is ~52 MB, mostly YARA-X.

## SAFETY RULES — this machine is the owner's daily-driver PC

The agent you are building kills processes, quarantines files, installs WFP filters that can cut network access, edits AppLocker, plants decoy files in user profiles and installs a SYSTEM service with a locked DACL. **Never do any of that to this host.**

1. On this host you may: build, run unit/integration tests, run the server (Docker or native), run the console/tray in dev/mock mode, run `kestrel-agent simulate` (SimPlatform — touches nothing real), and run the **read-only** `kestrel-agent sensors-test --seconds N` (elevated) to observe ETW.
2. Anything that installs the MSI/service, runs `kestrel-agent run`/`install`, applies hardening in Enforce, isolates, quarantines or kills **must run in a disposable VM**: Windows Sandbox (`WindowsSandbox.exe` with a `.wsb` config mapping a build folder read-only) or a Hyper-V VM restored from a checkpoint. Check availability with `Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM, Microsoft-Hyper-V-All`. Enabling a feature needs admin + reboot: if it's not enabled, do NOT reboot the machine — record it in `docs/HANDOFF.md` as a blocker for the owner and continue with everything else.
3. Never run real malware. Use the benign emulations in `docs/TESTING-ON-WINDOWS.md` (and Atomic Red Team-style safe tests) inside the VM only.
4. Never disable Defender, Smart App Control or firewall on this host. Don't add Defender exclusions on the host except for the repo's `target` folders if builds are blocked (record it).
5. Never commit secrets (`CLAUDE.local.md`, `.env`, tokens, keys). Never push to a remote unless the owner configured one and the task says to.
6. Disk: Rust `target` dirs grow large — check free space before big builds and clean stale targets.

## How to work (autonomous mode)

The owner gives one prompt and expects the whole job done end to end without further input.

* **Never stop to ask questions.** Take the most reasonable reading, write the decision and why into `docs/DECISIONS.md` (append, dated), and continue. Stop only for an irreversible action that could reasonably go either way (and then do all the preparatory work first).
* **Plan with a task list** (TaskCreate/TaskUpdate) and keep it current — that is how the owner follows progress.
* **Research before building anything non-trivial.** Use subagents (Task/Agent tool, `general-purpose`) with web search for deep research: give each a narrow subtopic, require cited sources and current (2025-2026) facts, have them write notes to `docs/research/notes/<topic>.md`, then synthesise into `docs/research/<topic>-report.md`. Verify Windows API names, ETW provider GUIDs/event ids/field names and ASR/policy names against Microsoft docs or well-known source (krabsetw, SilkETW, Velociraptor, Fibratus, SigmaHQ) — never from memory.
* **Parallelise implementation with subagents** that each own a disjoint set of paths (e.g. one for `kestrel-detect`, one for `kestrel-win`, one for `kestrel-server`, one for `console/`). Give each: the files to read first, exact contracts, what to build, how to verify, and "do not edit other paths; do not commit — report contract gaps". Define/extend contracts yourself *before* spawning them. Use separate `CARGO_TARGET_DIR`s per parallel Rust builder to avoid lock contention, and delete them afterwards.
* **Verify everything you claim**: run tests, clippy, fmt, builds, the e2e script, and screenshots of UI you changed (Playwright; look at the images). A task isn't done if tests fail.
* **Independent review for anything security-relevant**: spawn a fresh reviewer subagent that didn't write the code, read-only, reviewing as a hostile pentester, writing findings with file:line, exploit scenario and fix. Fix confirmed findings, then re-verify.
* **Commit in logical steps** with clear messages. Initialise git first if `.git` is missing (`git init`, commit the baseline as "Baseline from cloud session").
* **At the end**: update `docs/HANDOFF.md` (what changed, verification matrix with pass/fail, what still needs the owner — e.g. reboot to enable Windows Sandbox, signing certificate, Docker Desktop login), update README if features changed, and give a short final summary.

## Engineering conventions

* Rust 2021, `anyhow` in binaries, `thiserror` in libraries, `tracing` for logs. No `unwrap()` on untrusted input; agent code must never panic on malformed ETW/JSON.
* Windows code behind `#[cfg(windows)]`; keep pure logic platform-independent with Linux-runnable unit tests.
* Detection rules: behaviour-first (family names age in months), Audit by default unless `protect_day_one` is justified, every rule ships with fixtures (positive and benign) under `crates/kestrel-detect/tests/fixtures/` and false-positive notes.
* Response safety: never act on protected/critical processes (shared list in `kestrel_detect::protect`), never block the Kestrel server, re-check process start time before acting on a PID, quarantine never follows reparse points.
* Privacy: anything uploaded goes through the privacy filters; never add keystroke/screenshot/URL capture.
* Licences: no GPL/AGPL/SSPL/ELv2 code or rules (`deny.toml`; Elastic detection rules are ELv2 — don't copy them). SigmaHQ rules are DRL 1.1 — keep author attribution visible in alert views.
* UI: the console's design language is in `console/src` (dark default, IBM Plex, severity = icon + label, never colour alone). Keep it consistent; check light and dark.
