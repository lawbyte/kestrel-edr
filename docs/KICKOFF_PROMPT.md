# Kickoff prompt — Kestrel EDR, Windows phase

You are the lead engineer on Kestrel EDR in this repository. The owner will not answer questions during this run: work fully autonomously from start to finish, coordinating subagents, and only stop when everything below is done or genuinely blocked on the owner (then document the blocker and finish everything else).

## Read first (in this order)
1. `CLAUDE.md` — rules, layout, **safety rules for this host**, how to work.
2. `docs/HANDOFF.md` — current state, what was and wasn't verified, open items, prioritised backlog.
3. `docs/research/edr-research-report.md` (skim all; read the build plan and v1 rule set closely), `docs/ARCHITECTURE.md`, `docs/contracts.md`, `docs/TESTING-ON-WINDOWS.md`, `docs/security-review-2026-10-21.md`.

## Mission for this run
Take Kestrel from "compiled and simulated" to "validated on real Windows, broader malware coverage, release-ready v1.1", in this order:

**Phase 0 — Setup.** `git init` + baseline commit if `.git` is missing. Check the toolchain (Rust MSVC ≥1.96, VS Build Tools C++, protoc, Node 22+, WiX v6, Docker Desktop or PostgreSQL 16, Git; the WSL2 Kali distro is available as a Linux server — see CLAUDE.md); install what's missing with `winget`/`rustup`/`dotnet tool` (note anything that needs the owner, e.g. a UAC prompt you can't satisfy or a reboot). Create the task list for the whole run.

**Phase 1 — Native build green.** Build and test everything natively on Windows (see CLAUDE.md commands): Rust workspace (fmt, clippy -D warnings, tests incl. server tests against local Postgres), console, tray (`npm run tauri build`), MSI with WiX. Fix whatever only breaks on MSVC/Windows. Build and start the server via `docker compose` (deploy/) and complete first-run setup with the setup code; if Docker isn't available run the server natively.

**Phase 2 — Real-Windows validation.** First on this host, read-only only: elevated `scripts/windows-smoke.ps1` and `kestrel-agent sensors-test`. Then everything destructive in a disposable VM (Windows Sandbox or Hyper-V checkpoint — see CLAUDE.md safety rules; if neither is available without a reboot, record the blocker in HANDOFF and skip to Phase 3, doing what you can with `sensors-test` + captured events). In the VM: install the MSI against the server on this host, confirm health on the device page, run the benign emulation for every rule in `docs/TESTING-ON-WINDOWS.md`, confirm the expected rule ids/incidents and Protect-mode actions, isolation/release/break-glass, uninstall with the token, the tray app. Investigate and fix each of the 8 known Windows-layer risks listed in HANDOFF. Capture real event samples and turn them into regression fixtures. Measure agent CPU/memory/events-lost idle and under load; tune.

**Phase 3 — Broader malware coverage.** The owner wants Kestrel to detect general malware, not only stealers. Run deep research first: spawn ≥4 parallel research subagents (web search, cited, 2025-2026 sources) on (a) ransomware behaviours + user-mode detection from ETW, (b) LSASS/credential dumping techniques and telemetry, (c) Windows persistence techniques and telemetry, (d) which SigmaHQ rules fit Kestrel's telemetry and how other user-mode agents (Fibratus, Aurora, Velociraptor, Elastic) cover these — write notes to `docs/research/notes/`, synthesise `docs/research/general-malware-report.md`. Then design rule families RW-xx, CD-xx, PS-xx (+ a curated SigmaHQ Audit pack with DRL attribution), extend contracts/sensors first (e.g. aggregated file write/rename telemetry for ransomware, lsass access, task/service/WMI persistence), then implement in parallel subagents with disjoint ownership, with positive + benign fixtures, catalog metadata, console catalog/mock updates, and validation in the VM like Phase 2.

**Phase 4 — Close open items.** Fix the partial/open security-review items in HANDOFF (H10 DNS, M6 MSI token, M10 IOC unblock, policy version after restore, wire signed auto-update with staged rings). Reduce agent size by moving YARA-X into an on-demand scanner. Make CI's Windows smoke test real.

**Phase 5 — Independent review + release prep.** Spawn a fresh read-only reviewer subagent (didn't write any of the new code) to review all changes since the baseline as a hostile pentester; fix confirmed findings; re-verify. Then run the full verification matrix (Rust fmt/clippy/tests, console + tray build/tests, MSI build, docker compose up, e2e — `scripts/e2e.sh` in WSL Kali (see CLAUDE.md), VM validation results), refresh screenshots (Playwright, look at them), update README (remove any claim that isn't true), `docs/HANDOFF.md` (new state, verification matrix, owner-only blockers), `docs/DECISIONS.md`, and tag `v1.1.0-rc1` locally.

## Rules of engagement
* Follow CLAUDE.md, especially the host safety rules — this is the owner's daily PC. Never install the agent service, apply hardening, isolate, quarantine or kill on the host; never run real malware anywhere; never disable Defender.
* Never ask the owner anything; decide, log the decision in `docs/DECISIONS.md`, continue.
* Use subagents for research and for parallel implementation (disjoint file ownership, contracts defined by you first, separate CARGO_TARGET_DIRs). Use a separate reviewer subagent for security-relevant work.
* Verify every claim by running it. Commit in logical steps. Keep the task list current.
* Final message: a short summary of what changed, the verification matrix, and the exact list of things only the owner can do (reboots, licences, signing certificate, Docker login, etc.).
