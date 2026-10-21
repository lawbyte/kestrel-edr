# Contributing to Kestrel EDR

Thanks for helping. This page covers how to build, test and send changes.

## Before you start

* Read the [documentation](https://lawbyte.github.io/kestrel-edr/), especially [Build from source](https://lawbyte.github.io/kestrel-edr/build/) and [Testing safely](https://lawbyte.github.io/kestrel-edr/guide/testing).
* For a large change, open an issue first so we can agree on the approach.
* Security issues go through [private reporting](SECURITY.md), not public issues.

## Never test response actions on your own PC

The agent kills processes, quarantines files, changes firewall (WFP) rules and isolates hosts. Run `kestrel-agent run`, the MSI and every emulation only in a disposable virtual machine. Unit tests, `kestrel-agent simulate`, the server in Docker and the console in mock mode are safe on a workstation.

## Checks that must pass

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace            # set DATABASE_URL to include the server integration tests
cd console; npm ci; npm test -- --run; npm run lint; npm run build
cd tray; npm ci; npm test -- --run; npm run build
cd website; npm ci; npm run build # includes the docs style check
```

On Linux or WSL, `scripts/e2e.sh` runs the server with simulated agents end to end.

## Conventions

* **Contracts:** types shared between components live in `crates/kestrel-common`. A change there updates every caller in the same pull request (agent, server, console types in `console/src/api/types.ts`, tray protocol). Prefer additive, `#[serde(default)]` changes, because agents in the field can be older than the server. REST changes go into `docs/contracts.md`.
* **Detection rules:** behaviour first, Audit by default, stable ids (`ST-`, `RW-`, `CD-`, `PS-`, `TP-`). Every rule ships with positive and benign fixtures under `crates/kestrel-detect/tests/fixtures/` and false-positive notes in its catalog entry. Fix false positives in the rule itself; do not add general "never stop this app" exemptions.
* **Response safety:** never act on protected or critical processes, re-check process start time before acting on a PID, never follow reparse points.
* **Privacy:** anything uploaded passes the privacy filters. No background keystroke, screenshot or URL capture.
* **Licences:** no GPL, AGPL, SSPL or ELv2 code or rules (`deny.toml`). SigmaHQ rules keep their DRL 1.1 author attribution.
* **Rust:** edition 2021, `thiserror` in libraries, `anyhow` in binaries, no `unwrap()` on untrusted input; Windows code behind `#[cfg(windows)]` with platform-independent logic unit-tested on Linux.
* **Docs:** plain technical English; the docs build rejects en and em dashes and emoji.

## Pull requests

* One logical change per pull request, with a clear description of what and why.
* Add or update tests for the behaviour you change.
* For detection changes, say which fixtures cover it and how you checked false positives.
* For UI changes, include light and dark screenshots.

By contributing you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
