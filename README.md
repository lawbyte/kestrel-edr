# Kestrel EDR

Kestrel is a self-hosted endpoint detection and response (EDR) product for Windows, built to catch **infostealers** (Lumma, Vidar, StealC, Rhadamanthys and similar malware) while they work. These programs read browser passwords, cookies, crypto wallets and messenger sessions, then upload them. Kestrel watches for exactly that behaviour, contains the process, and gives IT one incident that says what was taken and what to rotate.

It has four parts:

* **Agent** (`kestrel-agent`): a Windows service written in Rust. It reads ETW sensors, runs the detection engine on the device, and contains threats.
* **Server** (`kestrel-server`): one Docker Compose stack per organisation, with PostgreSQL and optional ClickHouse. All telemetry stays on your own infrastructure.
* **Admin console**: a React app served by the server.
* **Tray app**: a small Tauri app for employees. It shows status, explains blocks in plain language and lets the employee request a review.

> **Status: v1, user-mode only.** Read the limits section before you rely on it.

## What it does

* **Stealer detection on the device.** There are 16 behavioural rules (`ST-01`…`ST-16`) and 5 tamper rules (`TP-01`…`TP-05`). They run in the agent, so detection and containment still work while the device is offline.
* **Suspend on suspicion.** When an untrusted process opens a credential store or decrypts browser secrets with DPAPI, the agent freezes it for a short window (3 s by default). It kills the process if a stronger rule confirms the theft, and resumes it otherwise.
* **Response actions.** These can be automatic (rules in Protect mode) or issued by an analyst from the console:
  * kill or suspend/resume a process or process tree
  * quarantine a file into an encrypted vault, then restore or delete it
  * block a destination IP or an image's network access through WFP
  * isolate the host so that only the Kestrel server stays reachable (released automatically after `isolation_auto_release_hours` without server contact, default 72 h; local break-glass `kestrel-agent release-isolation --token …`)
  * scan with YARA-X
  * collect a triage package
  * re-apply hardening

  Actions issued while a device is offline are queued and delivered when it reconnects. They expire after 7 days.
* **Canary credential stores.** The agent plants a decoy Chrome profile, a fake MetaMask vault and decoy `.aws\credentials`. `ST-16` fires when anything other than the agent or an allow-listed, validly signed security/search/backup tool reads them, which gives almost no false positives. In Protect mode it kills the reader, blocks its network and quarantines it; the host is isolated only when the reader is unsigned and runs from a user-writable folder.
* **Hardening pack.** Each control can be set to Audit or Enforce:
  * AppLocker deny rules for `mshta` and for executables in Temp/Downloads
  * removing the Win+R Run dialog
  * the Windows Terminal multi-line paste warning
  * PowerShell script-block logging
  * the DPAPI debug channel
  * Defender ASR rules
  * Chrome/Edge `RemoteDebuggingAllowed=false`
* **Incidents, not alert floods.** The server groups alerts by device and process tree into incidents. Each incident gets:
  * a priority (0–100)
  * a plain-language storyline
  * the process tree and network evidence
  * the categories of data at risk
  * a checklist with three kinds of items: what the agent already did, one-click actions that need approval, and manual steps such as revoking sessions or moving wallet funds
* **Hunting.** A small filter language over telemetry, for example `event_type = dns_query and dns_qname ~ telegram`. Telemetry is stored in ClickHouse, or in Postgres for small sites.
* **Custom Sigma rules.** Rules are compiled and validated by the server, then pushed to agents and evaluated there with `rsigma`.
* **Operations features:**
  * RBAC with roles `admin`, `analyst` and `readonly`
  * OIDC SSO and TOTP MFA
  * API tokens for SIEM integrations
  * notifications by email, Slack, Teams, signed webhook and syslog (CEF/JSON)
  * a hash-chained audit log with a verify endpoint
  * live updates in the console through server-sent events (SSE)
  * signed agent updates (Ed25519)
* **Privacy controls for PDPA (Singapore) and UU PDP (Indonesia).**
  * Each upload category can be switched off separately: command lines, DNS, script content and raw telemetry.
  * User names can be replaced with salted hashes.
  * Path prefixes can be redacted.
  * Analysts' hunt queries are recorded in the audit log.
  * The tray app shows employees the organisation's monitoring notice.

## Honest limits (v1)

* **User mode only. There is no kernel driver.** Telemetry comes from ETW and the event log, so it arrives asynchronously, typically within about 1 s on the core session and up to about 5 s for file and network events. A fast stealer can read and send some data before the agent reacts. Kestrel aims to **detect fast and contain fast**, and it does not guarantee prevention. The incident checklist assumes the data may have left the device, and says so.
* An attacker with administrator or SYSTEM rights can blind ETW, stop sessions or remove WFP filters. The `TP-*` rules and the agent's watchdog detect and repair much of this, but a user-mode agent cannot fully defend itself against an admin.
* The Windows sensor layer has been unit-tested, cross-compiled and smoke-tested in CI. It still needs validation on real Windows 11 hardware: see [docs/TESTING-ON-WINDOWS.md](docs/TESTING-ON-WINDOWS.md) for the known-risk list.
* Only Windows endpoints. The agent core and simulator also run on Linux and macOS for development, but there is no real sensor layer for them.
* Alert grouping and the hunt language are deliberately simple (see [docs/contracts.md](docs/contracts.md)).

## Detection rules

| Id | Rule | Default |
|---|---|---|
| ST-01 | Credential-store read by untrusted process | Audit |
| ST-02 | Smash-and-grab credential collection (≥ 3 secret categories in 60 s) | **Protect** |
| ST-03 | Foreign DPAPI unprotect of browser secrets | Audit |
| ST-04 | Steal-then-send (credential read, then external connection within 300 s) | **Protect** |
| ST-05 | Browser debugging abuse (`--remote-debugging-*` with headless/alt profile) | Audit |
| ST-06 | Local CDP client (non-browser connects to the DevTools port) | Audit |
| ST-07 | Browser process tampering (memory access, injection, debugger attach) | **Protect** |
| ST-08 | Chrome elevation-service abuse | Audit |
| ST-09 | Foreign crypto library load (`nss3.dll`) | Audit |
| ST-10 | ClickFix Run/Address-bar artefact (RunMRU / TypedPaths) | Audit |
| ST-11 | Paste-and-run process chain | Audit |
| ST-12 | Untrusted execution from user paths | Audit |
| ST-13 | .NET LOLBin hollowing | Audit |
| ST-14 | Dead-drop / exfil service from non-browser (Telegram, Steam, Discord webhooks, …) | Audit |
| ST-15 | Trusted-binary sideload from user path | Audit |
| ST-16 | Canary tripwire | **Protect** |
| TP-01 | Telemetry session tampering | Audit |
| TP-02 | WFP filter tampering | Audit |
| TP-03 | AMSI tampering | Audit |
| TP-04 | Agent service or file tampering | Audit |
| TP-05 | Telemetry loss | Audit |

The four **Protect** rules are the "safe on day one" set. Run everything else in Audit for about two weeks first. The console's Rules page shows each rule's logic, its ATT&CK mapping, its Protect action and known false positives.

## Architecture

```
 Windows endpoint                                         Kestrel server (docker compose)
┌──────────────────────────────────────────────┐        ┌───────────────────────────────────────┐
│ kestrel-agent (service, LocalSystem)         │        │ kestrel-server                        │
│                                              │  gRPC  │  ├ agent service :8443 (mTLS, pinned) │
│  ETW sessions ─► translator ─► engine ──┐    │ mTLS   │  │   enroll · stream · acks           │
│  (Kernel-Process/File/Network/Registry, │    │◄──────►│  ├ ingest ─► incidents/grouping       │
│   Audit-API, DNS-Client, DPAPI, PS4104) │    │ :8443  │  ├ REST /api + console SPA  :443      │
│  event log (Security WFP, Sysmon opt.)  ▼    │        │  ├ notifications, jobs, audit chain   │
│        response (kill/suspend/quarantine/WFP)│        │  └ SSE /api/events/stream             │
│        hardening · canaries · YARA-X scan    │        │        │                    │         │
│        SQLite outbox (zstd) ─► transport ────┤        │   PostgreSQL 16        ClickHouse     │
│        tray pipe \\.\pipe\kestrel-tray       │        │   (control plane,      (telemetry;    │
└──────────────────┬───────────────────────────┘        │    or events fallback)  optional)     │
                   │ JSON lines (session-0 check)        └───────────────▲───────────────────────┘
          ┌────────▼─────────┐                                          │ HTTPS (cookie + CSRF)
          │ kestrel-tray     │                              ┌───────────┴──────────┐
          │ (per user, Tauri)│                              │ Admin console (React)│
          └──────────────────┘                              └──────────────────────┘
```

For data flow, the detection pipeline and the security model, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

### 1. Server (Docker Compose)

```bash
git clone <your-kestrel-repo> kestrel && cd kestrel/deploy
cp .env.example .env
sed -i "s|^KESTREL_MASTER_KEY=.*|KESTREL_MASTER_KEY=$(openssl rand -base64 32)|" .env
$EDITOR .env        # KESTREL_PUBLIC_HOSTNAME, POSTGRES_PASSWORD, CLICKHOUSE_PASSWORD
docker compose up -d --build
```

Then:

1. Open `https://<KESTREL_PUBLIC_HOSTNAME>/` and complete first-run setup: the one-time setup code (printed in the server log, `docker compose logs kestrel-server | grep "SETUP CODE"`, or set with `KESTREL_SETUP_CODE`), the organisation name and the first admin.
2. Back up `KESTREL_MASTER_KEY` separately from the database.

Ports, TLS, backup, upgrades and sizing are covered in [deploy/README.md](deploy/README.md).

### 2. Agent (MSI)

1. In the console, open **Devices → Enrollment tokens** and create a token. The console shows a PowerShell/`msiexec` one-liner, for example:

   ```powershell
   msiexec.exe /i KestrelAgent.msi /qn SERVER=edr.example.internal:8443 TOKEN=kte_… CA_B64=<base64 agent CA>
   ```

2. Download `KestrelAgent.msi` from `https://<server>/downloads/KestrelAgent.msi`. It is served when the file is placed in `deploy/installers/`.
3. Run the command elevated, or deploy it with GPO, Intune or your RMM tool. Tokens default to 7 days and 50 uses; create one per rollout wave.
4. Make sure `SERVER` uses a name that is listed in `KESTREL_PUBLIC_HOSTNAME`. The agent pins the internal agent CA and verifies that name.

The server issues a per-device **uninstall token** at enrollment. Find it on the device page (**Uninstall token → Reveal**, audit-logged; **Rotate** sends a new one to the agent, which becomes current once the agent confirms it). Uninstall with `msiexec /x KestrelAgent.msi /qn UNINSTALL_TOKEN=<token>`; the agent refuses removal without it. The agent renews its client certificate by itself 30 days before it expires.

The MSI does three things:

* installs `kestrel-agent.exe` and `kestrel-tray.exe` into `C:\Program Files\Kestrel`
* creates `C:\ProgramData\Kestrel`, accessible to SYSTEM and Administrators only
* enrolls the device and registers the `KestrelAgent` service

The device appears under **Devices** within seconds. Its device page shows sensor health: ETW, events lost, DPAPI channel, AMSI and outbox.

### 3. Tray

The tray app starts at every user logon through the `HKLM\…\Run` key the MSI sets. It shows protected/attention/isolated/offline status, recent blocks in plain language, a **Request review** button, and the organisation's IT contact and monitoring notice. To set the contact and notice, open the console and go to **Policies → Branding & notice**.

### 4. Console

These are the main screens:

* **Overview**: what needs attention
* **Incidents**: the triage queue, with keyboard navigation
* **Devices**: sensor health, timeline, process tree and live response
* **Hunt**
* **Policies**: rule modes, suspend window, isolation auto-release and indicator blocks, hardening, privacy and telemetry, canaries and exfil domains, branding
* **Rules and Exclusions & IOCs**: exclusions show a scope preview before you save them
* **Quarantine**
* **Review requests**
* **Settings**: users, SSO, MFA, notifications, retention, API tokens and the audit log

Screenshots taken against a real server are in [docs/screenshots/](docs/screenshots/), and mock-mode screenshots are in `console/screenshots/`.

## Development workflow

To try everything on Linux without Windows, run the end-to-end test:

```bash
# Linux: build, then run the full end-to-end test (server + 3 simulated endpoints)
./scripts/e2e.sh                         # starts a throwaway Postgres if DATABASE_URL is unset
E2E_KEEP=1 ./scripts/e2e.sh              # ...and leave the server up at https://127.0.0.1:18443
```

It replays recorded attacks (`crates/kestrel-agent/replays/*.jsonl`) through the real agent core and the real server. It then checks the incidents, data at risk, response-action delivery, the audit chain and hunting.

To work on the console, the tray and Windows builds:

* Console, mock data: `cd console && npm run dev:mock`
* Console, against a server: `npm run dev`. It proxies `/api`.
* Tray UI, mock data: `cd tray && npm run dev:mock`
* Windows cross-check from Linux: `cargo wincheck -p kestrel-agent` (see [docs/BUILDING.md](docs/BUILDING.md))
* On a Windows host: `scripts/windows-smoke.ps1` checks that the ETW sensors produce events

CI runs these checks: `cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace`, the console and tray builds and tests, `scripts/e2e.sh`, the server image, the Windows agent/tray/MSI builds, the ETW smoke test, the licence policy (`cargo deny`, no copyleft) and optional Azure Artifact Signing.

## Repository layout

```
crates/
  kestrel-common     shared types: events, alerts, policy, response actions, wire + tray protocols
  kestrel-detect     detection engine: rules ST/TP, process table, IOCs, exclusions, Sigma, canaries
  kestrel-platform   Platform trait (sensors, response, hardening, canaries, tray) the agent runs on
  kestrel-win        Windows implementation: ETW, enrichment, WFP, quarantine vault, AppLocker, service, tray pipe
  kestrel-agent      agent binary: enrollment, mTLS transport, SQLite outbox, engine loop, privacy filter,
                     simulator (SimPlatform) + replays/, signed updates
  kestrel-server     axum REST + tonic gRPC, internal CA, Postgres/ClickHouse, incidents, RBAC, audit, notifications
console/             React admin console (Vite); `npm run build` → console/dist (served by the server)
tray/                Tauri 2 employee tray app (own Cargo workspace in tray/src-tauri)
proto/               kestrel.proto (agent ↔ server gRPC)
deploy/              Dockerfile, docker-compose.yml, .env.example, operations README
installer/           Kestrel.wxs (WiX v6 MSI)
scripts/             e2e.sh (Linux end-to-end), windows-smoke.ps1 (Windows ETW smoke test)
docs/                contracts.md, ARCHITECTURE.md, BUILDING.md, TESTING-ON-WINDOWS.md, screenshots/
```

## Known gaps

* Server-side detections only cover agent health and identity: `TP-SRV-HEARTBEAT` (missed heartbeats), `TP-SRV-SEQ-RESET` (outbox sequence reset), `TP-SRV-OUTBOX-RESET` (outbox database recreated), `TP-SRV-EVENTS-LOST`, `TP-SRV-ETW` and `TP-SRV-DUP-ENROLL` (hardware UUID reused by a new enrollment). Cross-device correlation is not implemented.
* The server cannot push agent updates yet (`ServerPayload::Update` is implemented and signature-checked on the agent, but never sent).
* The open items of the security review are listed below.
* For anything beyond about 5,000 endpoints, add a message bus and multiple ingest replicas (see deploy/README sizing).

## Security review status

An independent review on 2026-10-21 ([docs/security-review-2026-10-21.md](docs/security-review-2026-10-21.md)) found 0 critical, 10 high, 12 medium and 12 low issues. The fixes are covered by unit and integration tests and by `scripts/e2e.sh`. Windows-only behaviour (sensors, WFP, quarantine, AppLocker, the MSI) is cross-compiled and unit-tested but still needs a run on real Windows; [docs/TESTING-ON-WINDOWS.md](docs/TESTING-ON-WINDOWS.md) has a regression check per finding.

| Finding | Status | Notes |
|---|---|---|
| H1 Process made unkillable by name or path | Fixed | One shared protected list: exact path on the system volume + valid Microsoft signature; `PathClass` is volume-aware |
| H2 Identity takeover via `hw_uuid` | Fixed | Enrollment always creates a new device; duplicates flagged (`TP-SRV-DUP-ENROLL`) and merged / dismissed by an admin |
| H3 Certificates never renewed | Fixed | Renewal over the mTLS stream with atomic swap and rollback; the server asks when < 30 days remain |
| H4 Pre-created state directory | Fixed | Owner and DACL verified at install, enroll and every start; untrusted directories moved aside |
| H5 OIDC login by email match | Fixed | Bound by `(issuer, sub)` only, `email_verified` required, admins link accounts explicitly |
| H6 Empty OIDC domain list fail-open | Fixed | Empty list denies; default role can never be an admin role |
| H7 First run unhashed / unsigned | Fixed | First-run images held ≤ 750 ms for hash + signature; late facts re-run IOCs and rules; `Unknown` never trusted |
| H8 Quarantine / restore follow junctions | Fixed | No reparse points or extra hard links, final-path check, hash before ACL changes, handle-relative restore |
| H9 AppLocker allow-all over GPO policy | Fixed | Effective policy inspected; GPO/MDM-managed policies never touched |
| H10 Isolation can strand a host | **Partial** | Permits re-planned every minute, server permit agent-only, auto-release (`isolation_auto_release_hours`) and `release-isolation` break-glass. DNS to the configured resolvers is still allowed for every process while isolated |
| M1 Exclusions ignore the drive / `*` spans folders | Fixed | Drive kept; `*` within a segment, `**` across |
| M2 Review approval creates path exclusions | Fixed | sha256 or valid-signer exclusions only, for the alerted rule, 90-day expiry |
| M3 Tray pipe abuse | Fixed | Requests attributed to the pipe client's token; per-user activity; rate limits |
| M4 Login lockout / spoofable IP key | Fixed | Backoff counted on failures only; `X-Forwarded-For` only from `KESTREL_TRUSTED_PROXIES` |
| M5 Uninstall token never escrowed | Fixed | Server-issued at enrollment, audited reveal, rotation over the wire (`SetUninstallToken`), hidden from MSI logs |
| M6 Enrollment tokens leak via command lines | **Partial** | Tokens and `--token` arguments redacted on agent and server; defaults 7 days / 50 uses. The MSI still passes the token on the custom action's command line |
| M7 Future heartbeat disables processing | Fixed | Dedup by seq, timestamps clamped to server time |
| M8 Outbox reset discards messages | Fixed | `Hello.outbox_epoch`; a new epoch resets the high-water mark and raises `TP-SRV-OUTBOX-RESET` |
| M9 Incomplete privacy minimisation | Fixed | Health, review and alert users hashed; alert process, ancestry and summaries scrubbed like events |
| M10 Permanent host-wide IOC blocks, any CIDR | **Partial** | Wide / private ranges need confirmation, ≤ /8 refused; blocks per offending image with a TTL (`ioc_block_ttl_secs`). Deleting an IOC does not lift blocks already in place (they expire) |
| M11 ST-16 auto-isolates on any reader | Fixed | Signed backup / AV / indexer readers ignored; isolation only for unsigned readers in user-writable paths |
| M12 No revocation checks | Fixed | Revocation checked in the background (cache, then online); revoked signers become `Invalid` |
| L1 TOTP replay, password oracle | Fixed | |
| L2 API tokens on `/me`, no expiry | Fixed | |
| L3 Unauthenticated first-run setup | Fixed | One-time setup code (`KESTREL_SETUP_CODE` or server log) |
| L4 OIDC start amplifier | Fixed | |
| L5 Sessions and SSE not cut off | Fixed | |
| L6 Audit chain rewritable | Fixed | HMAC chain keyed from the master key, head anchored to log / syslog |
| L7 Notification SSRF / injection / exposure | Fixed | |
| L8 Review requests for other devices' alerts | Fixed | |
| L9 ST-11 kills the parent shell | Fixed | |
| L10 Exclusions without guardrails, silence TP rules | Fixed | |
| L11 Different kill-safety lists | Fixed | |
| L12 Canary planting follows junctions | Fixed | |
| Info: update manifest signs only the hash | Fixed | Signature over `kestrel-update-v1\n{version}\n{url}\n{sha256}` |
| Info: monotonic `policy.version` after a DB restore | Open | Agents ignore policies with a lower version than they hold |

## Licence

Apache-2.0. See `Cargo.toml` (`license = "Apache-2.0"`). The dependency licence policy is in `deny.toml`. GPL, AGPL, SSPL and ELv2 dependencies are rejected.

## Credits

* Rule logic draws on public research by SigmaHQ, Elastic Security Labs, Google (Chrome DPAPI event-log detection), Microsoft Threat Intelligence (ClickFix, Lumma), SpecterOps, Unit 42, Kaspersky and Intrinsec. Each rule's references are listed in `crates/kestrel-detect/src/catalog.rs` and on the console's Rules page.
* **SigmaHQ rules are licensed under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).** Kestrel's built-in rules are original Rust implementations and do not ship SigmaHQ rule files. If you import SigmaHQ rules as custom Sigma rules, the DRL requires you to keep the author attribution. Kestrel keeps the rule's `author` as `rule_author` on every alert and shows it in the console. The server recognises DRL/SigmaHQ rules by their `license` and `references` fields.
* Sigma evaluation uses `rsigma-parser`/`rsigma-eval` (MIT). ETW uses `ferrisetw`. On-demand scanning uses YARA-X (BSD-3-Clause).
