# Kestrel architecture

This document covers how the parts fit together. The wire contracts live in [contracts.md](contracts.md), and the operational details live in [../deploy/README.md](../deploy/README.md).

## Components

| Component | Crate / dir | Role |
|---|---|---|
| Shared contracts | `crates/kestrel-common` | `Event`, `Alert`, `Policy`, `ResponseAction`, `wire` (agent ↔ server JSON payloads), `tray` (tray protocol) |
| Detection engine | `crates/kestrel-detect` | Process table, builtin rules ST-01…16 / TP-01…05, IOCs, exclusions, custom Sigma (`rsigma`), canary generation, suspend-on-suspicion verdict windows. Pure Rust; runs on any OS |
| Platform trait | `crates/kestrel-platform` | What the agent needs from an OS: host facts, `start_sensors`, `execute(action)`, hardening, isolation state, canaries, tray server |
| Windows platform | `crates/kestrel-win` | `WindowsPlatform`: ETW sessions (ferrisetw), event-log subscriptions, enrichment (hash, Authenticode, MOTW), response (kill/suspend/quarantine vault), WFP, AppLocker/ASR/registry hardening, canaries, `\\.\pipe\kestrel-tray`, service install/run |
| Agent | `crates/kestrel-agent` | Enrollment and PKI, gRPC/mTLS transport, SQLite outbox, engine loop, privacy filter, command execution, tray handler, signed updates, `SimPlatform` + replays |
| Server | `crates/kestrel-server` | axum HTTPS (REST `/api`, console SPA, `/downloads`), tonic gRPC agent service, internal agent CA, PostgreSQL control plane, ClickHouse/Postgres telemetry, incidents, RBAC, OIDC/MFA, notifications, audit chain, background jobs |
| Console | `console/` | React admin UI. Talks only to `/api`, and gets live updates over SSE |
| Tray | `tray/` | Tauri 2 per-user app. Talks only to the local agent over the tray pipe |
| Installer | `installer/Kestrel.wxs` | Per-machine MSI. Enrolls and registers the service through a deferred custom action |

## Data flow

```
ETW / event log ──► kestrel-win translator ──► mpsc ──► agent engine loop ──┬─► response (Platform::execute)
                                                                           ├─► Alert ─────┐
                                                                           └─► privacy filter ─► event batch ─┐
                                                                                          ▼                    ▼
                                                                                SQLite outbox (zstd, seq, priorities)
                                                                                          │ gRPC Connect stream (mTLS)
                                                                                          ▼
 kestrel-server: ingest ──► alerts + incidents (Postgres) ──► notifications, SSE ──► console
                       └──► events (ClickHouse, or Postgres fallback) ──► hunt, device timeline, process tree
 console action ──► response_actions row ──► deliver now or queue ──► agent executes ──► ActionResult ──► status
```

1. **Sensors** (`kestrel-win/src/win/etw.rs`, `sensors.rs`) run three real-time ETW sessions:
   * `Kestrel-Core`, flushed every 1 s: Kernel-Process (start/stop/image load), Kernel-Audit-API-Calls (OpenProcess / OpenThread / SetContextThread and related calls), Kernel-Registry SetValueKey, and Crypto-DPAPI 16385.
   * `Kestrel-IO`, flushed every 5 s: Kernel-File Create, Kernel-Network, DNS-Client 3008 and PowerShell 4104.
   * `Kestrel-ProcCmd`, optional and in system-logger mode, used only as a command-line source for processes that exit quickly.

   Event-log subscriptions add Security WFP-change events (5446–5450) and, if Sysmon is installed, Sysmon 8 and 10 as a cross-check.

   ETW callbacks decode only the fields Kestrel uses and `try_send` them, counting anything dropped. A translator thread then:
   * resolves process GUIDs from pid plus start time
   * maps NT paths (`\Device\HarddiskVolumeN`) to drive letters
   * filters file events to paths that may be sensitive (`kestrel_detect::paths::may_be_sensitive` plus canary paths)
   * correlates DNS answers to connections
   * attaches enrichment (sha256, signer, Mark-of-the-Web) from caches

   Hashing and Authenticode checks run on a separate worker. For an image seen for the first time the `ProcessStart` is held (at most 750 ms) while a priority worker hashes it and checks its signature; facts that arrive later (and revocation results: cache-only first, then online with a timeout) are fed to `Engine::enrich_process`, which re-runs hash/cert IOCs, ST-12 and ST-08(b) and re-judges open suspend windows. Until then the signature is `Unknown`, which is never treated as trusted.
2. **Engine** (`kestrel-detect`). The engine loop calls `Engine::process(&event)` for every event and `tick()` every 250 ms. Both run behind `catch_unwind`, so a panic in a rule cannot stop the agent. The engine returns `Output::Alert` (with actions in Protect mode) or `Output::Action` (for example when a suspend window expires).
3. **Response**. The agent executes the actions through `Platform::execute`, records each `ActionOutcome` on the alert, and shows the employee a plain-language notification in the tray.
4. **Upload**. Alerts, action results, heartbeats, inventory, review requests and filtered telemetry batches go into the SQLite outbox. Each row has a strictly increasing `seq` and is zstd-compressed above a size threshold. The transport keeps one bidirectional `Connect` stream open, re-sends every unacknowledged row in order after a reconnect, and deletes rows when the server sends a cumulative `Ack {seq}`. When the outbox exceeds `max_outbox_mb`, the oldest events are dropped first. Alerts and action results are never dropped.
5. **Server ingest** (`ingest.rs`, `incidents.rs`).
   * Events go to the telemetry store.
   * Each alert is stored, together with any evidence events the device does not already upload as raw telemetry, and attached to an incident. Alerts on the same device join the same incident if they share a root process tree (the topmost non-system ancestor), or if an open incident is rooted at one of the alert's ancestors, within a 30-minute window.
   * The incident's title, storyline, priority, data at risk and remediation checklist are rebuilt on every new alert.
   * Automatic agent actions become `response_actions` rows with no requester.
   * Notifications are queued, so they never block ingest, and the SSE stream tells consoles to refresh.
6. **Commands**. Console actions are stored first. They are delivered immediately if the agent is connected, and otherwise on the next `Hello`. Commands are idempotent: the agent keeps an executed-command ledger. Each command ends as `succeeded` or `failed`, or as `expired` after 7 days.
7. **Policy**. Each device gets the policy of its group. The effective policy is the stored policy plus global and policy-scoped exclusions and IOCs plus branding. It is pushed whenever its version changes. Custom Sigma and YARA rules travel as a separate versioned `RuleBundle`.

## Detection pipeline

The engine emits every rule hit through one path:

1. The rule mode is looked up in the policy, falling back to the rule's default. Rules set to `Off` are dropped.
2. The agent itself and PID 0 and 4 are never subjects.
3. An `Allow` IOC on the process's sha256 or signer suppresses all rules.
4. Exclusions are checked: path glob, sha256, signer and image name, each either global or per rule, and each with optional expiry.
5. Duplicates are dropped: one alert per rule per process GUID per 10 minutes, except escalations.
6. In Audit mode the alert carries no actions. In Protect mode it carries actions, after these filters:
   * protected processes (csrss, lsass, services, svchost, explorer, Defender, …) are never killed or suspended. One shared list (`kestrel_detect::protect`) is used by the engine and the Windows response code, and a process only counts as protected at its exact location on the system volume with a valid Microsoft signature, so a look-alike name or path does not shield malware
   * only images in user-writable paths are quarantined; server-issued quarantine commands never touch Microsoft-signed OS files
   * the Kestrel server's IPs are never blocked

Exclusions (step 4) keep the drive letter; `*` matches within one path segment and `**` across segments. They never apply to `TP-*` tamper rules. Signer exclusions and allow IOCs need a `Valid` signature.

### Suspend on suspicion

ETW is asynchronous, so a stealer could finish reading and sending before a multi-event correlation completes. To narrow that window, the following rules **freeze** the process in Protect mode (`NtSuspendProcess`) and open a verdict window of `policy.suspend_window_ms` (3 s by default; 2–5 s suits most offices):

* ST-01 (credential-store read by an untrusted process)
* ST-03 (foreign DPAPI unprotect)
* the opt-in ST-12 (untrusted execution from user paths)

What happens next depends on what the engine sees during the window:

* **A strong rule fires in Protect mode** for the suspended process, its parent or one of its children. The strong rules are ST-02 (smash-and-grab), ST-04 (steal-then-send), ST-07 (browser tampering) and ST-16 (canary). The relatives count because a frozen process cannot itself connect out. The strong rule's alert carries `KillProcess{tree}` and `QuarantineFile`, plus `BlockDestination` for ST-04.
* **The window expires** and the process is unsigned or invalidly signed, runs from a user-writable path and was caught by ST-01 or ST-03. It is killed and quarantined.
* **The window expires in any other case.** The process is resumed, so legitimate tools such as password-manager imports and backup agents only stall briefly.
* **The process exits while suspended.** The window is dropped.

Per-process correlation state includes:

* secret categories touched (with last-touch time)
* the stores touched (used for the summary text)
* `data_at_risk`
* up to 20 evidence events
* the last untrusted credential read and the last DPAPI unprotect
* DNS answers

This state lets ST-02 and ST-04 correlate across events and lets the server explain *what* was at risk. The incident checklist then turns each `DataCategory` into remediation steps, for example "revoke all web sessions; a password reset alone does not kill stolen cookies".

### Canaries

For each user profile, the agent plants:

* a decoy Chrome profile `Profile NN`, where NN is 51–98 and derived from the hostname
* a SQLite `Login Data` file with fake entries
* a fake MetaMask LevelDB vault
* a decoy `.aws\credentials`, only if the real file does not exist

It never overwrites existing files, and it never follows junctions or symbolic links in the profile paths. Any reader of these files other than the agent or a validly signed security, search, backup or management tool on the allow-list trips ST-16. In Protect mode ST-16 kills the reader's process tree, blocks the image's network for 24 h and quarantines the image. It isolates the host (the server stays reachable) only when the reader is unsigned or unknown **and** runs from a user-writable folder, so a signed backup or migration tool that walks the profile cannot isolate a fleet.

## Security model

### Agent ↔ server transport
* **Pinned CA, mTLS.** On first start the server creates an internal **agent CA**, with its key wrapped by `KESTREL_MASTER_KEY` using AES-256-GCM. The CA signs the gRPC server certificate, whose SANs are `KESTREL_PUBLIC_HOSTNAME` and which is regenerated at each start, and one client certificate per device (CN = device id, 1-year validity). The agent trusts **only** the CA PEM it was installed with (`CA_B64`), never the system root store. Port 8443 must not sit behind a TLS-terminating proxy.
* **Enrollment tokens.** Tokens look like `kte_…`. The server stores only their SHA-256, plus a display prefix, group, expiry (default 7 days, 1–90), max uses (default 50, ≤ 10 000) and a revoked flag. Secrets that leak into command lines (`TOKEN=…`, `--token …`, `kte_…`, `kun_…`, `kst_…`) are redacted server-side before telemetry, alerts or action results are stored. Enrollment is an atomic `UPDATE … uses = uses + 1 WHERE NOT revoked AND expires_at > now AND uses < max_uses`. The agent generates its key pair locally and sends only a CSR. The private key never leaves the device and is written as a secret file under the state directory, which only SYSTEM and Administrators can access.
* **Identity is never re-bound.** Every token enrollment creates a new device id. The client-asserted hardware UUID only flags both devices as possible duplicates (`TP-SRV-DUP-ENROLL` when the existing device was alive in the last 24 h); an administrator merges, dismisses or decommissions explicitly. An enrollment never revokes another device's certificates.
* **Certificate lifecycle.** Agents send `RenewCertificate{csr_pem}` on their authenticated stream when < 30 days remain (the server also sends `RenewCertificate` on Hello in that window). The server signs with CN = the stream's device id (clientAuth only, 1 year), replies `Certificate{cert_pem, ca_pem}` and records which serial it replaces; every older certificate of the device is revoked once the device connects with the new one. The legacy `Enroll` with an empty token over mTLS follows the same rules. Decommissioning a device revokes its certificates and drops its live stream. Expired or revoked certificates must re-enroll with a token.
* **Uninstall token escrow.** The server generates a per-device uninstall token at enrollment, returns it in `EnrollResponse.uninstall_token` (the agent stores only its Argon2id hash) and keeps it sealed with the master key. Users with `devices.write` reveal it on the device page; every reveal is audit-logged. **Rotation** stores a new token as *pending* and sends it to the agent as `ServerPayload::SetUninstallToken` (immediately if connected, otherwise after the next `Hello`; never written to the plaintext message queue). The agent replaces the hash with an atomic rewrite of `agent.toml` and only then acks; the server promotes pending → current when that ack arrives and the token is still the pending one. Until then the old token keeps working.
* **Agent-side renewal.** The agent checks its certificate after every `Welcome` and daily; with < 30 days left (or when asked) it generates a new key and CSR, installs the returned certificate atomically while keeping the previous pair, reconnects, and deletes the previous pair after the next `Welcome`. If the new identity fails to connect 3 times, the previous pair is restored; a crash during the swap is repaired at start.
* **Outbox and clocks.** Envelope seqs are deduplicated against a per-device high-water mark; `Hello.outbox_epoch` changing (outbox deleted or recreated) resets it and raises `TP-SRV-OUTBOX-RESET`. Heartbeats are deduplicated by seq and processed on server receive time; agent timestamps are clamped to server time.
* **Server-side tamper heuristics.** The server raises:
  * `TP-SRV-HEARTBEAT` after more than 3 missed heartbeats on a live stream
  * `TP-SRV-SEQ-RESET` when the outbox sequence goes backwards (state wiped or cloned)
  * `TP-SRV-EVENTS-LOST` when more than 500 ETW events are lost between heartbeats
  * `TP-SRV-ETW` when the agent reports its ETW session down
  * `TP-SRV-OUTBOX-RESET` when the agent starts a new outbox (`Hello.outbox_epoch` changed)
  * `TP-SRV-DUP-ENROLL` when a new enrollment reuses the hardware UUID of a recently active device

### Endpoint self-protection (user mode)
* **Service DACL.** `KestrelAgent` runs as LocalSystem with auto start, restart-on-failure ×3 and an unrestricted service SID. Its DACL gives Administrators only query, interrogate and start rights. Stop, change-config, delete and `WRITE_DAC` are SYSTEM-only, so `sc stop KestrelAgent` fails even for an admin.
* **State directory.** `kestrel-agent install`, `enroll` and every service start verify `C:\ProgramData\Kestrel`: owner SYSTEM or Administrators, no write access for anyone else, no reparse point. An untrusted directory (for example one a standard user created before the install) is moved aside and re-created with owner SYSTEM and a protected DACL in one `CreateDirectoryW`; its `agent.toml` is not used.
* **Uninstall token.** Issued by the server at enrollment (see above), stored as an Argon2id hash in `agent.toml`, checked in constant time and never printed. The MSI takes no token at install; its uninstall action runs `kestrel-agent uninstall --token [UNINSTALL_TOKEN]`, and a wrong token aborts the uninstall. `TOKEN`, `UNINSTALL_TOKEN` and the deferred custom-action data are hidden from MSI logs. Uninstall restores a default DACL, removes Kestrel's WFP objects (otherwise an isolated host would stay isolated) and stops leftover ETW sessions.
* **Isolation release paths.** Isolation records when it started and re-resolves the server and the adapters' DNS servers every minute, re-planning the WFP permits when they change (a roaming laptop keeps reaching the server). The server permit applies to the agent executable only; DNS to the configured resolvers stays open for all processes. If the server stays unreachable for `policy.isolation_auto_release_hours` (default 72, 0 = never) the agent releases isolation itself and tells the user. Locally, an administrator with the uninstall token can run `kestrel-agent release-isolation --token …` as a break-glass.
* **Tamper rules on the device.**
  * TP-01: an ETW session stopped or an AutoLogger disabled. The watchdog restarts the sessions.
  * TP-02: foreign WFP filter changes, seen in Security events 5446–5450. This requires the "Filtering Platform Policy Change" audit policy.
  * TP-03: AMSI provider or FeatureBits changes.
  * TP-04: changes to the service registry key or agent files.
  * TP-05: event loss.

  An administrator can still defeat a user-mode agent. These rules make that loud and visible; they cannot make it impossible.
* **Response safety.**
  * Kill and suspend open the target first and check its creation time **on the same handle** against the GUID, so a reused PID is never touched.
  * The agent never acts on itself, PID 0/4 or the shared protected-process list (exact location + valid Microsoft signature).
  * Quarantine and restore never follow links: every path component is checked for reparse points, the file is opened with `FILE_FLAG_OPEN_REPARSE_POINT`, files with more than one hard link are refused and the final path must equal the requested one. The sha256 is verified before any ACL change. Restore only writes to the recorded original path, through a verified and locked parent handle (`NtCreateFile` with `FILE_CREATE`), never into `%SystemRoot%` or Program Files, and only when the parent's owner class matches.
  * Quarantine uses a per-host AES-256-GCM key protected with machine-scope DPAPI, in a vault directory restricted to SYSTEM and Administrators.
  * AppLocker hardening reads the **effective** policy and never touches GPO/MDM-managed AppLocker policies ("skipped: domain policy present"); it adds the default rule set, not an allow-all rule.
  * WFP filters are persistent and use hard actions, so isolation holds through a reboot before the agent starts.
* **Signed updates.** Update manifests must carry an Ed25519 signature over `kestrel-update-v1
{version}
{url}
{sha256}` (so a signed package cannot be replayed under another version or URL), checked against a key embedded at build time (`KESTREL_UPDATE_PUBKEY`). The package is downloaded over HTTPS and its hash is verified before `msiexec` runs: from the Kestrel server it is fetched on the agent port (`/downloads/updates/<file>`) trusting only the pinned agent CA; from any other host it is verified against public web PKI roots without presenting the client certificate (the signature, not TLS, is what makes the package trustworthy).
  * **The server never holds the signing key.** The owner creates it offline (`kestrel-agent update-keygen`) and signs each MSI offline (`update-sign`). An administrator registers a release by pasting the printed manifest; the server checks its format, verifies the signature against its own `KESTREL_UPDATE_PUBKEY` (registration is refused when unset) and, for a server-hosted package, that the file in `deploy/installers/updates/` has the signed SHA-256. A compromised server can withhold or delay updates but cannot make agents install anything unsigned.
  * **Staged rings (MVI 3.0-style).** Each group has an `update_ring`: `canary` (ring 0), `early` (ring 1), `broad` (ring 2, default) or `pinned` (never auto-updates). A release starts with no ring enabled; admins with `updates.write` promote it ring by ring, strictly in order, after checking per-ring health (devices on the target version, failures the agents reported, devices offline for more than 24 h after delivery). **Halt** is terminal: nothing more is delivered, agents that already updated stay updated (fix forward with a newer release). There is no automatic promotion.
  * **Delivery.** On promotion, connected agents in the ring get `ServerPayload::Update` at once; others get it after their next `Hello`, which re-offers it until the device reports the new version. Only the newest non-halted release enabled for the device's ring is offered, and only if it is newer than the running version (no downgrades). Decommissioned devices never receive it. Every delivery is recorded per device; a later `Hello` with the new version marks it succeeded and `AgentPayload::UpdateResult` marks it failed with the agent's error.

### Tray ↔ agent
* The agent serves the pipe `\\.\pipe\kestrel-tray` from the service process with DACL `D:P(A;;GA;;;SY)(A;;GRGW;;;AU)`. Remote clients are rejected. The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a pre-created (squatted) pipe makes the service fail loudly instead of sharing the name.
* **Session-0 check.** The tray connects with `SECURITY_IDENTIFICATION` QoS, so the server cannot impersonate the user. It then calls `GetNamedPipeServerSessionId` and trusts the pipe only if the server runs in **session 0**, where services run. A user-mode squatter runs in session ≥ 1, so it can never feed fake status or notifications to the tray. The tray can only read status and activity, run a quick check and request a review. It cannot allow, restore or disable anything.
* **Per-user scoping.** The service identifies every pipe client by its process token. `Activity` returns only that user's items plus machine-wide ones, and notifications are pushed only to their owner's tray, so users on a shared or RDS host never see each other's alerts or file paths. Review requests are accepted only for alerts the caller can see, once per alert until IT decides and at most 5 per user per hour; the request carries the caller's (pseudonymised, if configured) user name. A quick check runs at most once per 5 minutes.

### Console / REST
* Authentication uses a session cookie (`HttpOnly; Secure; SameSite=Strict`) plus an `X-CSRF-Token` header on mutating requests. Automation uses API tokens (`Bearer kst_…`), which have their own privilege set and skip CSRF.
* RBAC privileges are listed in contracts.md. Response actions check `ResponseAction::privilege()`.
* **First run** requires a one-time setup code printed in the server log at startup (or `KESTREL_SETUP_CODE`).
* **Login throttling** counts only failed verifications and applies exponential backoff, never a hard lockout: per account + address (5 free, then 1 s doubling to 15 min), per account from anywhere (20 free, capped at 60 s) and per address (20 free, capped at 5 min). `X-Forwarded-For` is honoured only from `KESTREL_TRUSTED_PROXIES` (right-most untrusted hop).
* **MFA.** TOTP codes are single-use (the last accepted time step is stored). For MFA accounts a request without a code gets `mfa_required` whether or not the password was right, so the password cannot be guessed on its own. API tokens cannot use `/me/*` (password, MFA) and expire (default 90 days).
* **Sessions** have an idle timeout and an absolute lifetime (`session_max_days`, default 7). The live-update stream re-checks its session every 60 s and closes (`event: session`) after logout, disable, role change or expiry.
* **OIDC SSO** binds accounts by `(issuer, sub)` only and never by email; a first sign-in creates a new SSO-only user, and an existing password account must be linked by an administrator (`PATCH /users/:id {oidc_subject}`). `email_verified` must be `true`, the email domain must be on `allowed_domains` (empty = nobody), and the default role can never be an administrator role. Discovery is cached for an hour, unfinished logins are capped and `/auth/oidc/start` is rate-limited per address.
* **Outbound requests** (webhook, Slack, Teams, OIDC) only reach public addresses, never follow redirects and never reach link-local or cloud-metadata addresses; `KESTREL_OUTBOUND_ALLOW_CIDRS` allows chosen private ranges. Syslog may target a private collector only with `notifications.syslog.allow_private`. Endpoint-controlled text is escaped for Slack mrkdwn and Teams markdown; webhook URLs are hidden from users without `settings.write`.
* **Guardrails.** Exclusions: no bare or leading wildcards, no drive roots or whole system/user folders, wildcards only below two literal folders, never for `TP-*` rules, and global scope needs `policies.write`. Review approvals only create sha256 (or valid-signer) exclusions for the alerted rule in the device's group policy, expiring after 90 days. IP IOCs wider than /16 (IPv6 /48) or in private/loopback ranges need `confirm_broad`; wider than /8 (/32) is refused. Console process actions need the process GUID; the console never offers shell or OS processes as kill targets.
* Strict CSP (`default-src 'self'`, no inline script), `frame-ancestors 'none'`, HSTS and `nosniff` are all set.
* **Audit chain.** Every administrative action is appended to `audit_log` with `hash = HMAC-SHA256(k, prev_hash || canonical_json(row))`, where `k` is derived from `KESTREL_MASTER_KEY`, so database access alone cannot recompute the chain. Every 15 minutes the head `(id, hash)` is written to the server log and, when configured, to syslog as an external anchor against truncation. Older unkeyed chains are re-chained once at startup if they verify. Administrative actions include login, policy and rule changes, token issuance, response actions, enrollment and hunt queries. `GET /api/audit-log/verify` recomputes the chain and returns `{ok, broken_at, count}`. After restoring a backup, run the verification.
* **Secrets at rest.** The CA key, web TLS key, TOTP secrets and notification secrets are encrypted with a key derived from `KESTREL_MASTER_KEY`. The server refuses to start if it cannot decrypt them, which happens when it is given the wrong master key. Write-only settings return only `*_set: bool`.

### Remote access (remote desktop + file manager)

Details are in contracts.md ("Remote access") and the wire types are in `kestrel_common::remote`.

* **Transport.** Both features use `ServerPayload::Live` / `AgentPayload::Live { session_id, msg }` on the existing mTLS stream.
  * Messages are JSON; frames and file chunks are base64.
  * They are ephemeral: agent envelopes carry seq 0, skip the SQLite outbox and are never acked. The server routes them through an in-memory hub keyed by session id, and checks that the session belongs to the sending device.
  * When the stream drops, every live session of that device ends.
  * Older peers ignore unknown kinds. The server opens sessions only with agents whose `Hello.capabilities` list `live.files` / `live.desktop`.
* **Who may use it.**
  * Admins only, through the privileges `remote.desktop` / `remote.files`.
  * Interactive console session only; API tokens are refused.
  * The remote-desktop WebSocket additionally checks `Origin` against `Host` and takes the CSRF token as a query parameter.
* **Install ceiling.** Each enrollment token carries a `RemoteAccessProfile`.
  * The agent pins it at enrollment as its ceiling. Only a new enrollment (a reinstall with the uninstall token) changes it; no later server message does.
  * The effective profile is `ceiling ∩ policy` (stricter wins). The agent enforces it: modes, upload/delete, allowed hours in device local time, required reason, blocked paths and session length.
  * The server checks the same intersection to show the result in the UI and to refuse early.
  * A device installed with *No remote access* cannot be opened by a compromised server or admin account. Every device enrolled before profiles existed has that ceiling.
* **Guardrails.**
  * *Consent:* the tray in the active console session shows Allow/Deny. No answer, no user signed in, or an old tray means deny.
  * *MFA step-up:* `POST /me/reauth`, valid for 10 minutes.
  * *Session and idle limits:* enforced by the server's timers; the agent also enforces the maximum length.
* **Remote desktop.**
  * The agent (SYSTEM, session 0) starts `kestrel-agent.exe desktop-helper` in the active console session, using a copy of its own token with `TokenSessionId` set.
  * The helper runs inside a kill-on-close job object, so it dies with the agent.
  * It talks to the agent over a per-session pipe whose DACL allows only SYSTEM. Each side checks the other's process id.
  * The helper captures the screen with GDI (`BitBlt`), follows input-desktop switches (UAC, lock screen), JPEG-encodes changed frames, and injects input with `SendInput`.
  * It also shows a click-through, always-on-top banner that cannot be closed: "IT (name) is viewing / controlling this PC".
  * Flow control: at most 3 frames in flight; the server acks each frame after writing it to the browser's WebSocket.
* **File manager.**
  * Paths are validated identically on server and agent (`validate_remote_path`): only absolute `X:\…` paths, never UNC/device paths or network drives.
  * Kestrel's install and state folders are refused after canonicalisation (8.3 names, junctions, symlinks). Their ancestors cannot be renamed or deleted.
  * Uploads go to an exclusive temp file and are renamed over the target only after the size and SHA-256 match.
  * Recursive delete removes links, never their targets.
  * Downloads stream from the agent's 512 KiB chunks straight to the browser; the server never stores file data.
* **Accountability.** The hash-chained audit log records every session start, mode change and stop, every consent result and every file operation, with path, byte count and SHA-256 for transfers. Frames and file contents are never logged or stored.

## Privacy controls (PDPA / UU PDP)

Kestrel is built to be deployable under Singapore's PDPA and Indonesia's UU PDP. These laws allow monitoring of company devices, but they require notice, purpose limitation and minimisation, and UU PDP requires a DPIA for systematic monitoring. The controls are per policy:

| Control | Effect |
|---|---|
| `telemetry.upload_events` / `event_kinds` | Turn off raw telemetry, or limit it to certain event kinds. Alerts and their evidence are always uploaded. |
| `privacy.capture_cmdline` | Off: command lines are truncated to image plus flags. |
| `privacy.hash_usernames` | User names are replaced by a stable salted hash, a pseudonym. The server applies it too (`u_` + HMAC) to the logged-on user in health, review-request users and alert process users it stores. |
| `privacy.redact_path_prefixes` | Paths under these prefixes are never uploaded, for example personal folders. The event keeps its type and process. |
| `privacy.capture_dns` | Off: no DNS telemetry. DNS evidence is still attached to alerts. |
| `privacy.capture_script_content` | Off: PowerShell/AMSI content is replaced by `[redacted]`. |
| Retention (Settings) | Events default to 30 days (ClickHouse TTL, or 7 days on the Postgres fallback), alerts to 365 days and the audit log to 730 days. |
| Branding → employee notice | Markdown notice shown in the tray app's Help & privacy tab: what is collected, why, retention, and a contact. |

Detection always runs locally on full-fidelity events. The filters apply only to what **leaves** the device. Admin remote access (above) is the one deliberate exception to "no screen or keystroke capture": interactive, admin-initiated, limited by the device's install profile, visible to the employee and audited, and nothing it carries is stored. Analyst access to employee telemetry (hunt queries) is recorded in the audit log, and all data stays on the organisation's own server.
