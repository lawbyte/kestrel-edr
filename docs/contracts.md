# Kestrel contracts

Every component builds against these. Change them only together with all callers.

| Boundary | Definition |
|---|---|
| Telemetry, alerts, policy, actions, wire payloads | `crates/kestrel-common` (Rust, serde JSON) |
| Agent ↔ server transport | `proto/kestrel.proto` (gRPC, mTLS) carrying `kestrel_common::wire` JSON |
| Detection engine API | `crates/kestrel-detect/src/lib.rs`, `paths.rs`, `table.rs` (public items) |
| Tray ↔ agent | `kestrel_common::tray` over `\\.\pipe\kestrel-tray`, JSON lines |
| Console ↔ server | REST API below |

Product name: **Kestrel EDR**. Rule ids: `ST-01`…`ST-16` (stealer), `TP-01`…`TP-05` (tamper), custom Sigma rules `SIG-<uuid8>`.

---

## REST API (console ↔ server)

Base path `/api`. JSON in/out, `snake_case` keys, timestamps are **ms since epoch** (integers), ids are UUID strings unless noted.

**Auth.** Session cookie `kestrel_session` (HttpOnly, Secure, SameSite=Strict) set by login. Mutating requests must send header `X-CSRF-Token` equal to the `csrf_token` returned by `/api/auth/login` and `/api/me`. API tokens (`Authorization: Bearer kst_…`) are accepted for SIEM/automation and skip CSRF.

**Errors.** Non-2xx responses have body `{"error": {"code": "not_found", "message": "…"}}`. Codes: `bad_request` 400, `unauthorized` 401, `forbidden` 403, `not_found` 404, `conflict` 409, `rate_limited` 429, `internal` 500.

**Lists.** Paginated lists accept `?limit=50&cursor=<opaque>` and return `{"items": [...], "next_cursor": "…"|null, "total": 123}`.

### Roles & privileges

Built-in roles (`roles` table, editable later):

| Role | Privileges |
|---|---|
| `admin` | `*` |
| `analyst` | `read`, `incidents.write`, `response.process`, `response.file`, `response.network`, `response.collect`, `exclusions.write`, `iocs.write` |
| `readonly` | `read` |

Other privileges: `policies.write`, `rules.write`, `devices.write`, `users.write`, `settings.write`, `audit.read`, `tokens.write`.

### Auth

| Method | Path | Body / query | Response |
|---|---|---|---|
| POST | `/auth/login` | `{email, password, totp?}` | `{user: User, csrf_token}` + cookie. First-run: if no users exist, `POST /auth/setup` is required instead. MFA accounts without `totp` → 401 `mfa_required` (also for a wrong password). Repeated failures → 429 `rate_limited` with `retry_after_ms` (exponential backoff, no lockout) |
| POST | `/auth/setup` | `{setup_code, org_name, email, password, name}` (only when zero users; `setup_code` is printed in the server log at startup or set by `KESTREL_SETUP_CODE`) | same as login; 403 `setup_code_required: true` on a wrong code, 409 once set up |
| GET | `/auth/setup-status` | — | `{needs_setup: bool, oidc_enabled: bool, org_name}` (unauthenticated) |
| GET | `/auth/oidc/start` | — | 302 to IdP |
| GET | `/auth/oidc/callback` | `code, state` | 302 to `/` with cookie |
| POST | `/auth/logout` | — | 204 |
| GET | `/me` | — | `{user: User, csrf_token, privileges: [string]}` |

`User = {id, email, name, role, last_login: ms|null, created_at: ms, disabled: bool, mfa_enabled: bool, sso_linked: bool, local_password: bool}`

`/me/*` mutations (`/me/password`, `/me/mfa/*`) require a session; API tokens get 403. Sessions end after `session_timeout_minutes` idle or `session_max_days` in total.

### Dashboard

`GET /dashboard` →
```json
{
  "devices": {"total": 120, "online": 112, "offline": 6, "isolated": 1, "degraded": 1},
  "incidents": {"open": 4, "critical": 1, "high": 2, "mttr_hours_30d": 3.5},   // mttr: null when nothing was resolved in 30 days
  "alerts_24h": 17,
  "blocked_24h": 6,
  "alert_trend": [{"day": "2026-10-14", "critical": 0, "high": 1, "medium": 3, "low": 2}],   // 14 days
  "top_rules": [{"rule_id": "ST-04", "name": "…", "count": 5}],
  "data_at_risk_30d": [{"category": "browser_cookies", "count": 3}],
  "hardening_coverage": [{"control": "block_mshta", "applied": 110, "total": 120}],
  "agent_versions": [{"version": "0.1.0", "count": 120}],
  "recent_incidents": [Incident]   // 5
}
```

### Devices

`Device = {id, hostname, os_name, os_build, arch, domain, agent_version, status: "online"|"offline"|"degraded"|"isolated", last_seen: ms, first_seen: ms, ip_addresses: [string], logged_on_user, group_id, group_name, policy_id, policy_name, policy_version_applied, tags: [string], health: AgentHealth (see kestrel-common wire.rs), open_incidents: int, cert_expires_at: ms|null, possible_duplicates: [device id], uninstall_token_set: bool, uninstall_token_pending: bool}`

`logged_on_user` (and `health.logged_on_user`) is a pseudonym (`u_` + 16 hex) when the device's policy has `privacy.hash_usernames`. `possible_duplicates` lists devices that enrolled with the same hardware UUID; enrollment never re-binds an existing device id.

Status rule: `isolated` if health.isolated; else `offline` if last_seen older than 3 min; else `degraded` if !health.etw_ok or etw_events_lost increased in last hour; else `online`.

| Method | Path | Notes |
|---|---|---|
| GET | `/devices?q=&status=&group_id=&limit=&cursor=` | list of Device |
| GET | `/devices/:id` | `{device: Device, duplicates: [{id, hostname, first_seen, last_seen, decommissioned}], inventory: Inventory, recent_alerts: [Alert row], effective_policy: Policy, hardening: [{control, desired, applied: bool\|null, source, report_only?: true, pending_reboot?: true}]}` |
| PATCH | `/devices/:id` | `{group_id?, tags?}` (`devices.write`) |
| DELETE | `/devices/:id` | decommission: revoke cert (`devices.write`) |
| GET | `/devices/:id/events?kinds=process_start,net_connect&q=&from=&to=&limit=` | `{items: [Event + {device_id}]}` from ClickHouse, newest first |
| GET | `/devices/:id/processes?at=ms` | process tree reconstructed from events: `{items: [ProcessInfo]}` |
| POST | `/devices/:id/actions` | `{action: ResponseAction, incident_id?, comment?}` → `ResponseActionRow` (privilege = `ResponseAction::privilege()`). `kill_process` / `suspend_process` / `resume_process` require `guid` (400 without) |
| POST | `/devices/:id/uninstall-token/reveal` | → `{token: string|null, pending_token: string|null}` (`devices.write`; audit `device.uninstall_token_revealed`) |
| POST | `/devices/:id/uninstall-token/rotate` | → `{pending_token, token_active: false, sent: bool, message}` (`devices.write`; audit `device.uninstall_token_rotated`). The new token is stored as pending and sent to the agent as `ServerPayload::SetUninstallToken` now (`sent: true`) or on its next connect. When the agent acks that message the token becomes current (audit `device.uninstall_token_activated`, `uninstall_token_pending` → false); until then the previous token keeps working. Rotating again before the ack supersedes the earlier pending token, which is then never promoted |
| POST | `/devices/:id/merge` | `{device_id}`: move that device's alerts, incidents, actions, quarantine and reviews into `:id`, then decommission it (`devices.write`) → Device |
| POST | `/devices/:id/duplicates/dismiss` | `{device_id}`: the two are separate machines; clears the flag on both (`devices.write`) → 204 |

Hardening rows (`/devices/:id` and dashboard `hardening_coverage`) cover the v1.1 controls too: `wdigest_off`, `asr_lsass`, `lsa_protection`, `report_vulnerable_driver_blocklist`, `task_scheduler_log`. A stored policy that predates a control counts with the control's `Hardening::default()` value. `applied` is `null` when the agent has not reported the control (older agent). `report_only: true` marks `report_vulnerable_driver_blocklist`: `applied` then means "Windows has the blocklist on"; Kestrel never changes it and the console never counts it as drift. `pending_reboot: true` is set when the agent reports `AgentHealth.hardening["<control>_pending_reboot"] = true` (LSA protection is configured but needs a reboot the agent never triggers); the console shows "Pending reboot" instead of "Drifted". **Contract gap:** the agent-side key `lsa_protection_pending_reboot` is a proposal of this server/console change — the Windows hardening module must emit it.

Device event timelines and hunt results render the v1.1 events (`file_activity`, `task_registered`, `service_installed`, `wmi_subscription`, `registry_set` with `op`, `process_access` with `return_code`) in plain words; the raw JSON stays one click away.

### Groups & enrollment

`Group = {id, name, description, policy_id, device_count}`

| Method | Path |
|---|---|
| GET/POST | `/groups` (POST `{name, description, policy_id}`) |
| PATCH/DELETE | `/groups/:id` |
| GET | `/enrollment-tokens` → `[{id, group_id, group_name, token_prefix, created_at, expires_at, max_uses, uses, revoked}]` |
| POST | `/enrollment-tokens` `{group_id, expires_in_days (default 7, 1-90), max_uses (default 50, 1-10000)}` → includes full `token` **once** plus `install_command` (PowerShell one-liner with msiexec properties) |
| DELETE | `/enrollment-tokens/:id` (revoke) |
| GET | `/agent/installer` → metadata `{version, msi_url, sha256}` |

### Incidents & alerts

Alerts are grouped into incidents server-side: same device + same root process tree (topmost non-system ancestor GUID) within 30 min → same incident; an open incident whose root is one of the alert's ancestors (e.g. ClickFix: `explorer.exe` RunMRU alert → `powershell.exe` → payload, all rooted at system-path binaries) also absorbs it (exact root match preferred); otherwise new incident.

`AlertRow = {id, incident_id, device_id, hostname, ts, rule_id, rule_name, rule_author, severity, attack: [string], mode, summary, process_guid, image, data_at_risk: [DataCategory], actions: [ActionOutcome], status: "new"|"acknowledged"|"closed"}`

`Incident = {id, title, severity, priority: 0-100, status: "open"|"in_progress"|"resolved"|"dismissed", classification: null|"true_positive"|"false_positive"|"benign", assignee: User|null, device_id, hostname, user, created_at, updated_at, alert_count, rule_ids: [string], attack: [string], data_at_risk: [DataCategory], contained: bool}`

Priority = max alert severity base score + 10 if any `data_at_risk` + 10 if an **impact-stage** rule fired + 5 if not contained, capped at 100. Impact stage (v1.1) = an exfiltration-stage stealer rule (ST-04/ST-14) **or any ransomware `RW-xx` or credential-dumping `CD-xx` rule** — encryption and a finished OS-credential dump are where the damage is done, like stolen data leaving the device. Persistence (`PS-xx`) alone does not add it. SigmaHQ pack hits (`SIG-*`) never add it; the builtin they corroborate does.

Title auto-generated, first match wins: all alerts `TP-*` → `"Agent tampering on {host}"`; any `RW-*` → `"Ransomware activity by {image} on {host}"`; any `data_at_risk` → `"Credential theft by {image} on {host}"`; any `CD-*` → `"Credential dumping by {image} on {host}"`; exfil-stage → `"Possible data exfiltration by …"`; any `PS-*` → `"Persistence planted by {image} on {host}"`; else `"{top rule name}: {image} on {host}"`. `{image}` is the first non-system process of the tree (the payload, not explorer/services).

| Method | Path | Notes |
|---|---|---|
| GET | `/incidents?status=&severity=&assignee=me|<id>&device_id=&q=&sort=priority|created&limit=&cursor=` | list |
| GET | `/incidents/:id` | `IncidentDetail` (below) |
| PATCH | `/incidents/:id` | `{status?, assignee_id?, classification?}` |
| POST | `/incidents/:id/comments` | `{body}` → Comment |
| POST | `/incidents/:id/checklist/:item_id` | `{done: bool}` |
| GET | `/alerts?…same filters…` | list of AlertRow |
| GET | `/alerts/:id` | full `Alert` (kestrel-common) + `{incident_id, device_id, hostname, status}` |
| PATCH | `/alerts` | bulk `{ids: [..], status}` |

`IncidentDetail = Incident + {`
- `storyline: string` — plain-language markdown narrative built from alerts in time order. Evidence is rendered in words under each alert: `file_activity` as *"renamed 412 files in 37 folders within 10 s, new extension `.k3str` (95%), 96 on network shares; created `readme.txt` in 37 folders (likely ransom note)"*, scheduled tasks / services / WMI subscriptions with their action or command, registry sets and deletions, `process_access` to lsass with its mask and, when `return_code ≠ 0`, *"refused by Windows (status 0xc0000022)"*. Family blocks (`> …` quote): RW → active ransomware, keep isolated, check shares and backups, do not pay; CD → every account that logged on is compromised; PS → whether the entry was removed (with vault backup ids from `ActionOutcome.artifact`) or is still in place, and to compare autoruns against a clean device.
- `alerts: [AlertRow]`
- `process_tree: [{guid, parent_guid, pid, image, cmdline, user, start_ts, exit_ts, signer, signed, sha256, path_class, alert_rule_ids: [string], is_root: bool}]`
- `timeline: [{ts, kind: "alert"|"action"|"comment"|"status", title, detail, actor}]`
- `evidence: [Event]` (merged, dedup, ≤200)
- `network: [{ts, process_guid, image, dst_ip, dst_port, dst_host, blocked: bool}]`
- `actions: [ResponseActionRow]`
- `checklist: [{id, text, kind: "done"|"approve"|"manual", done: bool, action?: ResponseAction}]` — Huntress-style: what the agent already did / one-click actions awaiting approval / manual steps (e.g. revoke sessions per `DataCategory::remediation()`). v1.1 family steps (deduplicated per incident):
  - **RW-xx**: keep isolated and powered on; verify offline/immutable backups and surviving VSS before restoring; check every writable share for the new extension; do not pay, preserve the ransom note + one encrypted sample; reset passwords of accounts used on the host; assess PDPA (PDPC, 3 days) / UU PDP (3×24 h) notification. Isolation is an approval when not already done.
  - **CD-xx**: reset passwords of every account that logged on (admins first); rotate service-account and local-admin credentials (force a LAPS rotation); look for lateral movement from the host; if a domain admin logged on, krbtgt double reset; make sure no dump file remains; enable LSA protection + WDigest-off.
  - **PS-xx** (and CD-07/CD-12 registry evidence): an `approve` item with a `remove_autorun` action per persistence entry in the evidence that Kestrel knows how to remove safely — scheduled task (`\Path`), service (name), WMI consumer (quoted name), Run/RunOnce value, IFEO `Debugger`, SilentProcessExit value, Startup-folder file, and WDigest `UseLogonCredential` restored with `restore_data: "dword:0"`. Never for entries containing "kestrel"; Winlogon/AppInit/COM and other locations become manual steps. Plus a `collect_triage` approval and "compare the autoruns list with a clean device". Done items for a successful `remove_autorun` name the vault backup (`ActionOutcome.artifact`).
  - The "where did it come from" step is added for ST, RW, CD and PS incidents.
- `comments: [{id, author: User, body, ts}]`
`}`

### Response actions

`ResponseActionRow = {id, device_id, hostname, incident_id, action: ResponseAction, status: "pending"|"sent"|"succeeded"|"failed"|"expired", requested_by: User|null (null = automatic), comment, created_at, completed_at, result_detail, artifact: string|null}`

`artifact` is `ActionOutcome.artifact` (quarantine id, triage path, WFP filter id, or for `remove_autorun` the id of the vault backup of the removed entry). Quarantine ids come from it when present, else from parsing `result_detail`. `remove_autorun` backups are **not** listed in `/quarantine` (there is no restore action for them yet — `RestoreAutorun` is deferred).

`POST /devices/:id/actions` validates `remove_autorun` (privilege `response.file`): `location` 1-1024 printable characters and never containing "kestrel"; `registry_value` → absolute `HKLM\…`/`HKU\…` key; `scheduled_task` → starts with `\`; `startup_file` → path inside a `\Start Menu\Programs\Startup\` folder; `service`/`wmi_subscription` → bare name; `restore_data` only for `registry_value`; `value_name`/`restore_data` ≤ 2048 chars, no NUL. The console only issues it from incident checklist approvals, behind a confirmation dialog.

| GET | `/actions?device_id=&status=&limit=&cursor=` |

### Policies, rules, exclusions, IOCs

| Method | Path | Notes |
|---|---|---|
| GET | `/policies` | `[{id, name, version, updated_at, group_count, device_count}]` |
| GET | `/policies/:id` | `Policy` (kestrel-common) |
| POST | `/policies` | `{name, clone_from?}` |
| PUT | `/policies/:id` | full `Policy`; server bumps `version`, pushes to agents (`policies.write`). v1.1 adds `sensors: {file_activity, ransomware_canaries, persistence, credential_access}` (all default true) and the hardening controls listed under Devices; the policy editor has a Sensors section and shows each new control's caveat (LSA protection needs a reboot and can block unsigned LSA plug-ins; the ASR LSASS rule only works where Defender is the active AV; the driver blocklist is report-only) |
| DELETE | `/policies/:id` | 409 if assigned |
| GET | `/rules` | `[RuleMeta + {enabled_custom: bool, hits_7d: int}]` — builtin catalog from `Engine::catalog()` plus custom rules and the SigmaHQ pack. The console groups by `category` (incl. `ransomware`, `credential_dumping`, `persistence`) with icon + label, and treats a `sigma` rule whose `license` is DRL and whose `references` contain a commit-pinned `https://github.com/SigmaHQ/sigma/blob/<40-hex>/…` URL as a **SigmaHQ pack** rule: it shows the author, "Detection Rule License (DRL) 1.1" and that upstream link |
| POST | `/rules` | custom Sigma rule `{source}` → validated server-side (compile with kestrel-detect) (`rules.write`) |
| PATCH/DELETE | `/rules/:id` | custom rules only |
| GET/POST | `/exclusions` | `Exclusion` (+ `{policy_id, created_by, created_at}`); POST may include `{from_alert_id}` to prefill. Rejected (400): `TP-*` rule ids, path values that start with a wildcard, are a bare wildcard / drive root / whole system or user folder, or wildcard below fewer than two literal folders; wildcards in image/signer values. `policy_id: null` (global) needs `policies.write` |
| DELETE | `/exclusions/:id` | |
| GET | `/exclusions/preview?kind=&value=&rule_id=` | `{matching_alerts_30d: int, sample: [AlertRow]}` — scope preview before saving |
| GET/POST | `/iocs`, DELETE `/iocs/:id` | `Ioc` (+ `{created_by, created_at, hits}`); POST bulk accepts `{items:[...], confirm_broad?}`. IP IOCs wider than /16 (IPv6 /48) or in private/loopback/link-local ranges need `confirm_broad: true` (per item or bulk); wider than /8 (IPv6 /32) are always refused |

IOC-triggered network blocks (`BlockDestination` issued by the engine on an IOC network/DNS hit) are scoped to the offending image (`image` set) unless the policy sets `ioc_block_host_wide`, and always carry `ttl_secs` = `policy.ioc_block_ttl_secs` (default 86400, at least 60). Deleting an IOC does not lift blocks already in place; they expire with their TTL.

Policy fields added by the 2026-10-21 security fixes (serde defaults, so older stored policies load unchanged), validated on `PUT /policies/:id`:

| Field | Default | Range | Meaning |
|---|---|---|---|
| `isolation_auto_release_hours` | 72 | 0–720 (0 = never) | The agent lifts host isolation by itself when it has not reached the server for this long since the later of the isolation start and the last server contact (checked every minute and at boot) |
| `ioc_block_ttl_secs` | 86400 | 60–2592000 | Lifetime of WFP blocks created by IOC hits |
| `ioc_block_host_wide` | false | — | IOC hits block the destination for every process instead of only the offending image |

Exclusions and IOCs are stored per policy (`policy_id`; `null` = global, merged into every policy) and pushed as part of `Policy`.

### Quarantine & review requests

| GET | `/quarantine` → `[{id, device_id, hostname, sha256, original_path, alert_id, state: "held"|"restored"|"deleted", created_at}]` |
| POST | `/quarantine/:id/restore`, `/quarantine/:id/delete` (`response.file`) |
| GET | `/review-requests?state=` → `[{id, device_id, hostname, user, alert_id, rule_name, file, justification, state: "requested"|"approved"|"denied", decided_by, decided_at, created_at, exclusion_scope: {kind: "sha256"|"signer", value, rule_id, policy_id, policy_name, expires_in_days}|null}]` |
| POST | `/review-requests/:id/decision` `{approved: bool, message, create_exclusion: bool}` → sends `ServerPayload::ReviewDecision`. `create_exclusion` creates exactly `exclusion_scope` (the file's sha256, or its signer when the signature is valid; the alert's rule; the device's group policy; 90-day expiry) and is refused (400) when `exclusion_scope` is null — never a path or file-name exclusion |

Agents can only file review requests for their own alerts; `user` is pseudonymised under `privacy.hash_usernames`.

### Hunt (v1: simple)

`POST /hunt` `{query: string, from, to, limit}` — `query` is a filter expression over the ClickHouse `events` table: `field op value` joined by `and`/`or`, ops `=`, `!=`, `~` (contains, case-insensitive), `>`/`<` for numbers. Fields: `event_type, image, cmdline, file_path, dst_ip, dst_port, dns_qname, signer, sha256, user, hostname, device_id, reg_key, reg_value, target_image, granted_access, return_code, op, new_ext`. Numeric fields (`dst_port`, `granted_access`, `return_code`) accept decimal or `0x` hex and reject `~`. Server parses into a parameterised SQL (never string-concatenated). → `{items: [Event + {device_id, hostname}], elapsed_ms}`.

Column mapping per event type (both backends; the full event JSON is always kept in `raw` and returned):

| event_type | file_path | cmdline | reg_key | reg_value | op (`file_op`) | other |
|---|---|---|---|---|---|---|
| `process_start` | — | command line | — | — | — | image, user, signer, sha256 |
| `file_access` / `image_load` | path | — | — | — | file op | signer (image_load) |
| `registry_set` | — | value data | key | value name | `set` / `delete_value` / `delete_key` | |
| `process_access` (+ remote_thread, thread_context, debug_attach) | — | — | — | — | — | `target_image`, `granted_access`; `return_code` (from `raw`) |
| `file_activity` | first canary hit, else first sample path | — | — | — | `activity` | `new_ext` = `top_new_ext` (from `raw`) |
| `task_registered` | task path (`\Folder\Name`) | Exec actions joined by ` \| ` | — | — | `created` / `updated` / `deleted` | `user` = run-as principal |
| `service_installed` | ImagePath | ImagePath | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` | — | `install` | `user` = service account |
| `wmi_subscription` | — | consumer (+ command) | `<namespace>\<filter>` | — | `bind` | |

`reg_value`, `return_code` and `new_ext` read the stored JSON in the Postgres fallback (`raw->>…`); ClickHouse uses the `reg_value` column and `JSONExtract*` on `raw`. No schema migration was needed. Example hunts: `target_image ~ lsass.exe and return_code != 0`, `event_type = file_activity and new_ext = k3str`, `event_type = task_registered and cmdline ~ appdata`, `reg_key ~ \CurrentVersion\Run and op = set`.

### Users, tokens, settings, audit

| GET/POST | `/users` (POST `{email, name, role, password?}`) ; PATCH `/users/:id` `{role?, disabled?, name?, password?, oidc_subject?: string|null}` (`oidc_subject` links the account to the IdP `sub` under the configured issuer; null unlinks) ; DELETE |
| GET/POST/DELETE | `/api-tokens` → `{id, name, prefix, created_at, last_used, privileges, expires_at}`; POST `{name, privileges, expires_in_days? (default 90, ≤ 730)}` returns full token once |
| GET/PUT | `/settings` → `Settings` |
| GET | `/audit-log?actor=&action=&limit=&cursor=` → `[{id, ts, actor: {id, email}|null, action, target, details, hash, prev_hash}]` (`audit.read`) |
| GET | `/audit-log/verify` → `{ok: bool, broken_at: id|null, count}` (hash-chain verification) |

`Settings = {org_name, branding: Branding, retention_days: {events: 30, alerts: 365, audit: 730}, notifications: {email: {enabled, smtp_host, smtp_port, username, from, to: [string], min_severity}, slack: {enabled, webhook_url, min_severity}, teams: {enabled, webhook_url, min_severity}, webhook: {enabled, url, secret, min_severity}, syslog: {enabled, host, port, protocol: "udp"|"tcp"|"tls", format: "cef"|"json", allow_private: false}}, oidc: {enabled, issuer, client_id, client_secret_set: bool, allowed_domains: [string], default_role}, session_timeout_minutes: 480, session_max_days: 7, require_mfa: false}`

Secrets (`client_secret`, SMTP password, webhook secret) are write-only: GET returns `*_set: bool`. Slack/Teams/webhook URLs are returned only to `settings.write` (others get `""` plus `webhook_url_set` / `url_set`).

Validation: `oidc.enabled` needs an https issuer, `client_id` and at least one `allowed_domains` entry (an empty list denies every SSO login); `oidc.default_role` cannot be a `*` role. Webhook/Slack/Teams URLs and the OIDC issuer must resolve to public addresses (private ranges only via `KESTREL_OUTBOUND_ALLOW_CIDRS`; redirects are not followed). A private syslog host needs `syslog.allow_private`; link-local / metadata addresses are always refused. `session_max_days` 1-90.

### Live updates

`GET /events/stream` — Server-Sent Events: `event: incident` / `alert` / `device` / `action` with JSON `{id, type: "created"|"updated"}` so the console refreshes rows without polling. The session (or API token) is re-validated every 60 s; when it is no longer valid the server sends `event: session` `{"type":"expired"}` and closes the stream.

### Agent transport rules (server side)

- Enrollment always creates a new device id; a matching `os.hw_uuid` only flags `possible_duplicates`. `EnrollResponse.uninstall_token` is issued per device (`kun_…`).
- `AgentPayload::RenewCertificate{csr_pem}` on the stream → `ServerPayload::Certificate{cert_pem, ca_pem}` (CN = stream device id). The server sends `ServerPayload::RenewCertificate` after Hello when the presented certificate expires within 30 days. Older certificates of the device are revoked when it first connects with a newer one. At most 3 stream renewals per device per 10 minutes.
- `Hello.outbox_epoch` (random UUID created with the agent's outbox database, constant across restarts) change → the per-device seq high-water mark resets to 0 (`TP-SRV-OUTBOX-RESET`). Agents that send no epoch keep the old behaviour.
- Heartbeats: duplicates are detected by `seq`; `ts` is clamped to server time.
- `ServerPayload::SetUninstallToken{token}` carries a rotated uninstall token. The server tracks its seq like `Command` / `Policy` / `Rules` and promotes the pending token when the agent acks that seq and the token is still the pending one. It is re-sent after `Hello` while a rotation is pending and is never queued in `pending_messages` (no plaintext token at rest outside the sealed column).
- `ServerPayload::Update(UpdateManifest)`: `signature` is base64 Ed25519 over the UTF-8 bytes of `kestrel-update-v1\n{version}\n{url}\n{sha256}` (fields trimmed, sha256 lower-case hex; version and url must not contain line breaks), verified against the key embedded at build time (`KESTREL_UPDATE_PUBKEY`). The server does not send updates yet.

### Agent transport rules (agent side)

- Every server message with `seq > 0` is acked (`AgentPayload::Ack{seq}`, envelope seq 0) after it was handled. Exception: a `SetUninstallToken` whose new hash could not be stored (or an empty / oversized token) is not acked, so the server keeps it pending and re-sends it on the next connect.
- `SetUninstallToken`: the agent replaces `uninstall_token_hash` in `agent.toml` (Argon2id PHC; the token itself is never stored or logged) by writing a temp file, flushing it and renaming it over `agent.toml`, then acks. `kestrel-agent uninstall` / `release-isolation` verify against the new hash from then on.
- Certificate renewal: with < 30 days left (checked after `Welcome` and daily) or on `ServerPayload::RenewCertificate`, the agent creates a new key + CSR and sends `AgentPayload::RenewCertificate` (seq 0). On `Certificate` it swaps key and certificate (keeping the previous pair), reconnects, and deletes the previous pair after the next `Welcome`; after 3 failed connects with the new identity it restores the previous one. An interrupted swap is repaired at start.

## Agent CLI and tray (endpoint)

- `kestrel-agent uninstall --token <t>` and `kestrel-agent release-isolation --token <t>` (also `KESTREL_UNINSTALL_TOKEN`) need the device's uninstall token and administrator rights. `release-isolation` is the local break-glass for an isolated host that cannot reach the server: it removes Kestrel's isolation filters and the running service does not re-apply them.
- The MSI no longer takes an uninstall token at install; the server issues it at enrollment. If the server issues none (old server), `install` writes a random one to `C:\ProgramData\Kestrel\uninstall-token.txt` (administrators only), replaced at the next enrollment. MSI uninstall still needs `UNINSTALL_TOKEN=`.
- Tray pipe (`kestrel_common::tray`): every request is attributed to the pipe client's identity (its process token). `Activity` returns the caller's own items plus machine-wide ones; notifications go only to their owner's tray; `RequestReview` only for alerts the caller can see, once per alert until IT decides, at most 5 per user per hour; `QuickCheck` at most once per 5 minutes (a recent result is returned otherwise).

## Built-in rule semantics changed by the security fixes

- **ST-16 (canary tripwire).** Ignored readers: the agent itself, PID 0/4, and validly signed security, search-indexer, backup and management tools on the allow-list (Unknown signatures never count). In Protect mode a hit kills the reader's process tree, blocks the image's network (`BlockImageNetwork`, 24 h TTL) and quarantines the image; `IsolateHost` (server IPs permitted) is added **only** when the reader is unsigned / invalid / unknown **and** runs from a user-writable path. A hit by the store's own application (e.g. Chrome reading the decoy profile) is a High alert without actions.
- **Protected processes** (kill / suspend refused): one shared list for engine and agent, matched by name **and** exact path on the system volume **and** a valid Microsoft signature (Defender only in its real install directories).
- **Signatures:** `Unknown` is never trusted (owners, benign readers, allow IOCs, signer exclusions, protected processes). Late hash / signature facts re-run hash and cert IOCs, ST-12 and ST-08(b). Revoked certificates count as `Invalid`.
- **Exclusions:** path values keep the drive, `*` matches within one path segment and `**` across segments; exclusions never apply to `TP-*` rules.
- **ST-11** kills only the `nslookup` child, not its parent shell.

---

## Server storage

- **PostgreSQL** — control plane (tables per the research report's data model: orgs/settings, devices, agent_certs, enrollment_tokens, groups, policies, rules, exclusions, iocs, alerts, incidents, incident_comments, checklist, response_actions, quarantine_items, review_requests, users, roles, api_tokens, sessions, audit_log hash-chained).
- **ClickHouse** — `events` table (MergeTree, `PARTITION BY toDate(ts)`, `TTL` from settings), schema per report. Optional: if `CLICKHOUSE_URL` is unset the server stores events in a Postgres `events` table with a 7-day retention (small deployments / dev).

## Ports (docker compose)

| Port | Service |
|---|---|
| 443 | Console + REST (`/api`), TLS (self-signed by default, or `TLS_CERT`/`TLS_KEY`) |
| 8443 | Agent gRPC (mTLS) |
