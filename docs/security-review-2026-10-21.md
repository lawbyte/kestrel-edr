# Kestrel EDR: independent security review

Scope: `/home/claude/kestrel` (server, agent, kestrel-win, kestrel-detect, console, tray, installer), read-only.
Method: manual code-path review against `docs/contracts.md` and the research report (v1 rule table, risks). Nothing was built or run on Windows. Each finding below was traced through the actual code. Where exploitation depends on Windows behaviour I could not run here, the finding says **Unconfirmed (runtime)**. In those cases the code path itself is still confirmed.

**Totals: Critical 0, High 10, Medium 12, Low 12.**

Areas that held up well: every REST route calls `require`. Hunt and ClickHouse queries are fully parameterised. CSRF uses SameSite=Strict plus a header. Passwords use Argon2id and secrets are sealed with AES-GCM. The CSR signer forces CN, EKU and no-CA. mTLS pins only the agent CA with no system roots. `Hello.device_id` is bound to the cert CN. `ActionResult` is scoped by `device_id`. Console and tray markdown renderers produce React nodes only, and links are scheme-checked. CSP is strict. Killing by GUID re-validates start time on the same handle.

---

## HIGH

### H1. Any user can make a process unkillable and unsuspendable by naming or placing it like Defender or a System32 binary
- **Where:** `crates/kestrel-win/src/filters.rs:53-65` (`is_critical_image`, `is_security_product`), enforced in `crates/kestrel-win/src/win/respond.rs:58-63` (`open_target`, used by kill, suspend and resume); `crates/kestrel-common/src/event.rs:304-338` (`PathClass::of` ignores the drive letter).
- **Scenario:**
  - `is_security_product` returns true for any path that contains `\windows defender\`, or any file named `msmpeng.exe`/`mssense.exe`. A stealer at `%TEMP%\Windows Defender\setup.exe` or `%TEMP%\x\MsMpEng.exe` cannot be killed or suspended. Every engine Protect action, suspend window and analyst Kill returns `refusing to act on security product`.
  - `is_critical_image` trusts `PathClass::System`. That class is computed without the drive letter and with a prefix match. So `C:\Windows\System32\spool\drivers\color\svchost.exe` (a user-writable directory) and `E:\Windows\System32\lsass.exe` (an ISO a standard user mounted) are both "critical" and refused.
  - Quarantine of a running image only renames the file. ST-04 `BlockDestination` blocks one IP. Exfiltration continues.
- **Fix:** For security products, match the exact install directories (`%ProgramFiles%\Windows Defender\`, `%ProgramData%\Microsoft\Windows Defender\Platform\<ver>\`) and require a valid Microsoft signature, not a substring or file name. For critical images, require the exact `%SystemRoot%\System32\<name>` path on the system volume, a valid Microsoft signature, and ideally PPL or `IsProcessCritical`. Make `PathClass::of` volume-aware: only `%SystemDrive%` is System, and known user-writable System32 subdirectories are excluded.

### H2. Anyone with an enrollment token can take over an existing device's identity via `hw_uuid` and silently blind it
- **Where:** `crates/kestrel-server/src/grpc.rs:169-203` (re-enrollment by client-supplied `req.os.hw_uuid`; revokes all of the victim's certs and reissues for the victim's `device_id`). Also `ingest.rs:51` (`Hello` can overwrite `hw_uuid`).
- **Scenario:**
  1. The attacker has a token. Tokens are multi-use (100 uses, 7 days by default), sit in GPO/Intune scripts and appear on command lines (see M6).
  2. The attacker learns a victim's SMBIOS UUID. Any user can read their own host's UUID with `wmic csproduct get uuid`, and cloned VMs often share one.
  3. The attacker sends a crafted `Enroll` with the victim's `hw_uuid`.
  4. The server revokes the real agent's certificate. The real agent gets `permission_denied` forever: `pending_enroll_token` was cleared, so it cannot re-enroll.
  5. The attacker receives a valid cert for the victim's `device_id` and the token's group (a policy change). It can send healthy heartbeats so the console shows "online", receive queued commands (isolate, kill) and fake their results, and inject alerts or review requests.

  A standard-user malware with a leaked token can do this to its own host.
- **Fix:** Never re-bind identity from client-asserted hardware facts. Option A: re-enrollment of an existing device requires proof of the old key (mTLS renewal) or an admin "approve re-enrollment" step. Option B: create a new device and let an admin merge it. At minimum, raise a TP alert when a live, recently heartbeating device is re-enrolled. Make tokens single-use or short TTL by default.

### H3. Agent certificates are never renewed, so the whole fleet goes dark 365 days after enrollment
- **Where:** `crates/kestrel-server/src/pki.rs:21` (`AGENT_CERT_VALIDITY_DAYS = 365`), `grpc.rs:91` (expired → reject). The agent has no renewal code: `grep renew` in `crates/kestrel-agent/src` returns nothing, and `transport.rs:76-91` only enrolls when no cert exists. The server renewal path (`grpc.rs:134-150`) is never called by the agent. The research report specifies 30-day renewal.
- **Scenario:** One year after rollout, every endpoint's TLS handshake fails at the same time. There is no telemetry, alerts, policy or commands. Recovery needs a fresh token and a manual `enroll` on every machine, because the pending token was wiped.
- **Fix:** Have the agent renew at about 2/3 of validity (or every 30 days) through the existing empty-token mTLS `Enroll`, with an atomic key and cert swap. Have the server alert on certs that are about to expire.

### H4. A standard user who pre-creates `C:\ProgramData\Kestrel` before install owns the agent state (keys, config, vault, updates)
- **Where:** `crates/kestrel-win/src/win/util.rs:659-664` (`SDDL_ADMIN_ONLY_DIR` has no `O:` owner, so `ensure_private_dir` never changes ownership); `installer/Kestrel.wxs:53-61` (PermissionEx sets ACEs only); `crates/kestrel-agent/src/commands.rs:42-47` (`write_install_config` keeps the existing `agent.toml`'s `uninstall_token_hash`).
- **Scenario:**
  1. Users can create folders under ProgramData. Malware already on the machine, or an insider, creates `C:\ProgramData\Kestrel` and owns it.
  2. After install, the owner keeps WRITE_DAC and rewrites the DACL.
  3. The user can then read `keys\agent.key` (impersonate the device), edit `agent.toml` `server` and `ca_pem` (redirect the agent to an attacker server that sends SYSTEM `QuarantineFile` or `RestoreFile` commands), delete or modify the outbox (`kestrel.db`), and swap `updates\*.msi` between the hash check and `msiexec`.
  4. Vault blobs can be forged because `key.dpapi` is machine-scope DPAPI, which any local user can decrypt.
  5. A pre-planted `agent.toml` also sets an uninstall token the attacker knows.
- **Fix:** At install and at every start, verify the state directory and children are owned by SYSTEM or Administrators. Set the owner explicitly (`O:SY`) and reset child ACLs. If the directory existed before install and was not created by the MSI, delete or quarantine it and recreate it. Never inherit config from a pre-existing `agent.toml` on a fresh MSI install.

### H5. OIDC logs into any existing account, including local password admins, by email match, and treats a missing `email_verified` as verified
- **Where:** `crates/kestrel-server/src/api/oidc.rs:213-221` (`email_verified() == Some(false)` is the only rejection), `:251-266` (`WHERE oidc_sub = $1 OR lower(email) = $2`, then `COALESCE(oidc_sub, $2)`).
- **Scenario:**
  - An IdP user whose `email` claim equals `admin@corp.com` is logged in as the local admin. This works even if that admin never used SSO, and even if the account is already linked to a different `sub`.
  - Entra ID tokens often omit `email_verified`, and the `email` attribute can be user- or tenant-controlled ("nOAuth"). Any tenant or guest user who can set that attribute takes over the admin account.
  - MFA does not help: OIDC sessions skip `require_mfa`.
- **Fix:**
  - Bind accounts by `(issuer, sub)` only.
  - Auto-link a local account only when an admin pre-sets the `sub`, or the user proves the local password once.
  - Require `email_verified == Some(true)`.
  - Never link to an account whose `oidc_sub` is already set to a different value.

### H6. An empty OIDC domain allow-list is fail-open, so every account at the IdP is auto-provisioned
- **Where:** `oidc.rs:223-229` (`if !cfg.allowed_domains.is_empty() && …`); `settings.rs:182-191` (empty by default, `default_role` readonly). `settings_routes.rs:83-89` allows `default_role = "admin"`.
- **Scenario:**
  - With issuer `https://accounts.google.com` (or any multi-tenant issuer) and no domains configured, any Google account on the internet gets a session. It can read every endpoint's telemetry, command lines, incidents and users list through `read`.
  - With a single-tenant Entra issuer, every B2B guest gets the same access.
  - If the admin set `default_role=admin`, it is full takeover.
- **Fix:** Refuse `oidc.enabled` with an empty `allowed_domains` unless the admin explicitly sets an "allow all" flag. Default new SSO users to a no-privilege "pending" role that needs admin approval. Do not allow `default_role` to be `admin`.

### H7. First execution of any new binary is seen with `signed=Unknown` and no `sha256`, so hash IOCs, ST-12 and signature trust silently fail
- **Where:** `crates/kestrel-win/src/win/translate.rs:302` (`file_or_request(...).unwrap_or_default()`: a cache miss only queues hashing and emits the event with default facts); `crates/kestrel-win/src/win/enrich.rs:123-131`. Nothing re-feeds facts to the engine. `crates/kestrel-detect/src/engine.rs:1235,1371-1384` (hash/cert IOCs only at ProcessStart), `:1327` (ST-12 requires `Unsigned|Invalid`), `:926-941` and `paths.rs:557-577` (`Unknown` passes "signed" checks).
- **Scenario:**
  - A freshly downloaded stealer, which is always first-seen, runs with `sha256=None` and `signed=Unknown`. A `block` sha256 IOC never fires on that run. ST-12 never fires. ST-08(b) never fires.
  - `system_trusted` and `protected()` treat Unknown as signed. So a binary in a writable System or Windows directory counts as a trusted reader, and one named `svchost.exe` there is "protected".
  - `is_trusted_owner` is name-based and only rejects Unsigned. A stealer renamed `chrome.exe` under `%LOCALAPPDATA%\…` is the "owner" of the Chrome stores, so ST-01, ST-02 and ST-04 never trigger.
  - Quarantine actions carry `sha256: None`, so the TOCTOU hash check in H8 is skipped.
- **Fix:**
  - For images in user-writable or external paths, compute hash and signature synchronously (bounded size), or hold the ProcessStart until enrichment completes, as is already done for command lines.
  - Alternatively, emit a later `ProcessFacts` update and re-run IOC, ST-12 and owner checks.
  - Treat `Unknown` as untrusted everywhere a trust decision is made.

### H8. Quarantine and restore run as SYSTEM with backup semantics and follow junctions, which allows bricking the host or writing arbitrary files
- **Where:** `crates/kestrel-win/src/win/quarantine.rs:96-113` (`CreateFileW(... FILE_FLAG_BACKUP_SEMANTICS)` without `FILE_FLAG_OPEN_REPARSE_POINT`, no final-path check), `:120-128` (`takeown /a` + `icacls` run **before** the optional hash check at `:152`), `:191-221` (delete, or rename + deny-execute + delete-at-reboot), `:229-251` (restore: `create_dir_all(parent)` + create + rename at `original_path`, then re-apply the original user-owned DACL). Server-issued `QuarantineFile` paths are not restricted at all (only the engine filters to user-writable).
- **Scenario A (brick):**
  1. A stealer lives at `C:\Users\bob\Downloads\x\explorer.exe` (or `winlogon.exe`).
  2. After detection, a helper process replaces `x` with a junction to `C:\Windows`. The hash is usually `None` (H7).
  3. The agent encrypts and deletes, or renames and deny-executes, the real `C:\Windows\explorer.exe`. The host is broken after reboot.
- **Scenario B (LPE):**
  1. The user replaces the quarantined file's parent directory with a junction to `C:\Windows\System32` or a service directory.
  2. The user files a tray review ("false positive, please restore").
  3. An analyst clicks Restore. SYSTEM writes the attacker's file there and applies the user's original DACL.
  4. ST-15 already quarantines sideload DLLs, so a DLL-name plant leads to code execution as SYSTEM or another user.
- **Unconfirmed (runtime):** the race timing in scenario A. The code paths are confirmed.
- **Fix:**
  - Open with `FILE_FLAG_OPEN_REPARSE_POINT`, reject reparse points in every path component, and compare `GetFinalPathNameByHandle` with the requested path.
  - Refuse System, Windows and ProgramFiles targets for server commands unless the hash matches an IOC.
  - Make sha256 mandatory, and verify it before any ACL change.
  - On restore, create the file with `CREATE_NEW` through a handle-relative open of a parent you verified, or restore only to a fresh directory.

### H9. Turning on `block_mshta` or `block_user_path_exec` adds a local "allow Everyone *" rule that overrides a domain AppLocker allowlist
- **Where:** `crates/kestrel-win/src/win/hardening.rs:205-214` (reads `Get-AppLockerPolicy -Local` only); `crates/kestrel-win/src/applocker.rs:9-11,141-148` (if the **local** Exe collection has no foreign rules, add `ID_ALLOW_ALL` for `S-1-1-0` with path `*` and set it to Enabled).
- **Scenario:** An organisation enforces an AppLocker allowlist through GPO. GPO rules are not in the local policy, so Kestrel sees "no foreign rules" and writes a local allow-all. AppLocker merges local and domain rules as a union, so every executable is now allowed fleet-wide. One Kestrel hardening toggle disables the customer's application control.
- **Fix:** Inspect `-Effective` (and the GPO) before editing. Never add an allow-all when the effective Exe collection has any non-Kestrel rules or is configured by GPO. Report "managed by GPO, not applied" instead.

### H10. Network isolation can strand a host permanently, with no in-band release and no local break-glass
- **Where:** `crates/kestrel-win/src/win/platform.rs:221-240` (server IPs and DNS resolvers are resolved once, when isolation starts); `crates/kestrel-win/src/win/wfp.rs:453-477` (`repair` re-applies the stale `isolation_specs` every 10 s); filters are persistent across reboots (`wfp.rs:230`); `crates/kestrel-agent/src/commands.rs:216-226` (server IPs are resolved only at service start). There is no `release` CLI or tray path; the only local way out is `uninstall` with the uninstall token, which is usually unknown (see M5).
- **Scenario:**
  1. A laptop is isolated (manually, or automatically by ST-16 in day-one Protect, see M11).
  2. It roams to another network. The new DHCP DNS server is not permitted, so the agent cannot resolve the server hostname. Or the server's IP changes.
  3. The agent can never receive `ReleaseHost`. Isolation persists through reboots and only a physical visit fixes it.
  - Separately, isolation permits the server IP for **all** processes, inbound and outbound, plus all DNS to the resolvers, which leaves DNS tunnelling open.
- **Fix:**
  - Re-plan the isolation permits whenever the server address or adapter DNS changes.
  - Permit DNS only for the agent's own app id, or pin the server IP in config, and restrict the server permit to the agent's app id.
  - Add an offline release: a signed time-limited release code, or a local admin and uninstall-token `release` command.
  - Optionally add an auto-release deadline when the server has been unreachable for N hours.

---

## MEDIUM

### M1. Path exclusions ignore the drive letter and `*` spans directories
- **Where:** `crates/kestrel-detect/src/engine.rs:252-293` (`Excl::matches`), `crates/kestrel-detect/src/util.rs:10-22` (`driveless` strips the drive and `\Device\HarddiskVolumeN`), `crates/kestrel-detect/src/paths.rs:626-653` (`glob_match`: `*` matches `\`).
- **Scenario:**
  - An exclusion for `C:\Tools\backup.exe` also matches `E:\Tools\backup.exe` on a USB stick or an ISO the user mounted.
  - `C:\Users\*\AppData\Local\Vendor\app.exe` also matches `C:\Users\bob\Downloads\AppData\Local\Vendor\app.exe`.
  - In both cases the malware is excluded from all rules (or from the scoped rule).
- **Fix:** Keep the volume in the comparison and resolve to a canonical volume GUID or system drive. Make `*` match within one path segment and add `**` for recursion. Warn on, or reject, patterns that start in user-writable locations.

### M2. Approving a tray review request creates a path-based exclusion for a user-writable path across the whole policy
- **Where:** `crates/kestrel-server/src/api/quarantine.rs:220-247` (approve + create_exclusion); `crates/kestrel-server/src/api/policies.rs:306-311` (`exclusion_from_alert`: sha256 if known, else `Path` = image). The sha256 is often missing (H7). The exclusion is attached to the device's **policy**, which every device in the group shares.
- **Scenario:** A user asks for `C:\Users\bob\Downloads\tool.exe` to be allowed. Every device in that group then ignores the rule for any binary at that path. With M1 that also covers any drive. The next stealer only needs that file name in Downloads.
- **Fix:** Only allow sha256 or (valid signer + rule) exclusions from review approvals. Scope them to the single device. Set an expiry by default.

### M3. Any local user can abuse the tray pipe: spam review requests, run unlimited scans, read every user's activity
- **Where:** `crates/kestrel-win/src/win/tray_server.rs:22` (`(A;;GRGW;;;AU)`); `crates/kestrel-agent/src/tray.rs:82-119` (no rate limits; `RequestReview` attributes the request to the console's logged-on user, not the pipe client; `QuickCheck` runs a full `Scan` each time; `Activity` returns all users' items).
- **Scenario:**
  - Malware running as the user requests review of its own block in a loop. Each request becomes a server `review_requests` row plus an audit entry under the global advisory lock. This floods the SOC queue and slows audit writes.
  - Any user can spam `QuickCheck` (16 parallel connections) for CPU denial of service.
  - On RDS or multi-user hosts, users see each other's alerts and file paths.
- **Fix:** Use `GetNamedPipeClientProcessId` and the client token to identify the caller. Rate-limit per alert (one request until decided) and per session. Filter Activity by the caller's session or SID. Debounce QuickCheck.

### M4. Login rate limiting locks out real users, and the IP key can be spoofed
- **Where:** `crates/kestrel-server/src/api/auth_routes.rs:188-205` (limits are checked **before** verifying the password; email key 8 per 15 min); `crates/kestrel-server/src/auth.rs:98-109` (takes the first `X-Forwarded-For` entry, which the client controls).
- **Scenario:**
  - An unauthenticated attacker sends 8 bad logins for `admin@corp` every 15 minutes. The real admin, even with the right password and TOTP, gets 429 indefinitely, for example during an incident.
  - Behind a proxy without `KESTREL_TRUST_PROXY_HEADERS`, all users share one IP bucket (20 per 5 min).
  - With the header trusted, attackers rotate the first XFF value to bypass the IP limit.
- **Fix:** Apply progressive delay or CAPTCHA instead of a hard lock. Never block a request that has correct credentials and TOTP for an account. Use the right-most untrusted XFF entry.

### M5. The uninstall token is generated but never escrowed or shown, so MSI uninstall fails and the token may leak to MSI logs
- **Where:** `installer/Kestrel.wxs` (the `CA_Install` command line has no `--uninstall-token`; `CA_Uninstall` uses `[UNINSTALL_TOKEN]` with `Return="check"`); `crates/kestrel-agent/src/main.rs:165-169` (prints the generated token to stdout inside `WixQuietExec`); `crates/kestrel-server/src/api/groups.rs:265-272` (the install command passes no token).
- **Scenario:**
  - With a silent install, nobody ever sees the token. Uninstalling through the MSI always fails and rolls back, so admins have to take ownership of the service manually.
  - When MSI logging is on, WixQuietExec writes the command output, including the token, into the MSI log.
- **Unconfirmed (runtime):** whether QuietExec output reaches the log under every logging policy.
- **Fix:** Have the server generate a per-device (or per-token) uninstall secret and deliver it at enrollment. Store only its hash on the agent. Let `devices.write` users reveal it in the console, and audit each reveal.

### M6. Enrollment tokens leak through command lines into Kestrel's own telemetry, and default to long-lived and multi-use
- **Where:** `crates/kestrel-server/src/api/groups.rs:265-299` (`msiexec … TOKEN=…`; defaults 100 uses / 7 days, maximum 100 000 / 365 days); `installer/Kestrel.wxs` (`kestrel-agent.exe install --token "[TOKEN]"`; `HideTarget` hides it only from the MSI log); `crates/kestrel-agent/src/privacy.rs:62-73` (command lines are uploaded in full by default).
- **Scenario:** Every reinstall, upgrade or GPO run on a host that already has Kestrel, Sysmon or 4688 auditing records the token. Kestrel uploads it, and any `read` user can find it with hunt (`cmdline ~ "TOKEN="`). That token enables H2.
- **Fix:** Pass the token via a file or protected registry value deleted after use, not on the command line. Redact `TOKEN=`, `--token`, `kse_…` and `kst_…` in agent command-line telemetry. Default to single-use, 24-hour tokens.

### M7. One heartbeat with a future timestamp permanently disables heartbeat processing for the device
- **Where:** `crates/kestrel-server/src/ingest.rs:298-303` (`if hb.ts <= prev_ts { return Ok(()) }` uses the agent clock); `last_hb_ts` is reset only at re-enrollment (`grpc.rs:188-190`), never on reboot (`ingest.rs:53`).
- **Scenario:** A local admin (or an RTC fault) sets the clock forward once. From then on every heartbeat is ignored as "stale". Health stays frozen (for example `etw_ok:true`), and the server-side TP-SRV-SEQ-RESET, ETW and events-lost heuristics are blind permanently.
- **Fix:** Deduplicate on `(boot_id, seq)` instead of the agent wall clock. Clamp agent timestamps to server time ± skew. Reset on new `boot_id`.

### M8. Resetting the outbox makes the server silently discard everything as duplicates
- **Where:** `crates/kestrel-server/src/grpc.rs:325-376` (`seq <= hwm` is acked and dropped, where `hwm = devices.last_agent_seq`); `crates/kestrel-agent/src/store.rs:94-133` (a new DB restarts the AUTOINCREMENT seq at 1; the device identity is kept in `agent.toml`).
- **Scenario:** An admin attacker, or disk corruption, deletes `kestrel.db` and the service restarts. Every alert, event and heartbeat with seq ≤ old high-water mark (often millions) is acked and thrown away. Heartbeats are dropped too, so the seq-reset tamper check never runs. This is a quiet way to blind reporting.
- **Fix:** Send an outbox epoch (random id stored in the DB) in `Hello`. When the epoch changes, reset `last_agent_seq` and raise a TP alert. Also alert when the first durable seq is far below the high-water mark.

### M9. Privacy minimisation is incomplete: raw usernames, paths and command lines still reach the server
- **Where:**
  - `crates/kestrel-agent/src/agent.rs:400`: `AgentHealth.logged_on_user` is sent raw, and `incidents.user_name` falls back to it (`crates/kestrel-server/src/incidents.rs:688,743`).
  - `crates/kestrel-agent/src/tray.rs:110`: `ReviewRequest.user` is raw.
  - `crates/kestrel-agent/src/privacy.rs:96-107`: alert `process`/`ancestry` command lines are not truncated when `capture_cmdline=false`.
  - Alert summaries embed the command line (ST-11, `engine.rs:1480`) and full DLL paths (`:1920,1931`) unredacted.
- **Scenario:** A customer enables hashed usernames and path redaction for PDPA or UU PDP. Usernames still appear in device health, incidents and review requests. `C:\Users\alice\Documents\…` paths and full command lines still appear in alerts and summaries.
- **Fix:** Apply `PrivacyFilter.user()` to `logged_on_user` and to review users. Run redaction and truncation over the alert process, ancestry and summary, or build summaries from scrubbed fields.

### M10. IOC network hits create permanent host-wide blocks and kills, and IOC input accepts any CIDR
- **Where:** `crates/kestrel-server/src/api/policies.rs:559-563` (`0.0.0.0/0` is accepted); `crates/kestrel-detect/src/engine.rs:1705-1716` (domain or IP IOC: `BlockDestination{ttl_secs: None}` for every app, plus a kill tree of the connecting non-browser process); IOC URLs add their host as a domain IOC (`:355-364`).
- **Scenario:**
  - A domain IOC for a site behind a CDN permanently blocks shared CDN IPs for all applications.
  - A mistaken `/0` or `/8` IOC kills every non-browser process that connects out (Teams, Outlook, updaters) and adds a permanent WFP filter per destination, fleet-wide.
  - Removing the IOC does not remove the filters already added.
- **Fix:** Reject prefixes shorter than /24 (v4) or /48 (v6) without an admin override. Give IOC blocks a default TTL. Scope domain-derived blocks to the offending image. Remove filters when the IOC is deleted.

### M11. ST-16 (day-one Protect) auto-isolates the host when any non-allowlisted process opens a decoy
- **Where:** `crates/kestrel-detect/src/engine.rs:1574-1603` (kill tree + quarantine + `IsolateHost`); `crates/kestrel-detect/src/paths.rs:518-528` (only Windows Search and Defender are ignored); the decoys sit inside the real Chrome `User Data` folder and `%USERPROFILE%\.aws` (`canary.rs:95-127`).
- **Scenario:** Backup or migration agents (USMT `scanstate`, Datto, Veeam), third-party AV or EDR file scanners, profile-cleanup scripts and archivers enumerate or read the decoys. This leads to fleet-wide automatic isolation, which combined with H10 may not be releasable. Even `dir /s` or `robocopy` run by IT triggers it.
- **Unconfirmed (runtime):** which scanners open files from user mode.
- **Fix:** Default ST-16 isolation to Audit (alert + kill only). Add signed-publisher allow-lists for backup and AV (reuse `BENIGN_READERS` Security/Indexer). Isolate only for untrusted readers.

### M12. Signature checks never check revocation, so stealers signed with revoked stolen certificates count as Valid
- **Where:** `crates/kestrel-win/src/win/enrich.rs:284-288` (`WTD_REVOKE_NONE`, `WTD_REVOCATION_CHECK_NONE`); `crates/kestrel-common/src/event.rs:235` documents "revoked" as Invalid.
- **Scenario:** Stealers are commonly signed with leaked certificates that have been revoked. They are classified `Valid`, which removes the unsigned/untrusted signals (ST-01 actor, ST-12, `untrusted_actor`) and allows signer exclusions or allow-IOCs to apply.
- **Fix:** Run a background revocation check (cached CRL/OCSP, offline-tolerant) and demote revoked signers to `Invalid`. Ship a local deny-list of known-abused certificate thumbprints.

---

## LOW

- **L1. TOTP replay, and a password-correctness oracle for MFA accounts.**
  - TOTP: `auth_routes.rs:266-277` uses `check_current` with skew 1 and does not track the last-used time step, so a code can be replayed for about 90 s.
  - Oracle: `auth_routes.rs:256-265` returns `mfa_required` only when the password is correct, and does not count as a failure.
  - Fix: store the last accepted step per user, and return the generic error until both factors are checked.
- **L2. API tokens reach `/me/*` and never expire.** `auth_routes.rs:403-467` (`mfa_setup`/`mfa_enable` accept any Principal). A leaked read-only `kst_` token can enroll MFA on the owner's account with an attacker secret, locking out the admin. `api_tokens` has no expiry. Fix: reject `Via::Token` on `/me/*`, and add `expires_at`.
- **L3. Unauthenticated first-run setup.** `auth_routes.rs:102-121`: whoever reaches `:443` first after deploy becomes admin. Fix: require a one-time setup secret printed in the server log or env.
- **L4. OIDC start is an unauthenticated amplifier.** `oidc.rs:71-123`: each request performs IdP discovery and inserts into an unbounded in-memory `oidc_pending` map that is pruned only by TTL. Fix: cache discovery, cap the map, rate-limit per IP.
- **L5. Sessions and SSE are not cut off.** Sessions slide forever with no absolute lifetime (`auth.rs:231-242`). `/events/stream` (`sse.rs`) stays open after logout, disable or role change. Fix: add an absolute session max, and re-validate the session periodically on SSE.
- **L6. Audit chain can be rewritten or truncated undetectably.** `audit.rs:35-40,116-164` uses an unkeyed SHA-256 chain anchored at the oldest remaining row. Anyone with DB write access can recompute the chain, or delete head or tail rows. Failures are only logged (`audit.rs:85-95`). Fix: use an HMAC with the master key plus periodic external anchoring (syslog the head hash).
- **L7. Notification channels.**
  - SSRF: `settings_routes.rs:90-98` lets `settings.write` point webhook, syslog or the OIDC issuer at internal hosts, and reqwest follows redirects.
  - Slack mrkdwn injection: `notify.rs:82` puts endpoint-controlled `summary`/`hostname` into Slack mrkdwn unescaped, allowing `<https://evil|Open incident>` phishing in the SOC channel.
  - Exposure: the generic webhook URL is shown to `read` users (`settings.rs:235-244` masks only Slack and Teams).
  - Fix: block private ranges and redirects, escape `<>&` for Slack, mask the URL.
- **L8. Review requests are not bound to the device's own alerts.** `ingest.rs:526-554` stores any `alert_id`. `quarantine.rs:221-247` builds the exclusion from that alert, possibly another device's. Practical risk is low because alert UUIDs are unguessable. Fix: verify `alerts.device_id = session.device_id`.
- **L9. ST-11 nslookup false positive is destructive.** `engine.rs:1454-1463` kill-trees the **parent** shell. An admin's `nslookup host 8.8.8.8` in an interactive PowerShell or Terminal (grandparent explorer or wt) kills their whole shell tree in Protect. Related: dedup at `engine.rs:1038-1042` returns before actions, so when a first ST-04 kill failed (see H1), new exfil destinations within 10 min get no `BlockDestination`. Fix: kill only the `nslookup` child, and let action-bearing re-hits bypass dedup.
- **L10. Exclusions have no guardrails and also silence tamper rules.** `policies.rs:314-358` accepts `Path` `*` with no rule and global scope. `engine.rs:1033` applies exclusions to TP-* rules. One `exclusions.write` analyst action, or a compromised account, disables all detection fleet-wide. Fix: reject bare wildcards, never apply exclusions to TP rules, and require `policies.write` for global scope.
- **L11. Agent kill safety list differs from the engine's.** `filters.rs:35-51` lacks `explorer.exe`, `sihost.exe`, `spoolsv.exe`, `conhost.exe` and others that the engine protects (`engine.rs:150-156`). The console's `pickTarget` fallback (`console/src/components/incident-parts.tsx:17`) returns an alerted `explorer.exe`, for example the ST-10 subject when no child is found, so "Kill explorer.exe + tree" is offered and executed. The API also accepts GUID-less kills, so a PID can be reused by another process during the 7-day command TTL. Fix: use one shared protected list, never offer shell or system targets, and require `guid` for API kills.
- **L12. Canary planting as SYSTEM follows junctions.** `crates/kestrel-win/src/canary.rs:86-97` runs `create_dir_all` + write + rename + set-hidden in user-controlled profile paths with no reparse check. A user can make SYSTEM create decoy directories or files (fixed names and content) in arbitrary directories. Fix: open the parent with `FILE_FLAG_OPEN_REPARSE_POINT`, reject reparse points, or impersonate the profile owner.

Informational:
- Update manifests are signed over the sha256 only, not the version or URL (`update.rs:41-50`). The server never sends `ServerPayload::Update`, so the feature is unwired. Bind the version when you wire it.
- `policy.version` on the agent is monotonic. After a server DB restore with a lower sequence, agents ignore all policies.
- The console placeholder and `/downloads` are unauthenticated by design.
