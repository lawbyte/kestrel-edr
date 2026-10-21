# Security model and limits

This page summarises how Kestrel protects itself and its data, and what it cannot do. The full design is in `docs/ARCHITECTURE.md` in the repository.

## Agent and server

* **Pinned CA and mutual TLS.** The server creates an internal agent CA on first start; its key is wrapped with `KESTREL_MASTER_KEY` (AES-256-GCM). Agents trust only the CA they were installed with, never the Windows root store. Each device has its own client certificate (one year, renewed automatically 30 days before expiry). Port 8443 must not sit behind a TLS-terminating proxy.
* **Enrollment tokens** (`kte_...`) are stored only as SHA-256 hashes, with group, expiry (default 7 days, 1 to 90), maximum uses (default 50, up to 10,000) and a revoked flag. The agent generates its key pair locally; the private key never leaves the device.
* **Secrets in command lines are redacted** server-side before telemetry, alerts or action results are stored (`TOKEN=...`, `--token ...`, `kte_`, `kun_`, `kst_` values).
* **Identity is never re-bound.** Every enrollment creates a new device; a reused hardware UUID only flags duplicates (`TP-SRV-DUP-ENROLL`) for an administrator to merge or dismiss.
* **Server-side tamper checks:** missed heartbeats (`TP-SRV-HEARTBEAT`), outbox sequence going backwards (`TP-SRV-SEQ-RESET`), a new outbox (`TP-SRV-OUTBOX-RESET`), more than 500 ETW events lost between heartbeats (`TP-SRV-EVENTS-LOST`), ETW session down (`TP-SRV-ETW`).

## Endpoint self-protection (user mode)

* **Service DACL.** `KestrelAgent` runs as LocalSystem. Administrators may only query and start it; stop, reconfigure and delete are reserved to SYSTEM, so `sc stop KestrelAgent` fails even for an administrator.
* **State folder.** `C:\ProgramData\Kestrel` must be owned by SYSTEM or Administrators with no write access for anyone else and no reparse point. This is checked at install, enrollment and every service start; an untrusted folder is moved aside and re-created.
* **Uninstall token.** Issued by the server per device, stored on the device only as an Argon2id hash, needed for uninstall and the isolation break-glass. MSI properties that carry tokens are hidden from MSI logs.
* **Tamper rules** on the device: ETW session stopped (`TP-01`, the watchdog restarts it), foreign WFP filter changes (`TP-02`, the agent removes them; needs the "Filtering Platform Policy Change" audit policy), AMSI tampering (`TP-03`), changes to the agent's service key or files (`TP-04`), telemetry loss (`TP-05`), protection turned off with the tray switch or a wrong uninstall token entered there (`TP-06`).
* **Response safety:** protected processes, PID-reuse checks, no link following in quarantine and restore. See [Response actions](../console/response#safety-rules-the-agent-always-applies).
* **Signed updates** with your offline Ed25519 key; the server never holds it. See [Agent updates](../console/updates).
* **Tray pipe:** the tray only trusts an agent running in session 0, and the agent attributes every pipe request to the caller's Windows account.

## Console and REST API

* Session cookie (`HttpOnly`, `Secure`, `SameSite=Strict`) plus an `X-CSRF-Token` header on every change. API tokens (`Bearer kst_...`) have their own privileges, skip CSRF and expire.
* First-run setup needs a one-time code from the server log or `KESTREL_SETUP_CODE`.
* Login throttling uses exponential backoff on failures only, per account and per address, with no hard lockout. `X-Forwarded-For` is trusted only from `KESTREL_TRUSTED_PROXIES`.
* TOTP codes are single use. For MFA accounts a sign-in without a code is answered with `mfa_required` whether or not the password was right.
* Sessions have an idle timeout and a maximum lifetime; the live-update stream re-checks the session every 60 seconds.
* OIDC binds accounts by issuer and subject only, requires a verified email in an allowed domain, and never gives new SSO users an administrator role.
* Outbound requests reach only public addresses unless allowed with `KESTREL_OUTBOUND_ALLOW_CIDRS`, and never follow redirects.
* Strict Content Security Policy, `frame-ancestors 'none'`, HSTS and `nosniff`.
* The audit log is an HMAC chain keyed from the master key, anchored to the server log and syslog every 15 minutes, with a verify endpoint.
* Secrets at rest (CA key, web TLS key, TOTP secrets, notification secrets) are encrypted with a key derived from the master key.

## Limits

* **No kernel driver.** Kestrel detects fast and contains fast; it cannot guarantee prevention. A fast stealer can send some data before the agent reacts.
* **An administrator or SYSTEM attacker can defeat the agent**: blind ETW, stop sessions, remove WFP filters, or use a vulnerable signed driver to kill it. The TP rules make this loud; they cannot make it impossible. An administrator can also build an MSI with Kestrel's upgrade code to skip the uninstall-token check.
* **Registry writer attribution** is a join between ETW and a registry watcher. It is exact only when one process could have written the value; a value set and reverted within the watcher's debounce window (50 to 750 ms) is not seen.
* **SMB encryption from another host** appears as the System process; Kestrel alerts but cannot kill the remote encryptor.
* **Automatic image blocks** (ST-02, ST-07, ST-16) stay until an analyst lifts them.
* **Enrollment and uninstall tokens** typed on an `msiexec` command line are visible to local process monitors; the custom action itself passes them on stdin.
* **Decoy names** are the same across the fleet.
* **Remote access:** an administrator with Full file access and upload can run code as SYSTEM, so guardrails other than the install ceiling are soft against a malicious administrator. A compromised administrator account or server can use remote access on every device whose install profile allows it. The desktop WebSocket carries the CSRF token in the query string (it may appear in reverse-proxy access logs). Allowed hours use the device's local time, which a standard user can change. The install ceiling does not cover the older response actions (kill, quarantine, isolate, triage); RBAC governs those.
* **Not code-signed yet.** Defender flags the unsigned agent; sign before production.
* Server-side detection covers agent health and identity only; there is no cross-device correlation yet. Alert grouping and the hunt language are deliberately simple.
* Only Windows endpoints have a real sensor layer.

## Reviews

Two independent security reviews were carried out (v1.0 and v1.1), plus a hostile review of the remote-access feature. Findings were fixed with regression tests and re-reviewed. The reports are in `docs/security-review-2026-10-21.md` and `docs/security-review-v1.1-2026-10-21.md` in the repository.
