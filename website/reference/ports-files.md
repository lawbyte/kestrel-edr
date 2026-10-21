# Ports, files and API

## Ports

| Port | Direction | Purpose |
|---|---|---|
| 443/tcp | admin browsers and endpoints to server | Console, REST API `/api`, MSI download `/downloads/KestrelAgent.msi` |
| 8443/tcp | endpoints to server | Agent gRPC with mutual TLS; signed update packages `/downloads/updates/<file>` |
| 18443, 18444 | local | `scripts/e2e.sh` test server (HTTPS, gRPC) |

Host ports are set with `KESTREL_HTTPS_PORT` and `KESTREL_GRPC_PORT`; the port agents dial with `KESTREL_GRPC_PUBLIC_PORT`.

## Files on an endpoint

| Path | Contents |
|---|---|
| `C:\Program Files\Kestrel\kestrel-agent.exe` | Agent service binary |
| `C:\Program Files\Kestrel\kestrel-scan.exe` | YARA-X scanner |
| `C:\Program Files\Kestrel\kestrel-tray.exe` | Employee tray app |
| `C:\ProgramData\Kestrel\` | State folder, SYSTEM and Administrators only |
| `C:\ProgramData\Kestrel\agent.toml` | Agent configuration (server, pinned CA, uninstall token hash, remote-access ceiling) |
| `C:\ProgramData\Kestrel\agent.db` | SQLite outbox and local state |
| `C:\ProgramData\Kestrel\keys\` | Device private key and client certificate |
| `C:\ProgramData\Kestrel\logs\` | Agent logs |
| `C:\ProgramData\Kestrel\quarantine\` | Encrypted quarantine vault |
| `C:\ProgramData\Kestrel\triage\` | Triage packages before upload |
| `C:\ProgramData\Kestrel\updates\` | Downloaded update packages |
| `C:\ProgramData\Kestrel\uninstall-token.txt` | Only with old servers that issue no uninstall token |

Other names on an endpoint:

| Name | What |
|---|---|
| `KestrelAgent` | Windows service (LocalSystem, automatic start) |
| `Kestrel-Core`, `Kestrel-IO`, `Kestrel-ProcCmd` | ETW sessions (`logman query -ets`) |
| `\\.\pipe\kestrel-tray` | Named pipe between tray and agent |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, value `KestrelTray` | Starts the tray at sign-in |
| `HKLM\SOFTWARE\Kestrel\Installer` | Installer bookkeeping for upgrades |

## Files on the server

| Path (in `deploy/`) | Contents |
|---|---|
| `.env` | Configuration, including `KESTREL_MASTER_KEY`. Never commit it; back it up separately. |
| `installers/KestrelAgent.msi`, `installers/VERSION` | MSI served at `/downloads/KestrelAgent.msi` (mounted at `/app/agent`) |
| `installers/updates/` | Signed update packages served on port 8443 |
| `tls/` | Your web certificate and key (mounted at `/app/tls`) |
| Docker volumes `pgdata`, `chdata` | PostgreSQL and ClickHouse data |

## REST API

The console uses the same REST API that automation can use. Base path `/api`, JSON with `snake_case` keys, timestamps in milliseconds since the epoch.

* **Sessions:** `POST /api/auth/login` returns a `csrf_token` and sets a session cookie. Send `X-CSRF-Token` on every change.
* **API tokens:** `Authorization: Bearer kst_...`, created under **Settings > API tokens**. Tokens skip CSRF and carry only the privileges you give them.
* **Errors:** `{"error": {"code": "...", "message": "..."}}` with `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `rate_limited`, `internal`.
* **Lists:** `?limit=50&cursor=...`, returning `{items, next_cursor, total}`.

Useful endpoints:

| Method and path | Purpose |
|---|---|
| `GET /api/healthz` | Health (no authentication) |
| `GET /api/auth/setup-status` | Whether first-run setup is needed (no authentication) |
| `GET /api/agent/installer` | Agent CA PEM and MSI SHA-256 |
| `GET /api/devices`, `GET /api/devices/{id}` | Devices |
| `POST /api/devices/{id}/actions` | Response action, body `{"action": {...}}` |
| `GET /api/incidents`, `GET /api/incidents/{id}` | Incidents |
| `GET /api/alerts` | Alerts |
| `POST /api/hunt` | Hunt, body `{query, from, to, limit}` |
| `GET /api/audit-log/verify` | Verify the audit chain |

The full contract (every endpoint, payload and privilege) is in [`docs/contracts.md`](https://github.com/lawbyte/kestrel-edr/blob/main/docs/contracts.md) in the repository. `scripts/vm/api.sh` is a minimal shell client for it.
