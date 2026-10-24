# Kestrel EDR server — self-hosted deployment

One Docker Compose stack per organisation: `kestrel-server` (console + REST API on **443**, agent gRPC with mTLS on **8443**), PostgreSQL 16 (control plane) and ClickHouse (telemetry). All data stays on your host.

## Install in 5 commands

```bash
git clone https://github.com/lawbyte/kestrel-edr.git && cd kestrel-edr/deploy
cp .env.example .env
sed -i "s|^KESTREL_MASTER_KEY=.*|KESTREL_MASTER_KEY=$(openssl rand -base64 32)|" .env
$EDITOR .env        # KESTREL_PUBLIC_HOSTNAME, POSTGRES_PASSWORD, CLICKHOUSE_PASSWORD
docker compose up -d --build
```

Open `https://<KESTREL_PUBLIC_HOSTNAME>/`, complete first-run setup (the one-time setup code from `docker compose logs kestrel-server | grep "SETUP CODE"` or `KESTREL_SETUP_CODE`, organisation name + first admin), then **Devices**, **Install agent** to create an installer for your PCs. The illustrated walkthrough is the [step-by-step install guide](https://lawbyte.github.io/kestrel-edr/guide/quick-start).

Check health: `docker compose ps` (all `healthy`) and `curl -k https://localhost/api/auth/setup-status`.

* `BUILD_CONSOLE=0` in `.env` builds an API-only image (no Node stage output).
* Put `KestrelAgent.msi` (and an optional `VERSION` file) in `deploy/installers/`; it is served at `https://<host>/downloads/KestrelAgent.msi` and its SHA-256 appears in `GET /api/agent/installer`. Or set `KESTREL_AGENT_MSI_URL`.
* Small sites can skip ClickHouse: set `CLICKHOUSE_URL=` (empty) and telemetry goes to Postgres with ≤ 7 days retention (`docker compose up -d postgres kestrel-server`, and remove the `clickhouse` entry from `depends_on`).

## Ports & firewall

| Port | Who connects | Purpose |
|---|---|---|
| 443/tcp | Admin browsers, endpoints (MSI download only) | Console, REST API `/api`, `/downloads` |
| 8443/tcp | Endpoints | Agent gRPC, mutual TLS |

## Configuration (`.env`)

| Variable | Meaning |
|---|---|
| `KESTREL_MASTER_KEY` | **Required.** Wraps the agent CA key, the self-signed web key, TOTP secrets and notification secrets (AES-256-GCM). Back it up separately from the database. Losing it = new CA = every agent must re-enroll. |
| `KESTREL_PUBLIC_HOSTNAME` | DNS name(s) agents/browsers use, comma separated. Used as SANs of the gRPC certificate (regenerated at each start from the internal CA) and of the self-signed web certificate. |
| `POSTGRES_*`, `CLICKHOUSE_*` | Database credentials. `DATABASE_URL` overrides the `POSTGRES_*` composition. |
| `TLS_CERT`, `TLS_KEY` | Optional PEM paths for your own web certificate (mount into `deploy/tls/`). |
| `KESTREL_GRPC_PUBLIC_PORT` | Port agents dial if NAT changes it (used in install commands). |
| `KESTREL_HTTPS_PUBLIC_PORT` | Port browsers and installers use for the console and `/downloads` if NAT or a proxy changes it. Defaults to `KESTREL_HTTPS_PORT`. |
| `KESTREL_HEARTBEAT_INTERVAL_SECS` | Expected agent heartbeat; > 3 missed intervals on a live stream raise `TP-SRV-HEARTBEAT`. |
| `KESTREL_TRUSTED_PROXIES` | Comma-separated IPs/CIDRs of your reverse proxies. `X-Forwarded-For` is honoured only on connections from these addresses (right-most untrusted hop) for login throttling and audit. Empty = the TCP peer is used. (Replaces `KESTREL_TRUST_PROXY_HEADERS`.) |
| `KESTREL_SETUP_CODE` | Optional one-time code for the first-run setup screen. Unset: a random code is printed in the server log at startup (`docker compose logs kestrel-server \| grep "SETUP CODE"`) until the first administrator exists. |
| `KESTREL_OUTBOUND_ALLOW_CIDRS` | Private ranges that webhooks, Slack/Teams and the OIDC issuer may reach (e.g. an internal Keycloak). By default outbound HTTP only reaches public addresses, never follows redirects, and never reaches link-local / cloud-metadata addresses. |
| `KESTREL_LOG_FORMAT=json` | Structured logs for your log shipper. |

Retention, notifications (Slack, Teams, signed webhook, SMTP, syslog CEF/JSON), OIDC SSO and MFA policy are set in the console under **Settings** and stored in Postgres.

## TLS

* **Console (443):** without `TLS_CERT`/`TLS_KEY` the server generates a self-signed certificate on first run (stored encrypted, regenerated only when `KESTREL_PUBLIC_HOSTNAME` changes). For production use a certificate from your internal PKI or ACME: copy `fullchain.pem` and `privkey.pem` into `deploy/tls/`, set `TLS_CERT=/app/tls/fullchain.pem`, `TLS_KEY=/app/tls/privkey.pem`, and `docker compose up -d`.
* **Agents (8443):** an internal **agent CA** is created on first run. It signs the gRPC server certificate and one client certificate per device (CN = device id, 1-year validity). The MSI pins this CA (`ca_pem` from `GET /api/agent/installer`, passed base64-encoded as `CA_B64=` in the install command). Do not put a TLS-terminating proxy in front of 8443 (mTLS must reach the server); use TCP pass-through if needed.
* **Certificate renewal:** agents send `RenewCertificate` (a fresh CSR) on their authenticated stream when < 30 days remain, or when the server asks on connect; the server signs it for the stream's device id and replies with the new certificate. The old certificate is revoked only once the agent connects with the new one. `cert_expires_at` is shown per device. Expired or revoked certificates cannot renew — re-enroll with a token.
* **Re-enrollment:** every enrollment creates a new device, even on the same hardware. A matching hardware UUID flags both devices as possible duplicates (and raises `TP-SRV-DUP-ENROLL` if the old one was alive in the last 24 h); merge or dismiss them on the device page.
* **Revocation:** deleting (decommissioning) a device revokes its certificates and drops its live stream immediately.

## Backup & restore

Back up **three things**: the Postgres database, the ClickHouse volume (optional — telemetry), and `.env` (master key!).

The `evidence` volume (`KESTREL_EVIDENCE_DIR`, default `/var/lib/kestrel/evidence`) holds evidence bundles an administrator collected after a suspected data theft. They are encrypted with a key derived from `KESTREL_MASTER_KEY` (unreadable without it), deleted automatically after *Settings → retention → evidence* days (default 14), and capped at `KESTREL_EVIDENCE_MAX_GB` (default 20 GB). They are investigation copies of employees' data: back the volume up only if your evidence-handling policy requires it, and keep such backups as restricted as the master key.

```bash
# Backup (daily cron)
docker compose exec -T postgres pg_dump -U kestrel -Fc kestrel > kestrel-$(date +%F).dump
docker compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "BACKUP DATABASE kestrel TO File('/var/lib/clickhouse/backups/kestrel-$(date +%F)')"   # needs <backups> config, or snapshot the chdata volume
cp .env /secure/offline/location/kestrel.env

# Restore
docker compose up -d postgres
docker compose exec -T postgres pg_restore -U kestrel -d kestrel --clean --if-exists < kestrel-YYYY-MM-DD.dump
docker compose up -d
```

The restored server must use the **same `KESTREL_MASTER_KEY`**; otherwise it refuses to start (`cannot decrypt stored secrets`). The audit log is hash-chained: after a restore run **Settings → Audit log → Verify** (`GET /api/audit-log/verify`).

## Upgrade

```bash
git pull
docker compose build kestrel-server
docker compose up -d kestrel-server
```

Database migrations run automatically on start (forward-only; take a backup first). Connected agents reconnect within seconds and replay anything not yet acknowledged from their local outbox — nothing is lost during the restart.

## Sizing (planning estimates, validate with your own telemetry volume)

Assumes default telemetry (all event kinds) at roughly 1–5 KB/s per busy endpoint and 30-day event retention. Alerts and control-plane data are small.

| Endpoints | Host | Disk | Notes |
|---|---|---|---|
| ≤ 100 | 2 vCPU, 4 GB RAM | 50–100 GB SSD | ClickHouse optional; the Postgres fallback (7 days) is fine for a pilot. |
| 1,000 | 4–8 vCPU, 16 GB RAM | 0.5–1 TB SSD | One host. Give ClickHouse ~8 GB RAM. Consider `Policy.telemetry.event_kinds` to drop noisy kinds. |
| 5,000 | 16 vCPU, 64 GB RAM (or split: server + Postgres 8c/16 GB, ClickHouse 8–16c/32–64 GB) | 2–4 TB NVMe | Put ClickHouse on its own host/volume; Postgres on fast SSD. Beyond ~5k endpoints add a message bus (NATS) and multiple ingest replicas. |

ClickHouse stores events with ZSTD compression and a `TTL` equal to **Settings → Retention → events** (changed live with `ALTER TABLE … MODIFY TTL`).

## Operations notes

* Logs: `docker compose logs -f kestrel-server`.
* Health endpoint: `GET /api/healthz` (unauthenticated).
* Device status: `isolated` (agent reports isolation) → `offline` (no contact for 3 min) → `degraded` (ETW unhealthy or events lost in the last hour) → `online`.
* Commands queued for offline devices are delivered on reconnect and expire after 7 days.
* Login is rate-limited per source IP (20 / 5 min) and per account (8 failures / 15 min).

## Development / tests

```bash
# Throwaway Postgres (any server where the user may CREATE DATABASE):
export DATABASE_URL=postgres://kestrel:kestrel@127.0.0.1:5432/postgres
# Optional ClickHouse path:
export KESTREL_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123
CARGO_INCREMENTAL=0 cargo test -p kestrel-server
```

End-to-end with the real agent in simulator mode:

```bash
cargo run -p kestrel-agent -- simulate --server <host>:8443 --server-name <KESTREL_PUBLIC_HOSTNAME> \
  --ca ca.pem --token <enrollment token> --replay crates/kestrel-agent/replays/lumma_clickfix.jsonl \
  --state-dir ./simstate --exit-after-replay 10
```
