# Deploy the server

Each organisation runs one Docker Compose stack: `kestrel-server` (console and REST API on port 443, agent gRPC with mutual TLS on port 8443), PostgreSQL 16 (control plane) and ClickHouse (telemetry). All data stays on your host.

<Shot src="img/diagrams/deployment.svg" alt="Deployment: endpoints, server, PostgreSQL, ClickHouse and admin browsers" />

## Install

```bash
git clone <your-kestrel-repo> kestrel && cd kestrel/deploy
cp .env.example .env
sed -i "s|^KESTREL_MASTER_KEY=.*|KESTREL_MASTER_KEY=$(openssl rand -base64 32)|" .env
$EDITOR .env        # KESTREL_PUBLIC_HOSTNAME, POSTGRES_PASSWORD, CLICKHOUSE_PASSWORD
docker compose up -d --build
```

Then open `https://<KESTREL_PUBLIC_HOSTNAME>/` and complete first-run setup: the one-time setup code (from `docker compose logs kestrel-server | grep "SETUP CODE"`, or the value of `KESTREL_SETUP_CODE`), the organisation name and the first administrator.

Check health:

```bash
docker compose ps                                       # every service "healthy"
curl -k https://localhost/api/auth/setup-status
curl -k https://localhost/api/healthz                   # unauthenticated health endpoint
```

### Small sites without ClickHouse

Set `CLICKHOUSE_URL=` (empty) in `.env`. Telemetry then goes to PostgreSQL with at most 7 days of retention. Start only the two services you need, and remove the `clickhouse` entry from `depends_on` of `kestrel-server` in `docker-compose.yml`:

```bash
docker compose up -d postgres kestrel-server
```

## Configuration (`.env`)

All variables below exist in `deploy/.env.example` or are read by the server.

| Variable | Default | Meaning |
|---|---|---|
| `KESTREL_MASTER_KEY` | (empty, required) | Wraps the agent CA key, the self-signed web key, TOTP secrets and notification secrets (AES-256-GCM). Generate once with `openssl rand -base64 32`. Back it up separately from the database. Losing it means a new CA, and every agent must re-enroll. |
| `KESTREL_PUBLIC_HOSTNAME` | `edr.example.internal` | DNS names (or IPs) that agents and browsers use, comma separated. They become the SANs of the agent gRPC certificate (regenerated at every start) and of the self-signed web certificate. **The first name is the primary one: installer scripts and install commands use it**, so it must be reachable from every endpoint. |
| `KESTREL_HTTPS_PORT` | `443` | Host port published for the console, REST API and downloads. |
| `KESTREL_GRPC_PORT` | `8443` | Host port published for agent gRPC. |
| `KESTREL_GRPC_PUBLIC_PORT` | `8443` | Port agents dial, if NAT or a load balancer changes it. Used in install commands. |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | `kestrel`, (required), `kestrel` | PostgreSQL credentials. `DATABASE_URL` overrides the composed connection string. |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | ClickHouse endpoint. Empty = PostgreSQL fallback for telemetry. |
| `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`, `CLICKHOUSE_DB` | `kestrel`, (required), `kestrel` | ClickHouse credentials. |
| `TLS_CERT`, `TLS_KEY` | unset | PEM paths of your own web certificate, mounted from `deploy/tls/` (for example `/app/tls/fullchain.pem`, `/app/tls/privkey.pem`). Unset = self-signed. |
| `KESTREL_AGENT_MSI_URL` | unset | External MSI URL. Default: `https://<host>/downloads/KestrelAgent.msi` from `deploy/installers/`. |
| `KESTREL_HEARTBEAT_INTERVAL_SECS` | `60` | Expected agent heartbeat. More than 3 missed intervals on a live stream raise `TP-SRV-HEARTBEAT`. |
| `KESTREL_TRUSTED_PROXIES` | (empty) | IPs or CIDRs of your reverse proxies. `X-Forwarded-For` is honoured only from these addresses (right-most untrusted hop), for login throttling and audit. Empty = the TCP peer address is used. |
| `KESTREL_SETUP_CODE` | unset | One-time code for the first-run setup screen. Unset = a random code is printed in the server log at startup until the first administrator exists. |
| `KESTREL_OUTBOUND_ALLOW_CIDRS` | unset | Private ranges that webhooks, Slack, Teams and the OIDC issuer may reach (for example an internal Keycloak). By default outbound HTTP reaches only public addresses, never follows redirects and never reaches link-local or cloud-metadata addresses. |
| `KESTREL_UPDATE_PUBKEY` | unset | Base64 Ed25519 public key for signed agent updates. Without it, registering a release in the console is refused. See [Agent updates](../console/updates). |
| `BUILD_CONSOLE` | `1` | `0` builds an API-only image without the console. |
| `KESTREL_IMAGE_TAG` | `local` | Tag of the built `kestrel-server` image. |
| `RUST_LOG` | `info,sqlx=warn` | Log filter. |
| `KESTREL_LOG_FORMAT` | `text` | `json` for structured logs for your log shipper. |

Retention, notifications (email, Slack, Teams, signed webhook, syslog), OIDC single sign-on and the MFA requirement are set in the console under **Settings** and stored in PostgreSQL.

To run the server outside Docker, also set `KESTREL_HTTPS_ADDR` and `KESTREL_GRPC_ADDR` (bind addresses; defaults `0.0.0.0:443` and `0.0.0.0:8443`), `CONSOLE_DIR` (the built console) and `AGENT_DIR` (the folder with `KestrelAgent.msi`). The master key must be at least 16 characters.

## Ports and firewall

| Port | Who connects | Purpose |
|---|---|---|
| 443/tcp | Admin browsers; endpoints (MSI download only) | Console, REST API `/api`, `/downloads` |
| 8443/tcp | Endpoints | Agent gRPC with mutual TLS; also signed update packages under `/downloads/updates/` |

Restrict 443 to the networks your administrators use. Endpoints need 8443 (and 443 only to download the MSI). Do not put a TLS-terminating proxy in front of 8443: mutual TLS must reach the server. Use TCP pass-through if you need a proxy.

## TLS

**Console (443).** Without `TLS_CERT` and `TLS_KEY`, the server creates a self-signed certificate on first run. It is stored encrypted and regenerated only when `KESTREL_PUBLIC_HOSTNAME` changes. For production, use a certificate from your internal PKI or an ACME client:

```bash
cp fullchain.pem privkey.pem deploy/tls/
# in .env:
#   TLS_CERT=/app/tls/fullchain.pem
#   TLS_KEY=/app/tls/privkey.pem
docker compose up -d
```

**Agents (8443).** On first run the server creates an internal **agent CA**. It signs the gRPC server certificate and one client certificate per device (CN = device id, valid for 1 year). The MSI pins this CA: it is passed base64-encoded as `CA_B64=` in the install command, and the agent trusts only that CA, never the Windows root store.

**Certificate renewal.** Agents renew their client certificate over their authenticated stream when fewer than 30 days remain. The old certificate is revoked once the agent connects with the new one. Expired or revoked certificates cannot renew; re-enroll the device with a token. Deleting (decommissioning) a device revokes its certificates and drops its connection immediately.

## Publish the agent MSI

Put `KestrelAgent.msi` (and optionally a `VERSION` file) in `deploy/installers/`. The folder is mounted read-only into the container at `/app/agent`.

* It is served at `https://<host>/downloads/KestrelAgent.msi`.
* Its SHA-256 appears in `GET /api/agent/installer` and on **Settings > Enrollment**.
* Installer scripts (`Install-Kestrel-<profile>.cmd`) are generated only when this file exists, because the script pins the MSI's SHA-256.

Signed update packages go into `deploy/installers/updates/`; see [Agent updates](../console/updates).

## Backup and restore

Back up three things: the PostgreSQL database, the ClickHouse volume (optional; telemetry only) and `.env` (it holds the master key).

```bash
# Backup (for example a daily cron job)
docker compose exec -T postgres pg_dump -U kestrel -Fc kestrel > kestrel-$(date +%F).dump
docker compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "BACKUP DATABASE kestrel TO File('/var/lib/clickhouse/backups/kestrel-$(date +%F)')"   # needs a <backups> config, or snapshot the chdata volume
cp .env /secure/offline/location/kestrel.env

# Restore
docker compose up -d postgres
docker compose exec -T postgres pg_restore -U kestrel -d kestrel --clean --if-exists < kestrel-YYYY-MM-DD.dump
docker compose up -d
```

The restored server must use the **same** `KESTREL_MASTER_KEY`. Otherwise it refuses to start (`cannot decrypt stored secrets`). After a restore, verify the hash-chained audit log in **Settings > Audit log > Verify** (`GET /api/audit-log/verify`).

## Upgrade

```bash
git pull
docker compose build kestrel-server
docker compose up -d kestrel-server
```

Database migrations run automatically at start. They are forward-only, so take a backup first. Connected agents reconnect within seconds and replay anything not yet acknowledged from their local outbox, so nothing is lost during the restart.

## Sizing

Planning estimates. Validate them with your own telemetry volume. They assume default telemetry (all event kinds) at roughly 1 to 5 KB/s per busy endpoint and 30-day event retention.

| Endpoints | Host | Disk | Notes |
|---|---|---|---|
| up to 100 | 2 vCPU, 4 GB RAM | 50 to 100 GB SSD | ClickHouse optional; the PostgreSQL fallback (7 days) is fine for a pilot. |
| 1,000 | 4 to 8 vCPU, 16 GB RAM | 0.5 to 1 TB SSD | One host. Give ClickHouse about 8 GB RAM. Consider limiting telemetry event kinds in the policy. |
| 5,000 | 16 vCPU, 64 GB RAM, or split hosts | 2 to 4 TB NVMe | Put ClickHouse on its own host or volume and PostgreSQL on fast SSD. |

Beyond about 5,000 endpoints, a message bus and multiple ingest replicas are needed; that is not implemented yet. ClickHouse stores events with ZSTD compression and a TTL equal to **Settings > Branding, privacy & retention > Data retention** for events.

## Logs and health

* Logs: `docker compose logs -f kestrel-server`. Set `KESTREL_LOG_FORMAT=json` for a log shipper.
* Health: `GET /api/healthz` (unauthenticated). Compose uses it as the container health check.
* Device status in the console: `isolated` (the agent reports isolation), `offline` (no contact for 3 minutes), `degraded` (ETW unhealthy or events lost in the last hour), otherwise `online`.
* Commands queued for offline devices are delivered on reconnect and expire after 7 days.
* Login is rate-limited per source address and per account, with exponential backoff and no hard lockout.
* Every 15 minutes the head of the audit chain is written to the server log (and to syslog when configured), as an external anchor.
