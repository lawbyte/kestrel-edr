#!/usr/bin/env bash
# Kestrel EDR end-to-end test: real server + real agent core (simulator mode).
#
#   ./scripts/e2e.sh
#
# Builds kestrel-server and kestrel-agent, starts the server against a fresh
# PostgreSQL database, enrolls three simulated endpoints that replay recorded
# telemetry (Lumma ClickFix, Vidar smash-and-grab, a benign workday) and checks
# the results through the REST API: devices, incidents, priorities, data at
# risk, storyline/process tree/checklist, an offline-queued response action,
# the audit hash chain and a hunt query.
#
# Environment:
#   DATABASE_URL       Postgres server to use (a throwaway database is created on
#                      it and dropped afterwards). Unset: a temporary cluster is
#                      started with the local PostgreSQL binaries.
#   PG_BIN             PostgreSQL bin dir for the temporary cluster
#                      (default: first of /usr/lib/postgresql/*/bin, then $PATH).
#   E2E_SKIP_CONSOLE=1 Do not build the console (console/dist is used if present).
#   E2E_SKIP_BUILD=1   Use already-built binaries.
#   E2E_KEEP=1         Leave the server (and database) running after the checks
#                      and print login details; Ctrl-C to stop and clean up.
#   E2E_HTTPS_PORT / E2E_GRPC_PORT   Ports (default 18443 / 18444).
#   CARGO_TARGET_DIR   Honoured (binaries are taken from $CARGO_TARGET_DIR/debug).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

HTTPS_PORT="${E2E_HTTPS_PORT:-18443}"
GRPC_PORT="${E2E_GRPC_PORT:-18444}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN="$TARGET_DIR/debug"
API="https://127.0.0.1:$HTTPS_PORT/api"
ADMIN_EMAIL="admin@kestrel.test"
ADMIN_PASSWORD="E2e-Correct-Horse-Battery-9"
SETUP_CODE="E2E-$(openssl rand -hex 6)"
REPLAYS="$ROOT/crates/kestrel-agent/replays"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kestrel-e2e.XXXXXX")"
chmod 755 "$WORK"
COOKIES="$WORK/cookies.txt"
SERVER_LOG="$WORK/server.log"
SERVER_PID=""
PG_DIR=""
PG_RUNAS=()
DB_NAME=""
ADMIN_DB_URL=""
PASSED=()
FAILED=()

log() { printf '\033[1;34m[e2e]\033[0m %s\n' "$*" >&2; }
pass() { PASSED+=("$1"); printf '  \033[32mPASS\033[0m %s\n' "$1" >&2; }
fail() { FAILED+=("$1"); printf '  \033[31mFAIL\033[0m %s\n' "$1" >&2; }
check() { # check "description" <command...>
  local d="$1"; shift
  if "$@"; then pass "$d"; else fail "$d"; fi
}
die() {
  printf '\033[31m[e2e] fatal: %s\033[0m\n' "$*" >&2
  if [[ -f "$SERVER_LOG" ]]; then
    echo "----- last 60 lines of server log -----" >&2
    tail -n 60 "$SERVER_LOG" >&2 || true
  fi
  exit 1
}

cleanup() {
  local rc=$?
  set +e
  # Simulated agents started in the background.
  for p in $(jobs -p); do [[ "$p" == "$SERVER_PID" ]] || kill -TERM "$p" 2>/dev/null; done
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.2; done
    kill -9 "$SERVER_PID" 2>/dev/null
  fi
  if [[ -n "$DB_NAME" && -n "$ADMIN_DB_URL" ]]; then
    psql "$ADMIN_DB_URL" -qAt -c "DROP DATABASE IF EXISTS \"$DB_NAME\" WITH (FORCE)" >/dev/null 2>&1
  fi
  if [[ -n "$PG_DIR" ]]; then
    "${PG_RUNAS[@]}" "$PG_BIN/pg_ctl" -D "$PG_DIR/data" -m immediate stop >/dev/null 2>&1
  fi
  if [[ $rc -ne 0 && -f "$SERVER_LOG" && "${E2E_KEEP_LOGS:-0}" == "1" ]]; then
    log "logs kept in $WORK"
  else
    rm -rf "$WORK"
  fi
  exit $rc
}
trap cleanup EXIT
trap 'exit 130' INT TERM

stop_pid() { # graceful stop: SIGINT, then SIGTERM after 5s
  kill -INT "$1" 2>/dev/null || return 0
  for _ in $(seq 1 25); do kill -0 "$1" 2>/dev/null || break; sleep 0.2; done
  kill -TERM "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
need curl
need jq
need openssl
need psql

# ---------------------------------------------------------------------------
# 1. Build
# ---------------------------------------------------------------------------
if [[ "${E2E_SKIP_BUILD:-0}" != "1" ]]; then
  log "building kestrel-server and kestrel-agent"
  cargo build -q -p kestrel-server -p kestrel-agent
fi
[[ -x "$BIN/kestrel-server" && -x "$BIN/kestrel-agent" ]] || die "binaries not found in $BIN"

CONSOLE_DIR="$ROOT/console/dist"
if [[ "${E2E_SKIP_CONSOLE:-0}" != "1" && ! -f "$CONSOLE_DIR/index.html" ]]; then
  log "building the console"
  (cd console && npm ci --no-audit --no-fund && npm run build)
fi
[[ -f "$CONSOLE_DIR/index.html" ]] || log "console bundle not present; server will serve the API-only placeholder"

# ---------------------------------------------------------------------------
# 2. Database
# ---------------------------------------------------------------------------
if [[ -n "${DATABASE_URL:-}" ]]; then
  ADMIN_DB_URL="$DATABASE_URL"
else
  if [[ -z "${PG_BIN:-}" ]]; then
    PG_BIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -n1 || true)"
    [[ -n "$PG_BIN" ]] || PG_BIN="$(dirname "$(command -v initdb || echo /nonexistent/initdb)")"
  fi
  [[ -x "$PG_BIN/initdb" ]] || die "DATABASE_URL unset and no PostgreSQL binaries found (set PG_BIN)"
  PG_DIR="$WORK/pg"
  mkdir -p "$PG_DIR"
  if [[ "$(id -u)" == "0" ]]; then
    # initdb refuses to run as root.
    id postgres >/dev/null 2>&1 || die "running as root but no 'postgres' user exists"
    chown postgres "$PG_DIR"
    PG_RUNAS=(runuser -u postgres --)
  fi
  PG_PORT="${E2E_PG_PORT:-$((20000 + RANDOM % 20000))}"
  log "starting a temporary PostgreSQL cluster on port $PG_PORT ($PG_BIN)"
  "${PG_RUNAS[@]}" "$PG_BIN/initdb" -D "$PG_DIR/data" -U kestrel --auth=trust -E UTF8 >/dev/null
  "${PG_RUNAS[@]}" "$PG_BIN/pg_ctl" -D "$PG_DIR/data" -l "$PG_DIR/pg.log" -w \
    -o "-c listen_addresses=127.0.0.1 -c port=$PG_PORT -c unix_socket_directories='$PG_DIR' -c fsync=off" start >/dev/null \
    || { cat "$PG_DIR/pg.log" >&2; die "postgres did not start"; }
  ADMIN_DB_URL="postgres://kestrel@127.0.0.1:$PG_PORT/postgres"
fi
DB_NAME="kestrel_e2e_$(date +%s)_$RANDOM"
psql "$ADMIN_DB_URL" -qAt -c "CREATE DATABASE \"$DB_NAME\"" >/dev/null || die "cannot create database $DB_NAME"
DB_URL="$(echo "$ADMIN_DB_URL" | sed -E "s#/[^/?]*(\?|$)#/$DB_NAME\1#")"
# The sed above replaces the last path segment; make sure it really did.
[[ "$DB_URL" == *"/$DB_NAME"* ]] || die "could not derive a database URL from $ADMIN_DB_URL"

# ---------------------------------------------------------------------------
# 3. Server
# ---------------------------------------------------------------------------
log "starting kestrel-server (https :$HTTPS_PORT, grpc :$GRPC_PORT)"
mkdir -p "$WORK/agent-dl"
DATABASE_URL="$DB_URL" \
CLICKHOUSE_URL="" \
KESTREL_MASTER_KEY="$(openssl rand -base64 32)" \
KESTREL_PUBLIC_HOSTNAME="localhost" \
KESTREL_HTTPS_ADDR="127.0.0.1:$HTTPS_PORT" \
KESTREL_GRPC_ADDR="127.0.0.1:$GRPC_PORT" \
KESTREL_GRPC_PUBLIC_PORT="$GRPC_PORT" \
KESTREL_HEARTBEAT_INTERVAL_SECS=5 \
KESTREL_SETUP_CODE="$SETUP_CODE" \
CONSOLE_DIR="$CONSOLE_DIR" \
AGENT_DIR="$WORK/agent-dl" \
RUST_LOG="${RUST_LOG:-info,sqlx=warn,tower_http=warn,h2=warn}" \
  "$BIN/kestrel-server" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for i in $(seq 1 150); do
  if curl -ksf "$API/healthz" >/dev/null 2>&1; then break; fi
  kill -0 "$SERVER_PID" 2>/dev/null || die "server exited during startup"
  sleep 0.2
  [[ $i -eq 150 ]] && die "server did not become healthy in 30s"
done
log "server healthy"

# --- REST helpers ----------------------------------------------------------
CSRF=""
api() { # api METHOD PATH [JSON]  -> body on stdout; fails on non-2xx
  local m="$1" p="$2" body="${3:-}" out code
  local args=(-ks -o "$WORK/resp" -w '%{http_code}' -b "$COOKIES" -c "$COOKIES" -X "$m" -H 'Accept: application/json')
  [[ -n "$CSRF" ]] && args+=(-H "X-CSRF-Token: $CSRF")
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data "$body")
  code="$(curl "${args[@]}" "$API$p")" || { echo "curl failed: $m $p" >&2; return 1; }
  out="$(cat "$WORK/resp")"
  if [[ "$code" != 2* ]]; then
    echo "HTTP $code for $m $p: $out" >&2
    return 1
  fi
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# 4. First-run setup, enrollment token, CA
# ---------------------------------------------------------------------------
if api POST /auth/setup "$(jq -nc --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" \
  '{setup_code: "WRONG", org_name: "x", email: $e, password: $p, name: "x"}')" >/dev/null 2>&1; then
  fail "first-run setup accepted a wrong setup code"
else
  pass "first-run setup refuses a wrong setup code"
fi
setup="$(api POST /auth/setup "$(jq -nc --arg c "$SETUP_CODE" --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" \
  '{setup_code: $c, org_name: "Kestrel E2E", email: $e, password: $p, name: "E2E Admin"}')")" || die "setup failed"
CSRF="$(jq -r .csrf_token <<<"$setup")"
[[ -n "$CSRF" && "$CSRF" != null ]] || die "no csrf_token in setup response"
pass "first-run setup created admin $ADMIN_EMAIL"

tok="$(api POST /enrollment-tokens '{"expires_in_days": 1, "max_uses": 10}')" || die "enrollment token"
TOKEN="$(jq -r .token <<<"$tok")"
[[ -n "$TOKEN" && "$TOKEN" != null ]] || die "no token returned"
jq -e '.install_command | test("msiexec")' <<<"$tok" >/dev/null && pass "enrollment token + install command issued" || fail "install_command missing"

inst="$(api GET /agent/installer)" || die "installer metadata"
jq -r .ca_pem <<<"$inst" >"$WORK/ca.pem"
grep -q "BEGIN CERTIFICATE" "$WORK/ca.pem" || die "no ca_pem in /agent/installer"
pass "agent CA fetched from /api/agent/installer"

# ---------------------------------------------------------------------------
# 5. Simulated endpoints
# ---------------------------------------------------------------------------
sim() { # sim NAME HOSTNAME REPLAY SPEED EXTRA...   (always run in the background: it execs)
  local name="$1" host="$2" replay="$3" speed="$4"; shift 4
  exec "$BIN/kestrel-agent" --state-dir "$WORK/agent-$name" simulate \
    --server "127.0.0.1:$GRPC_PORT" --server-name localhost --ca "$WORK/ca.pem" --token "$TOKEN" \
    --hostname "$host" --replay "$replay" --speed "$speed" --heartbeat-secs 2 "$@" \
    >"$WORK/agent-$name.log" 2>&1
}

LUMMA_HOST="E2E-LUMMA-01"
VIDAR_HOST="E2E-VIDAR-02"
BENIGN_HOST="E2E-BENIGN-03"
log "replaying lumma_clickfix, vidar_smash_grab, benign_workday (parallel)"
sim lumma "$LUMMA_HOST" "$REPLAYS/lumma_clickfix.jsonl" 1 --exit-after-replay 15 & P1=$!
sim vidar "$VIDAR_HOST" "$REPLAYS/vidar_smash_grab.jsonl" 10 --exit-after-replay 15 & P2=$!
sim benign "$BENIGN_HOST" "$REPLAYS/benign_workday.jsonl" 30 --exit-after-replay 15 & P3=$!
for p in "$P1:lumma" "$P2:vidar" "$P3:benign"; do
  pid="${p%%:*}"; n="${p##*:}"
  if wait "$pid"; then pass "agent simulate ($n) exited cleanly"
  else fail "agent simulate ($n) exited with an error"; tail -n 30 "$WORK/agent-$n.log" >&2; fi
done

# Ingest is asynchronous from the agents' point of view; give grouping a moment.
sleep 2

# ---------------------------------------------------------------------------
# 6. Assertions
# ---------------------------------------------------------------------------
devices="$(api GET '/devices?limit=100')" || die "list devices"
check "3 devices enrolled" test "$(jq '.items | length' <<<"$devices")" -eq 3
dev_id() { jq -r --arg h "$1" '.items[] | select(.hostname == $h) | .id' <<<"$devices"; }
LUMMA_ID="$(dev_id "$LUMMA_HOST")"; VIDAR_ID="$(dev_id "$VIDAR_HOST")"; BENIGN_ID="$(dev_id "$BENIGN_HOST")"
check "each simulated hostname is a device" test -n "$LUMMA_ID" -a -n "$VIDAR_ID" -a -n "$BENIGN_ID"

incidents="$(api GET '/incidents?limit=100&status=open,in_progress,resolved,dismissed')" || die "list incidents"
n_inc="$(jq '.items | length' <<<"$incidents")"
check "≥2 incidents (got $n_inc)" test "$n_inc" -ge 2
inc_for() { jq -c --arg d "$1" '[.items[] | select(.device_id == $d)] | sort_by(-.priority) | .[0] // empty' <<<"$incidents"; }
LUMMA_INC="$(inc_for "$LUMMA_ID")"; VIDAR_INC="$(inc_for "$VIDAR_ID")"
check "incident for $LUMMA_HOST" test -n "$LUMMA_INC"
check "incident for $VIDAR_HOST" test -n "$VIDAR_INC"
check "lumma kill chain grouped into one incident ($(jq --arg d "$LUMMA_ID" '[.items[] | select(.device_id == $d)] | length' <<<"$incidents"))" \
  test "$(jq --arg d "$LUMMA_ID" '[.items[] | select(.device_id == $d)] | length' <<<"$incidents")" -eq 1
check "no incidents for $BENIGN_HOST" test "$(jq --arg d "$BENIGN_ID" '[.items[] | select(.device_id == $d)] | length' <<<"$incidents")" -eq 0
if [[ -n "$LUMMA_INC" ]]; then
  check "lumma priority ≥ 80 ($(jq .priority <<<"$LUMMA_INC"))" jq -e '.priority >= 80' <<<"$LUMMA_INC" >/dev/null
  check "lumma data_at_risk ⊇ {browser_passwords, crypto_wallet} ($(jq -c .data_at_risk <<<"$LUMMA_INC"))" \
    jq -e '(.data_at_risk | index("browser_passwords")) != null and (.data_at_risk | index("crypto_wallet")) != null' <<<"$LUMMA_INC" >/dev/null
  check "lumma rule_ids include ST-04 steal-then-send ($(jq -c .rule_ids <<<"$LUMMA_INC"))" \
    jq -e '.rule_ids | index("ST-04") != null' <<<"$LUMMA_INC" >/dev/null
fi
if [[ -n "$VIDAR_INC" ]]; then
  check "vidar priority ≥ 80 ($(jq .priority <<<"$VIDAR_INC"))" jq -e '.priority >= 80' <<<"$VIDAR_INC" >/dev/null
fi

if [[ -n "$LUMMA_INC" ]]; then
  LUMMA_INC_ID="$(jq -r .id <<<"$LUMMA_INC")"
  detail="$(api GET "/incidents/$LUMMA_INC_ID")" || die "incident detail"
  check "incident detail: storyline present" jq -e '(.storyline | type) == "string" and (.storyline | length) > 20' <<<"$detail" >/dev/null
  check "incident detail: process_tree non-empty ($(jq '.process_tree | length' <<<"$detail") nodes)" jq -e '(.process_tree | length) > 0' <<<"$detail" >/dev/null
  check "incident detail: checklist non-empty ($(jq '.checklist | length' <<<"$detail") items)" jq -e '(.checklist | length) > 0' <<<"$detail" >/dev/null
  check "incident detail: alerts listed" jq -e '(.alerts | length) > 0' <<<"$detail" >/dev/null
  check "storyline opens with the non-system subject, not explorer.exe ($(jq -r '.storyline | split("\n")[0][0:60]' <<<"$detail"))" \
    jq -e '(.storyline | startswith("`explorer.exe`")) | not' <<<"$detail" >/dev/null
  check "origin step names the payload, not explorer.exe" \
    jq -e '[.checklist[] | select(.text | test("came from"))] | length > 0 and all(.text | test("explorer\\.exe came from") | not)' <<<"$detail" >/dev/null
  check "release isolation offered only when the host was isolated" \
    jq -e '([.actions[] | select(.action.type == "isolate_host" and .status == "succeeded")] | length > 0) == ([.checklist[] | select(.text | startswith("Release isolation"))] | length > 0)' <<<"$detail" >/dev/null
fi

# --- Per-device secrets and certificates (M5, H3) --------------------------
utok="$(api POST "/devices/$LUMMA_ID/uninstall-token/reveal" '{}')" || utok='{}'
check "uninstall token escrowed at enrollment and revealable" jq -e '.token | startswith("kun_")' <<<"$utok" >/dev/null
check "device API exposes certificate expiry" jq -e --arg d "$LUMMA_ID" '.items[] | select(.id == $d) | .cert_expires_at > 0' <<<"$devices" >/dev/null
OLD_UTOK="$(jq -r '.token // empty' <<<"$utok")"
OLD_UHASH="$(grep -m1 '^uninstall_token_hash' "$WORK/agent-lumma/agent.toml" 2>/dev/null || true)"
# Rotation while the device is offline: kept pending, delivered on reconnect below.
rot="$(api POST "/devices/$LUMMA_ID/uninstall-token/rotate" '{}')" || rot='{}'
NEW_UTOK="$(jq -r '.pending_token // empty' <<<"$rot")"
check "uninstall token rotation queued for the offline device" \
  jq -e '.sent == false and (.pending_token | startswith("kun_"))' <<<"$rot" >/dev/null

# --- Response action queued while the device is offline -------------------
action="$(api POST "/devices/$LUMMA_ID/actions" \
  "$(jq -nc --arg i "${LUMMA_INC_ID:-}" '{action: {type: "block_destination", ip: "203.0.113.45", port: 443, ttl_secs: 3600}, comment: "e2e: block C2", incident_id: (if $i == "" then null else $i end)}')")" \
  || die "create response action"
ACTION_ID="$(jq -r .id <<<"$action")"
check "response action queued for offline device (status $(jq -r .status <<<"$action"))" \
  jq -e '.status == "pending" or .status == "sent"' <<<"$action" >/dev/null

log "reconnecting $LUMMA_HOST to deliver the queued action"
printf '# no events: reconnect only\n' >"$WORK/empty.jsonl"
sim lumma "$LUMMA_HOST" "$WORK/empty.jsonl" 1 & PR=$!
status=""
for _ in $(seq 1 100); do
  status="$(api GET "/actions?device_id=$LUMMA_ID&limit=50" | jq -r --arg a "$ACTION_ID" '.items[] | select(.id == $a) | .status')" || true
  [[ "$status" == succeeded || "$status" == failed ]] && break
  sleep 0.3
done
pend=""
for _ in $(seq 1 100); do
  pend="$(api GET "/devices/$LUMMA_ID" | jq -r '.device.uninstall_token_pending')" || true
  [[ "$pend" == false ]] && break
  sleep 0.3
done
stop_pid "$PR"
check "queued block_destination reached 'succeeded' after reconnect (got '$status')" test "$status" = succeeded
check "rotated uninstall token delivered and confirmed by the agent (pending=$pend)" test "$pend" = false
utok2="$(api POST "/devices/$LUMMA_ID/uninstall-token/reveal" '{}')" || utok2='{}'
check "rotated uninstall token is now current" \
  jq -e --arg t "$NEW_UTOK" '.token == $t and .pending_token == null' <<<"$utok2" >/dev/null
new_uhash="$(grep -m1 '^uninstall_token_hash' "$WORK/agent-lumma/agent.toml" 2>/dev/null || true)"
check "agent replaced its uninstall token hash (plaintext never stored)" \
  bash -c '[[ -n "$1" && "$1" != "$2" ]] && ! grep -qF -- "$3" "$4"' _ "$new_uhash" "$OLD_UHASH" "$NEW_UTOK" "$WORK/agent-lumma/agent.toml"
# release-isolation checks the token before anything else (then needs Windows).
old_out="$("$BIN/kestrel-agent" --state-dir "$WORK/agent-lumma" release-isolation --token "$OLD_UTOK" 2>&1 || true)"
new_out="$("$BIN/kestrel-agent" --state-dir "$WORK/agent-lumma" release-isolation --token "$NEW_UTOK" 2>&1 || true)"
check "agent rejects the previous uninstall token and accepts the rotated one" \
  bash -c '[[ "$1" == *"invalid uninstall token"* && "$2" != *"invalid uninstall token"* ]]' _ "$old_out" "$new_out"
if grep -q '"block_destination"' "$WORK/agent-lumma/sim-actions.jsonl" 2>/dev/null; then
  pass "agent executed block_destination (sim-actions.jsonl)"
else
  fail "agent did not record block_destination in sim-actions.jsonl"
fi

# --- Audit chain and hunt ---------------------------------------------------
verify="$(api GET /audit-log/verify)" || die "audit verify"
check "audit log hash chain verifies ($(jq -c . <<<"$verify"))" jq -e '.ok == true and .count > 0' <<<"$verify" >/dev/null

hunt="$(api POST /hunt '{"query": "event_type = dns_query and dns_qname ~ telegram", "limit": 100}')" || die "hunt"
n_hunt="$(jq '.items | length' <<<"$hunt")"
check "hunt 'event_type = dns_query and dns_qname ~ telegram' returns ≥1 row (got $n_hunt)" test "$n_hunt" -ge 1
check "hunt results have no duplicate events" \
  test "$(jq '[.items[] | [.device_id, .ts, .guid, .type]] | unique | length' <<<"$hunt")" -eq "$n_hunt"

dash="$(api GET /dashboard)" || die "dashboard"
check "dashboard counts 3 devices and ≥2 open incidents" jq -e '.devices.total == 3 and .incidents.open >= 2' <<<"$dash" >/dev/null

if grep -qE ' (ERROR|panicked)' "$SERVER_LOG"; then
  fail "server log contains errors"
  grep -E ' (ERROR|panicked)' "$SERVER_LOG" | head -n 10 >&2
else
  pass "server log has no ERROR lines"
fi

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
echo
echo "================ Kestrel E2E summary ================"
echo "passed: ${#PASSED[@]}   failed: ${#FAILED[@]}"
for f in "${FAILED[@]}"; do echo "  FAIL: $f"; done
if [[ ${#FAILED[@]} -eq 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
echo "====================================================="

if [[ ${#FAILED[@]} -ne 0 ]]; then
  echo "----- last 40 lines of server log -----" >&2
  tail -n 40 "$SERVER_LOG" >&2 || true
  exit 1
fi

if [[ "${E2E_KEEP:-0}" == "1" ]]; then
  {
    echo "E2E_KEEP=1: server left running."
    echo "  console:  https://127.0.0.1:$HTTPS_PORT/"
    echo "  login:    $ADMIN_EMAIL / $ADMIN_PASSWORD"
    echo "  lumma incident: ${LUMMA_INC_ID:-?}   lumma device: $LUMMA_ID"
    echo "  server log: $SERVER_LOG"
    echo "Press Ctrl-C (or send SIGTERM to $$) to stop and clean up."
  } >&2
  if [[ -n "${E2E_INFO_FILE:-}" ]]; then
    jq -n --arg url "https://127.0.0.1:$HTTPS_PORT" --arg email "$ADMIN_EMAIL" --arg password "$ADMIN_PASSWORD" \
      --arg incident "${LUMMA_INC_ID:-}" --arg device "$LUMMA_ID" '{url:$url,email:$email,password:$password,lumma_incident:$incident,lumma_device:$device}' \
      >"$E2E_INFO_FILE"
  fi
  wait "$SERVER_PID"
fi
