#!/usr/bin/env bash
# Tiny Kestrel REST client for lab runs.
#   KESTREL_URL=https://localhost KESTREL_EMAIL=admin@… KESTREL_PASSWORD=… scripts/vm/api.sh login
#   scripts/vm/api.sh get  /api/devices
#   scripts/vm/api.sh post /api/enrollment-tokens '{"group_id":"…"}'
#   scripts/vm/api.sh put  /api/policies/default @policy.json
# Session cookie + CSRF token are kept in $KESTREL_API_DIR (default ~/.kestrel-api).
set -euo pipefail
URL=${KESTREL_URL:-https://localhost}
DIR=${KESTREL_API_DIR:-$HOME/.kestrel-api}
mkdir -p "$DIR"; chmod 700 "$DIR"
JAR=$DIR/cookies; CSRF=$DIR/csrf
cmd=${1:?usage: api.sh login|get|post|put|patch|delete PATH [JSON|@file]}; shift || true
case "$cmd" in
login)
    body=$(printf '{"email":"%s","password":"%s"}' "${KESTREL_EMAIL:?}" "${KESTREL_PASSWORD:?}")
    resp=$(curl -sk -c "$JAR" -H 'Content-Type: application/json' -d "$body" "$URL/api/auth/login")
    echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf_token"])' > "$CSRF"
    echo "logged in"
    ;;
get)    curl -sk -b "$JAR" "$URL$1" ;;
post|put|patch|delete)
    m=$(echo "$cmd" | tr a-z A-Z)
    data=${2:-'{}'}
    curl -sk -b "$JAR" -X "$m" -H "X-CSRF-Token: $(cat "$CSRF")" -H 'Content-Type: application/json' \
        --data-binary "$data" "$URL$1" ;;
*) echo "unknown command $cmd" >&2; exit 2 ;;
esac
