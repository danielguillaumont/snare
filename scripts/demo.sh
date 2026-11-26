#!/usr/bin/env bash
# Two-minute local demo: start Snare, create a tenant, plant three tripwires, set one off,
# and print a dashboard sign-in key. Nothing leaves your machine and no model is called.
#
#   scripts/demo.sh            # then open http://127.0.0.1:18090 and paste the printed key
#
# Ctrl-C stops the server. State lives in a temp directory and is discarded.
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
bin=$work/snare
go build -o "$bin" ./cmd/snare

SNARE_KEY=$(openssl rand -hex 32)
SNARE_ADMIN_KEY=$(openssl rand -hex 24)
SNARE_SEAL_KEY=$(openssl rand -hex 32)
export SNARE_KEY SNARE_ADMIN_KEY SNARE_SEAL_KEY
export SNARE_DB=$work/snare.db SNARE_HTTP_ADDR=127.0.0.1:18080 SNARE_ADMIN_ADDR=127.0.0.1:18081 \
  SNARE_DASHBOARD_ADDR=127.0.0.1:18090 SNARE_DASHBOARD_DEV=1 SNARE_PUBLIC_URL=http://127.0.0.1:18080
export SNARE_ADMIN_URL=http://127.0.0.1:18081

"$bin" serve >"$work/server.log" 2>&1 &
server=$!
trap 'kill $server 2>/dev/null; rm -rf "$work"' EXIT
for _ in $(seq 1 50); do curl -s -o /dev/null "$SNARE_ADMIN_URL" && break; sleep 0.1; done

tenant=$("$bin" tenant create -name "Acme Support Agents" | awk '/^tenant:/ {print $2}')
key=$("$bin" tenant key -tenant "$tenant" -role viewer | awk '/^key:/ {print $2}')
admin=$("$bin" tenant key -tenant "$tenant" -role admin | awk '/^key:/ {print $2}')

mint() { SNARE_ADMIN_KEY=$admin "$bin" mint -kind "$1" -label "$2"; }
honey=$(mint honey_credential "billing-svc/.env: PAYMENTS_API_KEY" | awk '/^token:/ {print $2}')
mint decoy_tool "support-agent MCP: export_customer_records" >/dev/null
url=$(mint canary_url "KB article 4471: refund runbook link" | awk '/^url:/ {print $2}')

# The "attack": an agent that read a poisoned ticket follows the canary link, then tries the
# payments key it found in the repo. Two tripwires from one source: the second alert is
# Critical.
curl -s -o /dev/null -A "python-httpx/0.28 (agent)" "$url?ref=ticket-8812"
sleep 1
curl -s -o /dev/null -A "python-httpx/0.28 (agent)" -H "Authorization: Bearer $honey" "$SNARE_PUBLIC_URL/v1/charges"
sleep 1

cat <<EOF

Snare is running.
  Dashboard:  http://127.0.0.1:18090
  Sign in with this viewer key (shown once):
    $key

  Three tripwires are planted for tenant $tenant. One source just touched two of them,
  so the second touch is Critical.
  CLI view:   SNARE_ADMIN_KEY=$admin $bin events
  Server log: $work/server.log

Ctrl-C to stop.
EOF
wait $server
