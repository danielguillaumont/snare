#!/usr/bin/env bash
# Post-deploy smoke test: mint -> touch -> alert, across two tenants.
#
#   SNARE_API=https://api.snare.example.com SNARE_ADMIN_KEY=... scripts/smoke.sh
#
# Optional:
#   SNARE_CALLBACK_BASE  send the touch here instead of the minted URL's origin
#                        (for a local run: http://127.0.0.1:8080)
#
# Creates two throwaway tenants named smoke-<timestamp>, and disables them at the end.
# Needs curl and jq. Exit status 0 means every check passed.
set -euo pipefail

: "${SNARE_API:?set SNARE_API (admin API base URL)}"
: "${SNARE_ADMIN_KEY:?set SNARE_ADMIN_KEY (operator key)}"
api=${SNARE_API%/}
stamp=$(date -u +%Y%m%dT%H%M%SZ)
created=()

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok   $*"; }

call() { # call <key> <method> <path> [json-body]
  local key=$1 method=$2 path=$3 body=${4:-}
  local args=(-sS --fail-with-body -X "$method" -H "Authorization: Bearer $key" -H 'Content-Type: application/json')
  [ -n "$body" ] && args+=(--data "$body")
  curl "${args[@]}" "$api$path"
}

cleanup() {
  for t in "${created[@]}"; do
    call "$SNARE_ADMIN_KEY" POST "/api/operator/tenants/$t/disable" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

new_tenant() { # prints "<tenant id> <admin key>"
  local t k
  t=$(call "$SNARE_ADMIN_KEY" POST /api/operator/tenants "{\"name\":\"smoke-$stamp-$1\"}" | jq -r .id)
  [ -n "$t" ] && [ "$t" != null ] || fail "create tenant $1"
  k=$(call "$SNARE_ADMIN_KEY" POST "/api/operator/tenants/$t/keys" '{"role":"admin"}' | jq -r .key)
  [[ $k == snk_* ]] || fail "issue key for $1"
  echo "$t $k"
}

# new_tenant runs in a subshell, so record the ids here for cleanup.
read -r ta ka < <(new_tenant a) && [ -n "${ta:-}" ] || fail "tenant a"
created+=("$ta")
read -r tb kb < <(new_tenant b) && [ -n "${tb:-}" ] || fail "tenant b"
created+=("$tb")
ok "tenants $ta, $tb with admin keys"

minted=$(call "$ka" POST /api/tokens '{"kind":"canary_url","label":"smoke test canary"}')
id=$(jq -r .id <<<"$minted")
url=$(jq -r .url <<<"$minted")
[ -n "$url" ] && [ "$url" != null ] || fail "mint returned no URL: $minted"
ok "minted $id"

if [ -n "${SNARE_CALLBACK_BASE:-}" ]; then
  url="${SNARE_CALLBACK_BASE%/}/$(sed -E 's#^[a-z]+://[^/]+/##' <<<"$url")"
fi
curl -sS -o /dev/null "$url" || fail "touch $url"
ok "touched the canary URL"

for _ in $(seq 1 40); do
  n=$(call "$ka" GET "/api/events?token=$id&limit=10" | jq length)
  [ "$n" -ge 1 ] && break
  sleep 0.5
done
[ "$n" -eq 1 ] || fail "tenant A sees $n events for its token, want 1"
ok "tenant A sees the touch"

finding=$(call "$ka" GET "/api/events/export?since=0" | head -n1)
[ "$(jq -r .class_uid <<<"$finding")" = 2004 ] || fail "export is not an OCSF Detection Finding: $finding"
[ "$(jq -r .metadata.tenant_uid <<<"$finding")" = "$ta" ] || fail "finding carries the wrong tenant"
ok "export is OCSF 2004 for tenant A"

[ "$(call "$kb" GET "/api/events?token=$id&limit=10" | jq length)" -eq 0 ] || fail "tenant B can read A's events"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $kb" "$api/api/tokens/$id")
[ "$code" = 404 ] || fail "tenant B got $code for A's token, want 404"
ok "tenant B cannot see A's token or events"

acts=$(call "$ka" GET "/api/audit?limit=50" | jq -r '[.[].action] | join(",")')
[[ $acts == *key.issue* && $acts == *tenant.create* ]] || fail "tenant A audit log missing records: $acts"
[ "$(call "$SNARE_ADMIN_KEY" GET /api/operator/audit/verify | jq -r .ok)" = true ] || fail "audit chain does not verify"
ok "audit log records the setup and its hash chain verifies"

# The alert went through the durable outbox: the operator log sink has a delivered row for it.
for _ in $(seq 1 20); do
  st=$(call "$SNARE_ADMIN_KEY" GET "/api/operator/deliveries?limit=200" |
    jq -r --arg t "$ta" '[.[] | select(.tenant_id == $t and .sink == "op:log")][0].state // "none"')
  [ "$st" = delivered ] && break
  sleep 0.5
done
[ "$st" = delivered ] || fail "alert delivery for tenant A is $st, want delivered"
[ "$(call "$ka" GET /api/deliveries | jq '[.[] | select(.sink | startswith("op:"))] | length')" -eq 0 ] ||
  fail "tenant A can see operator sink deliveries"
ok "alert delivered through the outbox; operator deliveries hidden from tenants"

metrics=$(call "$SNARE_ADMIN_KEY" GET /metrics)
grep -q '^snare_hits_total{channel="http"} [1-9]' <<<"$metrics" || fail "metrics lack the HTTP hit"
grep -q '^snare_deliveries_total{sink="log",result="ok"} [1-9]' <<<"$metrics" || fail "metrics lack the delivery"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ka" "$api/metrics")
[ "$code" = 404 ] || fail "tenant key got $code on /metrics, want 404"
ok "metrics report the hit and delivery; tenants can't read them"

echo "PASS"
