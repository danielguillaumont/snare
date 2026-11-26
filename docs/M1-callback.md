# M1 — Callback core: design

**Goal:** when a planted tripwire is touched, an alert reaches the owner within seconds,
with enough context to act. Exit criterion (ROADMAP): a planted token fires an alert end to
end in < 5 s, covered by tests.

## Scope

| In M1 | Later |
|---|---|
| Signed tokens (mint, verify without a DB lookup) | Multi-tenant accounts (M4) |
| HTTP callback listener | Decoy MCP server, planting CLI (M2) |
| Authoritative DNS callback listener | TLS automation / ACME (deploy step) |
| SQLite store for tokens and events | Postgres (M4) |
| Alert pipeline: signed webhook + log sink, retries | Slack / Sentinel / Splunk sinks (M4) |
| Admin API + `snare` CLI | Dashboard (M4) |

## Token format

**v2 (current, M3a-fix):**

```
<prefix><encode(id || mac)>
id     = 10 random bytes   (80 bits: unguessable, collision-safe)
mac    = first 10 bytes of HMAC-SHA256(server_key, "snare/v2|" || id)
encode = b32 (32 lowercase base32 chars, default) or hex (40 lowercase hex chars)
prefix = empty by default; SNARE_TOKEN_PREFIX sets 1-12 chars of [a-z0-9-]
```

- **No fixed prefix by default.** M3a showed the old `snr` prefix let an attacker who had read
  the code drop every honey value ([results-m3a.md](results-m3a.md)). A v2 token looks like
  any other random secret; only the server key can check the MAC.
- The optional prefix is checked against real provider prefixes (`sk-`, `AKIA`, `ghp_`, `xox`,
  `AIza`, …) and `snr`, so honey values still never imitate a real provider's format.
- `SNARE_TOKEN_ENCODING=hex` gives 40 hex characters. Both fit one DNS label (≤ 63) and are
  case-insensitive.
- **Finding tokens without a prefix:** the listeners scan runs of encoding characters and check
  token-length windows by MAC, capped at 256 MAC checks per input, so junk traffic stays cheap.
  The MAC still drops scanner noise and forged hits **before** the database. Constant-time.
- **v1** (`snr` + 32 base32, MAC domain `snare/v1|`) still verifies, so tokens planted before
  M3a-fix keep firing.
- Minted URLs are `<SNARE_PUBLIC_URL>/v1/<token>`. `SNARE_URL_PATH` changes the path (it was a
  fixed `/t/`, another fingerprint).

## Channels

| Channel | Trigger | Why |
|---|---|---|
| HTTP | Any request whose path, query or `Host` contains a valid token, e.g. `https://cb.example/v1/<token>`; also a token in `Authorization`, `X-Api-Key` or `Api-Key` (recorded as its own hit; the header value is never stored) | Honey URLs, honey API base URLs and keys, canary links |
| DNS | Any query for `*.<token>.<zone>` or `<token>.<zone>` | Fires even when HTTP egress is blocked; resolvers leak lookups by design |

Both answer blandly (HTTP `200 {"status":"ok"}`, DNS an A record to a configured address)
so the toucher learns nothing.

## Event and alert

Each hit becomes an `Event`: token ID, channel, source IP, user agent / query name, time,
and the token's label and metadata. Alerts follow the shape of **OCSF Detection Finding
(class_uid 2004)** so they drop into SIEMs later without reshaping.

- **Dedup:** DNS resolvers retry and fan out. Hits for the same token + channel + source
  within 60 s collapse into one alert (still all stored as events).
- **Webhook sink:** JSON POST with `X-Snare-Signature: sha256=<hex HMAC of body>` and
  `X-Snare-Timestamp`, so receivers can verify origin and reject replays. Retries with
  exponential backoff (3 attempts), never blocking the listener.
- **Log sink:** structured JSON to stdout (`log/slog`).

## Abuse and safety

- Per-source-IP rate limit on the HTTP listener (token bucket).
- Invalid tokens: counted, not stored, no alert.
- Request bodies are not stored (bounded read, discarded) — callbacks may carry stolen data.
- Admin API requires a bearer key, compared in constant time; listens on a separate
  address (default localhost) from the public callback listeners.

## Layout

```
cmd/snare/            CLI: serve, mint, events
internal/token/       mint / verify
internal/store/       SQLite (modernc.org/sqlite, pure Go)
internal/alert/       event model, dedup, dispatcher, sinks
internal/listener/    http.go, dns.go
internal/admin/       admin HTTP API
```

## Configuration (env)

| Variable | Meaning |
|---|---|
| `SNARE_KEY` | Server HMAC key, ≥ 32 bytes, hex. Required. Signs new tokens. |
| `SNARE_KEY_PREVIOUS` | Up to 3 retired `SNARE_KEY` values, comma-separated hex. Tokens minted under them still verify, and their alerts carry `unmapped.verified_by_previous_key` (M4c). |
| `SNARE_ADMIN_KEY` | Bearer key for the admin API. Required. |
| `SNARE_HTTP_ADDR` / `SNARE_DNS_ADDR` / `SNARE_ADMIN_ADDR` | Listen addresses |
| `SNARE_ZONE` | DNS zone Snare is authoritative for, e.g. `cb.example.com.` |
| `SNARE_PUBLIC_URL` | Base URL used when printing honey URLs |
| `SNARE_WEBHOOK_URL` / `SNARE_WEBHOOK_SECRET` | Alert webhook and its signing secret |
| `SNARE_DB` | SQLite path |
| `SNARE_TRUST_PROXY` | `1` behind your own reverse proxy: client IP from the last `X-Forwarded-For` entry |
| `SNARE_SEAL_KEY` | 32 bytes of hex. Enables per-tenant sinks, sealed with AES-256-GCM (M4), and seals token labels and memos at rest (M4d). |
| `SNARE_SINK_ALLOW_PRIVATE` | `1` lets tenant sinks target private addresses. Local testing only (M4) |
| `SNARE_DASHBOARD_ADDR` | Listen address for the read-only tenant dashboard; unset disables it (M4) |
| `SNARE_DASHBOARD_DEV` | `1` drops the cookie `Secure` flag for plain-HTTP localhost; refused on other addresses (M4) |
