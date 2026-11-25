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

```
snr<id><mac>      all lowercase base32 (RFC 4648 alphabet, no padding)
id  = 10 random bytes   (80 bits: unguessable, collision-safe)
mac = first 10 bytes of HMAC-SHA256(server_key, "snare/v1|" || id)
```

- 3 + 16 + 16 = **35 characters**: fits one DNS label (≤ 63), safe in URLs, env files and
  JSON, and case-insensitive (DNS lowercases labels).
- The MAC lets the listeners drop scanner noise and forged hits **before** touching the
  database. Verification is constant-time.
- `snr` prefix makes Snare tokens recognizable to Snare and to secret scanners, which is
  deliberate: we never imitate real provider key formats (CLAUDE.md rule).
- Key rotation: the MAC is versioned by the `snare/v1|` domain string; a v2 key can verify
  in parallel later.

## Channels

| Channel | Trigger | Why |
|---|---|---|
| HTTP | Any request whose path or `Host` contains a valid token, e.g. `https://cb.example/t/<token>` | Honey URLs, honey API base URLs, canary links |
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
| `SNARE_KEY` | Server HMAC key, ≥ 32 bytes, hex. Required. |
| `SNARE_ADMIN_KEY` | Bearer key for the admin API. Required. |
| `SNARE_HTTP_ADDR` / `SNARE_DNS_ADDR` / `SNARE_ADMIN_ADDR` | Listen addresses |
| `SNARE_ZONE` | DNS zone Snare is authoritative for, e.g. `cb.example.com.` |
| `SNARE_PUBLIC_URL` | Base URL used when printing honey URLs |
| `SNARE_WEBHOOK_URL` / `SNARE_WEBHOOK_SECRET` | Alert webhook and its signing secret |
| `SNARE_DB` | SQLite path |
