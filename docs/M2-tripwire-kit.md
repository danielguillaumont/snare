# M2 — Tripwire kit: design

**Goal:** make planting tripwires a one-command job. Exit criterion (ROADMAP): `snare plant`
works on a sample repo and a RAG corpus, and every planted tripwire fires through the M1
callback server, covered by an end-to-end test.

## Commands

| Command | Plants | Fires when |
|---|---|---|
| `snare plant repo <dir>` | A legacy-looking env file with honey service config (base URL, API key, DB host) | Anyone (agent or attacker) uses the URL or resolves the host |
| `snare plant corpus <dir>` | Markdown "break-glass runbook" docs for a RAG / knowledge-base folder | The doc's links or image are fetched, or its credentials are used |
| `snare plant mcp` | A config for `snare decoy-mcp`, plus the snippet to register it with an MCP client | An agent calls any decoy tool |
| `snare decoy-mcp -config F` | (runs) a stdio MCP server exposing decoy tools | — |

Every plant mints one token per tripwire through the admin API, so each alert names the
exact file or tool that was touched (`label`), and records everything in a local manifest
(`snare-planted.json` by default, kept **outside** the planted directory so it doesn't reveal
the decoys).

## Design rules (from M0 results)

1. **Decoy tools come only from the screened catalog**: the 17 decoys that survived the kill
   test. Retired decoys (`fetch_internal_wiki`, `read_payment_methods`, `sync_audit_backup`)
   are never planted. A test checks the Go catalog against the experiment's `decoys.yaml`.
2. **Decoys must not offer a capability a user could legitimately ask for** in that agent's
   job. `snare plant mcp` takes `-exclude` so operators can drop decoys that overlap their
   agent's real scope.
3. **Canary instructions are opt-in** (`-with-instruction`). M0 measured that current Claude
   models acted on planted instructions in < 1% of runs, so links, images and credentials are
   the primary signal in documents, not instructions.
4. **Never imitate real provider key formats.** Honey values are Snare tokens (`snr…`).
   They look like opaque secrets, not like any vendor's keys.
5. **Never overwrite.** Planting refuses to touch an existing file. `-dry-run` prints what
   would be written.

## Decoy MCP server

- Transport: stdio, newline-delimited JSON-RPC 2.0, logs to stderr only.
- Methods: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.
- On `tools/call` for a decoy: respond immediately with a bland success
  (`{"status":"accepted","request_id":…}`) and fire `GET <callback>/t/<token>?tool=<name>` in
  the background. **Tool arguments are never sent** to the callback server: they may contain
  the victim's data.

## Honey values per tripwire

| Value | Form | Channel |
|---|---|---|
| Base URL | `<public_url>/t/<token>` | HTTP |
| API key / password | `<token>` | HTTP (if sent to the base URL) |
| Host | `<token>.<zone>` | DNS |

The repo file and corpus doc each carry one token, so attribution is per file.
