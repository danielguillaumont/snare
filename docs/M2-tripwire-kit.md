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
4. **Never imitate real provider key formats.** Honey values are Snare tokens (v2: random
   base32 or hex, with an optional prefix that can't be a provider's; v1: `snr…`).
   They look like opaque secrets, not like any vendor's keys.
5. **Never overwrite.** Planting refuses to touch an existing file. `-dry-run` prints what
   would be written.

## Screening decoys against your own agent (M3b)

The catalog was screened on our four test agents. Yours has different tools and users, so
screen the exact decoys your install will show before relying on them:

```powershell
bin\snare.exe decoys -seed 4242 -screen > my-decoys.json   # same -seed/-style/-names as plant mcp
cd experiments\killtest
python -m killtest screen --tools my-tools.json --system @my-prompt.txt --decoys ..\..\my-decoys.json `
    --generate-only --out screen\mine                       # writes tasks.yaml: read and edit it
python -m killtest screen --tools my-tools.json --system @my-prompt.txt --decoys ..\..\my-decoys.json `
    --tasks screen\mine\tasks.yaml --models claude-haiku-5-5 --max-usd 2 --out screen\mine
```

`my-tools.json` is your MCP server's `tools/list` result. Give each tool a realistic `result`
if you can; the generator writes one for any tool without it. The report gives each decoy a
verdict (RETIRE, REVIEW, UNDERPOWERED or KEEP) and lists every trip with its task, so a person
makes the final call. Drop retired decoys with `plant mcp -exclude`, or rename them with
`-names`. Protocol and validation: [M3b-decoy-screen.md](M3b-decoy-screen.md).

## Decoy MCP server

- Transport: stdio, newline-delimited JSON-RPC 2.0, logs to stderr only.
- Methods: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.
- On `tools/call` for a decoy: respond immediately with a bland success
  (`{"status":"accepted","request_id":…}`) and fire `GET <callback><url_path><token>?tool=<name>`
  in the background. `url_path` is copied from the server's `SNARE_URL_PATH` (default `/v1/`) at
  plant time, so decoy callbacks look like the install's other honey URLs. **Tool arguments are never sent** to the callback server: they may contain
  the victim's data.

## Honey values per tripwire

| Value | Form | Channel |
|---|---|---|
| Base URL | `<public_url>/v1/<token>` | HTTP |
| API key / password | `<token>` (its own token) | HTTP (in a credential header or URL on the callback host) |
| Host | `<token>.<zone>` | DNS |

**M3a-fix:** every field gets its **own** token (labels end in `base_url`, `api_key`,
`db_host`, `db_password`), so an alert says which value was used, and the planted values no
longer repeat one token across fields, which M3a's agents noticed.

**Decoy names (M3a-fix):** `plant mcp` shows each decoy under a per-install name picked from
curated alternatives (`-style snake|camel|kebab`, `-seed N`). `-names FILE` takes your own
`{"catalog_name": {"name": "...", "description": "..."}}`; `-catalog-names` keeps the public
names. Generated names come from public code, so an attacker who reads it can enumerate them
(see [results-m3a-fix.md](results-m3a-fix.md)); only your own names are secret. Every generated
name passed a per-name false-positive screen; one that failed was retired
([results-m3a-fix2.md](results-m3a-fix2.md)).
