# Wiring Snare into the agents and tools you already run

This guide starts with a running server (`snare serve`, with `SNARE_PUBLIC_URL` set) and an
admin key in `SNARE_ADMIN_URL` / `SNARE_ADMIN_KEY`. It covers three jobs:

1. Put decoy tools in front of an agent.
2. Check that a tripwire is live without raising a real incident.
3. Send alerts to the place your team already looks.

Every `snare` command below is checked by `cmd/snare/integrations_test.go`: if a flag is
renamed, that test fails until this page is updated.

## 1. Decoy tools in an MCP client

First ask where tripwires would do the most good for this agent. `advise` reads the client's
config offline and calls no model:

```sh
snare advise -config claude_desktop_config.json
```

After planting, `-manifest` shows which layers of the kill chain are armed and what would
arm the rest:

```sh
snare advise -manifest snare-planted.json
```

Then plant the decoy server. Pass `-exclude` for any decoy that overlaps the agent's real
job: a decoy the agent is supposed to call is a false positive waiting to happen.

```sh
snare plant mcp -dry-run -config decoy-mcp.json -exclude list_api_keys
snare plant mcp -config decoy-mcp.json -exclude list_api_keys -style snake
```

`plant mcp` writes `decoy-mcp.json` and prints a client entry like this, with the absolute
paths of your `snare` binary and config file:

```json
{
  "mcpServers": {
    "internal-ops": {
      "command": "/usr/local/bin/snare",
      "args": ["decoy-mcp", "-config", "/home/you/decoy-mcp.json"]
    }
  }
}
```

Where the entry goes:

| Client | File | Notes |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` (Settings → Developer → Edit Config) | Merge the entry into the existing `mcpServers` object, then restart the app. |
| Claude Code | `.mcp.json` at the project root, for a project-scoped server | Same `mcpServers` shape. |
| Other clients | Their MCP config file | Most use the same `mcpServers` shape. VS Code's `.vscode/mcp.json` names the object `servers`; the entry inside is the same. |

Choose `-style` to match how the agent's real tools are named (`snake`, `camel` or `kebab`),
so the decoys don't stand out. Each install gets its own random names unless you pass
`-seed`. `-catalog-names` uses the public catalog names, which are easy to fingerprint.

Keep the manifest (`snare-planted.json`) out of anything the agent can read. It lists every
decoy.

### Or: decoys inside your real servers (gateway)

`snare gateway` wraps a real MCP server instead of adding a separate one. The agent sees one
server, whose tool list has the decoys in it, named in that server's own style. The gateway
also watches every real tool call for a honey value being sent out, for example a planted
key pasted into an email. Everything else passes through unchanged.

```sh
snare plant gateway -config gw.json -exclude list_api_keys
```

Then change the server's client entry from running the server directly to running it
behind the gateway. For a server started with `npx some-mcp-server --repo .`:

```json
"github": { "command": "snare", "args": ["gateway", "-config", "/home/you/gw.json", "--", "npx", "some-mcp-server", "--repo", "."] }
```

Each touch it reports carries:

- `layer=tool` (a decoy was called) or `layer=egress` (a honey value left through a real
  tool);
- the tool's name;
- a session id shared by every touch from one client session.

Arguments are never logged or sent. The gateway recognizes honey values from salted
fingerprints, so `gw.json` holds no honey value and no key. It does hold decoy tokens, so
keep it outside the agent's workspace. After planting new tripwires, refresh the
fingerprints:

```sh
snare plant gateway -refresh -config gw.json
```

## 2. Confirm a tripwire is live without paging anyone

You want to know that a touch reaches Snare and your alerting before an attacker tests it
for you. Use a dedicated test tripwire, not a planted one, and close it out afterwards so it
doesn't sit in the open queue.

```sh
snare mint -kind canary_url -label "liveness check: delete me"
```

`mint` prints the token's URL. Fetch it once (with `curl` or a browser), then find the touch:

```sh
snare events -status open -limit 5
```

The new event's id is in the first column. Record that it was you, and retire the test tripwire:

```sh
snare triage -event 42 -status false_positive -note "liveness check"
snare tokens -disable tok_...
```

A disabled tripwire still records touches. It just never alerts, so a stray fetch later
shows up on the dashboard without paging anyone. To exercise a sink without touching any
tripwire, use `POST /api/sinks/{id}/test` (below). It sends a finding marked
Informational, which the shipped detection rules ignore.

## 3. Route alerts to your tools

**Operator-wide.** `SNARE_WEBHOOK_URL` and `SNARE_WEBHOOK_SECRET` send every alert to one
signed webhook. See [M1-callback.md](M1-callback.md) for the signature format.

**Per tenant.** With `SNARE_SEAL_KEY` set, each tenant adds its own destinations through the
admin API. Configs are sealed at rest, and listing a sink never returns its secrets.

```sh
curl -sS -X POST "$SNARE_ADMIN_URL/api/sinks" \
  -H "Authorization: Bearer $SNARE_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"type": "splunk_hec", "url": "https://splunk.example.com:8088", "token": "...", "index": "security"}'

curl -sS -X POST "$SNARE_ADMIN_URL/api/sinks/sk_.../test" -H "Authorization: Bearer $SNARE_ADMIN_KEY"
```

| `type` | Fields |
|---|---|
| `webhook` | `url`, `secret` (at least 16 characters; signs each body) |
| `slack` | `url` (the incoming-webhook URL; treated as a secret) |
| `splunk_hec` | `url`, `token`, optional `index` |
| `elastic` | `url`, `api_key`, optional `index` |
| `sentinel` | `url` (DCE), `rule_id`, `stream`, `azure_tenant_id`, `client_id`, `client_secret` |

Sink URLs must be public HTTPS addresses; private and link-local targets are refused (the
SSRF guard in [M4-saas.md](M4-saas.md)). Detection rules for each SIEM, including the
multi-tripwire correlation, are in [detections/](../detections/).

**Pulling instead of pushing.** `GET /api/events/export` streams a tenant's findings as OCSF
NDJSON. Use it for a SIEM that only pulls, or to keep your own copy before
`SNARE_EVENT_RETENTION` deletes closed events.

## When a real alert fires

Follow the triage steps in [detections/README.md](../detections/README.md). The short version:

1. Work out who touched it, what input steered the agent there, and what else it reached.
   The alert's `unmapped.incident_id` names the incident; `snare incidents -id N` prints
   every touch in it, with its stage, in order.
2. Decide whether it was a person testing (the only usual false positive).
3. Record the outcome with `snare triage`.
4. Retire the touched tripwire and plant a fresh one.
