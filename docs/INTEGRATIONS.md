# Wiring Snare into the agents and tools you already run

This guide starts with a running server (`snare serve`, with `SNARE_PUBLIC_URL` set) and an
admin key in `SNARE_ADMIN_URL` / `SNARE_ADMIN_KEY`. It covers three jobs:

1. Put decoy tools in front of an agent.
2. Check that a tripwire is live without raising a real incident.
3. Send alerts to the place your team already looks.

Every `snare` command below is checked by `cmd/snare/integrations_test.go`: if a flag is
renamed, that test fails until this page is updated.

## The short way: `snare init`

`snare init` does section 1 and the liveness part of section 2 in one go
([M14](M14-first-run.md)). It finds your MCP client configs (Claude Desktop, Claude Code's
`.mcp.json`, VS Code, Cursor, Windsurf) and says which servers it would put behind the gateway
and why:

```sh
snare init
```

That is a dry run: nothing is minted or written. When the plan looks right:

```sh
snare init -apply
```

What `-apply` does:
- **Gateways:** plants one gateway per chosen server in `~/.snare`.
- **Client config:** backs it up next to itself, then rewrites only the wrapped entries.
  Other fields and key order stay.
- **Liveness:** sends a heartbeat through each gateway's callback URL and checks Snare
  recorded it.
- **Coverage:** prints which kill-chain layers are armed.

Restart the client afterwards.

- `-client F` reads one file instead of searching.
- `-servers a,b` picks the servers yourself.
- `-profile credentials` plants 4 decoys per server instead of 17.
- `snare init -undo` puts the original commands back.

A config with comments is reported and left alone. Remote (URL) servers can't be wrapped;
use the decoy server below for those.

The rest of this page is the same thing by hand, plus the parts init leaves to you.

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

Both `plant mcp` and `plant gateway` plant all 17 catalog decoys by default. `-profile` narrows
that to the objectives you want trapped: `credentials` (4 decoys), `data` (7) or `control` (6),
comma-separated. `-exclude` still applies on top. In our eval, the full list made one model
decline an authorized task three times as often as a short list did
([results-m13](results-m13.md)), so a smaller set is worth considering. A pre-registered screen
of `credentials` as the default cut declines from 33% to 24% but missed its bar, so the
default stays `all` ([results-m13b](results-m13b.md)).

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

**Names in the server's own vocabulary (opt-in).** With `-style adapt`, decoy names also take
the real server's namespace and verbs, and its argument style: a Jira server whose tools are
`jiraFetchIssue` and `jiraShowBoards` gets decoys like `jiraFetchEnvSecrets`. Preview them
from a saved `tools/list` reply before you plant:

```sh
snare decoys -adapt tools.json
```

Adapted names haven't been screened for benign trips yet, so `auto` (style only) stays the
default. An attacker who has read Snare's code can still recognise generated names; your own
names (`-names`) are the ones it can't. Measured in
[results-m12.md](results-m12.md).

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

**Containment (opt-in, off by default).** With `-contain exfiltration`, the gateway does
more than report a honey value leaving:
- it doesn't forward the call that carries it, so the value never reaches the real tool;
- it freezes the session: every later real tool call fails with a bland error.

`-contain recon` also freezes on a decoy call, which is stricter: a benign decoy call then
stops the agent. The freeze is kept in `gw.json.frozen`, so restarting the server doesn't
lift it. Release it, with a note for the audit log, once you've looked:

```sh
snare plant gateway -config gw.json -contain exfiltration
snare gateway release -config gw.json -note "INC-142: poisoned ticket removed, key rotated"
```

The release is recorded through the admin API (an admin key) before the freeze is removed.
If the Snare server is down, deleting `gw.json.frozen` by hand also releases it, but that
release is not audited. Design: [M8-containment.md](M8-containment.md).

**What the agent read before the touch.** Every touch the gateway reports carries its last
8 tool results as fingerprints: tool, length, age and a 16-hex hash, never the text. The
alert's description names the last one. To find the file it came from, run this on the
machine with the documents; nothing leaves it:

```sh
snare provenance find -hash 3fa1c2d4e5f60718 kb tickets
```

To have the alert name the path directly, plant with `-provenance-names`. That sends each
call's `path`, `url` or similar argument to the Snare server, so it is off by default:

```sh
snare plant gateway -config gw.json -provenance-names
```

Design: [M9-provenance.md](M9-provenance.md).

**The agent's prompt and memory.** Put a canary in the system prompt, and records in the
agent's memory, so that a leaked prompt or an acted-on memory is a touch:

```sh
snare plant prompt -file system-prompt.md
snare plant memory -count 3 memory-import
snare plant gateway -refresh -config gw.json
```

`plant memory` writes `memory-notes.jsonl` (`-format md` for one note per record). Load it
with whatever loads the agent's vector store or memory server. Recalling a record is not a
touch; opening its link, using its key or sending it out is. Refresh the gateway afterwards
so it recognizes the new values. Design: [M10-context-canaries.md](M10-context-canaries.md).

**Warnings.** A planted gateway records two kinds of warning. Neither is ever sent to your
sinks on its own:
- **A honey value reached the agent.** It came back in a real tool's result, so the agent has
  read it ([M16](M16-early-warning.md)).
- **A real tool's definition changed.** The gateway pins each tool's name, description and
  schema the first time it sees them, in `gw.json.pins`. A later difference under the same
  name is a warning ([M17](M17-tool-integrity.md)).

Each joins the session's incident, and a tripwire touch after it in that session is
Critical. They show as `warning` in `snare events`, `snare incidents` and the dashboard, and
as severity Low in exports. When a server upgrade legitimately changes a tool, review it and
accept the new definition:

```sh
snare gateway pins -config gw.json                 # which tools changed
snare gateway pins -config gw.json -accept send_email
```

Turn either warning off when planting, with `-exposure=false` or `-integrity=false`.

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

**Keep it verified.** One manual check shows the path worked once. To know it still works,
turn on the heartbeat. The server then touches its own heartbeat token through its public
URL and DNS name on a schedule, and every planted gateway beats every 15 minutes. A
heartbeat is never an event or an alert.

```sh
snare heartbeat
```

It prints each channel's last verified time, and exits non-zero if one is stale or has
never beaten. The dashboard shows the same, and the metrics expose
`snare_heartbeat_stale{channel}`. Alert on it being 1. Turn the probe on with
`SNARE_HEARTBEAT=15m` on the server. Design: [M11-heartbeat.md](M11-heartbeat.md).

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
