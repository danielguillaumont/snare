# M14 — First run, end to end

**Status: design 2026-11-27. $0: no model calls.**

## Why now

The lab can't produce the case Snare exists for with current Claude models
([results-m15](results-m15.md)). The next evidence has to come from real deployments (M5).
Today a team needs to do five things by hand before a single tripwire is live:

1. read INTEGRATIONS;
2. run `snare plant gateway` once per server;
3. hand-edit their MCP client config;
4. find out whether the alert path works;
5. run `snare advise` to see what is still missing.

M14 makes that one command. A team can then try Snare in minutes and tell us what breaks.

## 1. `snare init`

```
snare init [-client F] [-servers a,b] [-dir D] [-profile P] [-apply] [-undo]
```

**By default it is a dry run.** It reads, classifies and prints the plan. It mints nothing,
writes nothing and doesn't need a Snare server. `-apply` carries the plan out.

### Find

- With `-client F`, only that file is read.
- Otherwise these known locations are checked and only the ones that exist are reported:

| Client | Path |
|---|---|
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` (Windows), `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `~/.config/Claude/claude_desktop_config.json` (Linux) |
| Claude Code (project) | `./.mcp.json` |
| VS Code (workspace) | `./.vscode/mcp.json` (`servers` key) |
| Cursor | `~/.cursor/mcp.json`, `./.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

A file that doesn't parse as JSON (VS Code allows comments) is reported and skipped, never
rewritten.

### Plan

Each server gets one action:

| Action | When |
|---|---|
| `wrap` | a local (stdio) server that `advise` gives at least one capability (untrusted input, private data, a way out), or one named in `-servers` |
| `armed` | already behind `snare gateway`, or the Snare decoy server |
| `skip` | a remote (URL) server, which the gateway can't wrap; a server with no capability; one left out of `-servers` |

- **Every action gives its reason.** The plan also lists the advise recommendations the
  gateway doesn't cover, such as `plant repo` for filesystem roots and canary records for
  databases, as next commands. Init doesn't run them: they write into the user's own data.
- **Each wrapped server adds 17 decoys** (or `-profile`'s set) to that server's tool list. M13
  showed a long list of sensitive-sounding tools raises declines ([results-m13](results-m13.md)),
  so with more than one server to wrap the plan prints that tradeoff and the `-profile` flag.
  The default stays `all`, as M13b registered.

### Apply

1. **Gateways:** for each `wrap` server, run `plant gateway` with config
   `<dir>/gw-<client>-<server>.json` (default `dir` is `~/.snare`) and the heartbeat on. Entries
   are appended to `<dir>/snare-planted.json`.
2. **Back up:** copy the client config to `<file>.snare-backup-<UTC timestamp>` first.
3. **Rewrite:** change only the wrapped entries. `command` becomes the absolute path of the
   running `snare`, and `args` becomes `gateway -config <gw> -- <old command> <old args>`.
   - Every other field (`env`, `type`, anything unknown) is kept.
   - Key order is kept, at the top level and among servers.
   - Whitespace is normalised to two-space indentation, which the backup lets you diff.
4. **Liveness:** send one heartbeat through each new gateway config's callback URL, tagged
   with a fresh session id. Then poll `GET /v1/heartbeats` for up to 10 s, until the `gateway`
   channel shows that session as its last source.
   - Success: "verified N s ago".
   - Failure: "not verified", with the likely cause (server unreachable, `SNARE_PUBLIC_URL`
     wrong). Init exits non-zero.
   - The client config is still rewritten, because a gateway that can't reach Snare forwards
     unchanged (M8 fail-open).
5. **Coverage:** print layer coverage from the manifest (`advise.Coverage`), "Layers armed: N
   of 6", with the command that arms each missing layer.

The client must be restarted to pick up the change, and init says so.

### Undo

`snare init -undo [-client F]` puts every wrapped entry back to the command after `--`,
after taking a backup first. Gateway configs and tokens stay. It prints the token IDs to
disable with `snare tokens -disable`, so a lingering decoy name can't fire.

### Safety

- **Dry run by default.**
- **Backup before every write.**
- **Idempotent:** a second `-apply` wraps nothing new.
- **Never wraps Snare itself.**
- **Never follows remote servers.**
- **Never prints a token:** gateway configs are written private (0600), as `plant gateway`
  writes them.

## 2. `snare demo -attack`

The current demo plants three tripwires and fires two over HTTP. `-attack` instead tells the
whole story through a real gateway, in process, with no model. The pieces:

- a scripted MCP server: a support desk with `get_ticket`, `read_file` and `send_email`;
- a scripted "agent" that reads a poisoned ticket, calls a decoy, reads the honey key and
  emails it;
- containment at `exfiltration` and provenance on.

It then prints the incident as a timeline:

| Step | What the demo shows |
|---|---|
| steered | the poisoned ticket is the last untrusted input (M9 fingerprint, named) |
| recon | the decoy call: `layer=tool` |
| collection | the honey key read from the planted file |
| contained | the email carrying it is not forwarded, and the session freezes (M8) |
| attributed | one incident, severity by deepest stage (M7), with the source named |

The incident comes from the admin API (`/v1/incidents/{id}`), the same data the dashboard
shows. Nothing is faked after the gateway. Everything runs on loopback and is deleted on
exit, as in today's demo.

## Exit criterion

- **`snare init`** goes from a client config to wrapped servers, a verified heartbeat and a
  coverage score in one command. Tested end to end against a real Snare server, a scripted
  MCP server and a temp client config. Tests also cover:
  - a dry run writes nothing;
  - a second apply changes nothing;
  - undo restores the original command;
  - unknown fields and key order survive;
  - a JSON file with comments is skipped untouched.
- **`snare demo -attack`** prints all five steps from a real incident. A test asserts each
  step against the admin API.

## Results

| Item | Status | Evidence |
|---|---|---|
| `snare init` | Not started | |
| `snare demo -attack` | Not started | |

## Changelog

- 2026-11-27: design.
