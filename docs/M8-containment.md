# M8 — Containment (opt-in)

**Goal:** when a tripwire fires inside a gateway session, stop that agent from doing more
harm until a person has looked.

**Budget: $0.** No model calls.

**Off by default.** This is the one place Snare acts instead of observing, so it runs
only when an operator turns it on (decided 2026-11-26, [DEPTH.md](DEPTH.md#decision-containment-is-opt-in)).

## Shape

```
agent ──► snare gateway ──► real MCP server
              │   ▲
              │   └── state file: frozen? (local, survives restarts)
              └──► Snare server: touch callback (records the touch and the action taken)

admin ──► snare gateway release ──► admin API (audited) ──► clears the state file
```

Containment is decided **in the gateway**, from what the gateway itself sees. It doesn't
wait for the Snare server, so it works when the server is unreachable.

## 1. What triggers it

The gateway sees two kinds of touch (M7 stages):

| Touch | Stage |
|---|---|
| A decoy tool called | recon |
| A honey value in a real tool's arguments | exfiltration |

The config names the earliest stage that contains:
- **`at: "exfiltration"`** (the default once containment is on) acts only on a leak.
- **`at: "recon"`** acts on a decoy call too. It is stricter, and a benign decoy call (M3b
  measured how often that happens) then stops the agent.

Touches seen elsewhere (a honey key used from another host, a DNS lookup) are not seen by
the gateway, so they don't contain. A pull from the server is a possible later step.

## 2. What it does

**Block the leak.** With containment on, the gateway scans a real call's arguments *before*
forwarding it. A call carrying a honey value is not forwarded. The client gets a tool error
instead, and the value never reaches the real tool. The scan is bounded (4,096 windows,
about 1.7 ms worst case, [M6](M6-gateway.md#results)).

**Freeze.** After a containing touch, every later `tools/call` to a real tool gets the same
tool error, without being forwarded.
- Decoy calls are still answered and recorded, so recon stays visible.
- Everything else (`initialize`, `tools/list`, notifications, server replies) is relayed as
  before, so the client stays connected and doesn't retry in a loop.

**The error is bland.** It is an ordinary MCP tool result with `isError: true`. Its text,
"The tool call failed. Try again later.", is the same for a blocked leak and a frozen
call. It doesn't mention Snare or name the trap. The agent learns that calls fail, not
which value was a trap.

**Batches.** A JSON-RPC batch with a `tools/call` in it is not forwarded while frozen, or
when it carries a honey value. Each request in it gets an error. MCP dropped batching in
2025-06-18, so this is a corner case, handled safely rather than precisely.

**Report.** The touch callback carries `contain=blocked` (the call was stopped) or
`contain=frozen` (the session was frozen by a decoy call). This is a fourth allowlisted
context key ([M6 §4](M6-gateway.md#4-session-ids-and-callback-context)). The server
stores it with the event; it appears in OCSF as `unmapped.containment` and on the
dashboard timeline.

## 3. The freeze persists

The freeze is written to a state file before the error is returned.
- **Where.** The config's `contain.state_file`, by default the config path plus `.frozen`.
- **What it holds.** The time, the session id, the stage and the tool name; never
  arguments.
- **Why a file.** A gateway that starts and finds the file starts frozen, so an MCP client
  restarting the server (as clients do after a crash) doesn't release it. Several
  gateways sharing one config share the freeze.

If the file can't be written, the freeze still holds in memory for the life of the process,
and the failure is logged.

## 4. Release is audited

```sh
snare gateway release -config gw.json -note "INC-142: poisoned ticket removed, key rotated"
```

1. The command reads the state file to get the session.
2. It calls `POST /api/sessions/{id}/release` with the note. This is the admin API, with an
   admin key.
   - The server checks that the tenant has a contained touch for that session.
   - It writes a `session.release` audit entry with the note.
3. Only after the server accepts does the command delete the state file.

A running gateway checks the file on each call while frozen, so the release takes effect
on the next call, with no restart.

**Break-glass.** If the Snare server is down, deleting the state file by hand releases the
freeze. That is not audited, and the doc for operators says so. Anyone with write access to
the agent's machine could do it anyway, so the audit records the normal path, not a
security boundary.

## 5. Configuration

```json
"contain": { "at": "exfiltration", "state_file": "/etc/snare/gw.json.frozen" }
```

`snare plant gateway -contain exfiltration|recon` writes it. With no `contain` block, the
gateway behaves exactly as in M6.

## Threat model additions

| Threat | Control |
|---|---|
| Containment breaks agents that were never attacked | Off by default; only Snare's own tokens trigger it; `at: exfiltration` acts only on a honey value leaving |
| An attacker learns which values are traps from the block | The error text is the same for a block and a freeze, and names nothing |
| The agent restarts its server to escape the freeze | The freeze is in a file the next gateway reads at start |
| The Snare server is down | Containment is local. Without containment, forwarding is unaffected: callbacks are asynchronous and fail quietly (tested) |
| A forged release | Release requires the admin API and an existing contained touch for that session; every release is audited |

## Exit criterion

- **Within one call.**
  - The leaking call itself is not forwarded.
  - With `at: recon`, the first real call after a decoy call is blocked.
  - Tests check what the real server received.
- **Persistence.** A new gateway started on a frozen state file blocks real calls.
- **Release.** `snare gateway release` records an audit entry and unfreezes a running
  gateway on its next call. A release for a session with no contained touch, or another
  tenant's, is 404.
- **Fail-open.** With containment off and the callback URL unreachable, every call is
  forwarded unchanged and the added latency stays within M6's measurement.
- **Isolation.** The new store method and route are in the tenant-isolation matrices.
- **End to end.** A gateway with containment on runs in front of the scripted server and a
  real Snare server:
  1. The agent emails the honey key out. The real tool never receives that call.
  2. The next call is blocked.
  3. The incident shows `containment: blocked`.
  4. A release is audited and calls flow again.

## Results

| Item | Status | Evidence |
|---|---|---|
| Block and freeze | Not started | |
| Persistence and release | Not started | |
| Fail-open | Not started | |
| End to end | Not started | |
