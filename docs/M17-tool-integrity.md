# M17 — Tool integrity: a real tool's definition changed

**Status: built 2026-11-27, $0. No model runs were planned or made.**

## 1. Why

An MCP server can change what its tools say after a client has started trusting it. This is
called a "rug pull" or tool poisoning:
- a tool's description gains hidden instructions;
- its schema gains a parameter such as `notes` or `context`, for the agent to fill with
  whatever it has read.

The agent reads tool descriptions as instructions. So a changed definition is an injection
path that never shows up in a tool result, and no Snare layer saw it until now.

The gateway already parses every `tools/list` reply to place decoys (M6). It sees each real
tool's name, description and schema, so it can notice when one changes.

## 2. Design

### Pin on first sight, warn on change

- **Fingerprint.** For each real tool in a `tools/list` reply, the gateway takes a SHA-256
  of its definition: name, description and input schema, in canonical JSON with sorted keys.
  It does this before decoys are added.
- **Pins.** The first fingerprint for a tool name is its pin. Pins are kept in a pin file
  next to the gateway config (`<config>.pins`), so they hold across restarts and sessions.
  This is trust on first use, like SSH host keys.
- **Change.** A later fingerprint that differs from the pin is a change. The gateway touches
  its own `integrity_signal` token with the session and the tool name. It does this at most
  once per tool per session, and it does not update the pin.
- **New and removed tools.** Tools that appear later are pinned silently, and tools that
  disappear are ignored. Servers add and drop tools on upgrade; a changed definition under
  the same name is the rug-pull shape.
- **Relayed unchanged.** The reply reaches the client exactly as before, plus decoys.
  Detection only: M17 doesn't block or strip anything.

### A warning, like M16

- `integrity_signal` is a new token kind, minted per gateway by `snare plant gateway`. It is
  on by default; `-integrity=false` turns it off.
- Its touches are **warnings**. They are recorded with layer `ingest` and stage `steered`,
  join the session's incident and are never sent on their own. A legitimate server upgrade
  changes descriptions too, so a change can't page anyone by itself.
- **Escalation needs no new rule.** A decoy call or honey use after the warning in that
  session has two tripwires and two stages, so it is Critical (M7 §3).
- As with M16, only the token's kind makes a warning. Callback parameters can't downgrade a
  honey token's touch.

### Accepting a change

`snare gateway pins -config F` lists the pins, and `-accept TOOL` re-pins one tool from its
latest definition. The gateway records the latest definition it saw in the same file. The
file holds fingerprints only, never descriptions, so nothing sensitive is written.

### Not in M17

- **Judging description content,** for example flagging instruction-like text. `snare
  advise` is the place for static checks, and a heuristic needs its own false-positive
  measurement.
- **Blocking a changed tool.** Containment for this stage would need its own decision about
  failing closed during upgrades.
- **Remote servers.** They aren't behind the gateway (M14 §1).

## 3. Exit criterion ($0)

- **Gateway:**
  - the first `tools/list` pins every real tool, and decoys are never pinned;
  - an unchanged list sends nothing;
  - a changed description or schema sends one warning per tool per session, carrying the tool
    name and never the description;
  - pins survive a restart, and a change across restarts is caught;
  - a new tool is pinned silently;
  - the reply is relayed as before;
  - with no integrity token configured, nothing is pinned or sent.
- **Server:** an `integrity_signal` touch is a warning (ingest/steered), is not queued, joins
  the incident, and a following decoy touch is Critical.
- **CLI:** `snare gateway pins` lists the pins, and `-accept` re-pins one tool.
- **Planting:** `snare plant gateway` mints the token and `-integrity=false` skips it.

**What isn't measured:** how often real servers change definitions during benign use. No
public server corpus is run here. That is why it is a warning.

## Results

| Item | Status | Evidence |
|---|---|---|
| Mechanism | ✅ Built | See below |

- **Gateway** (`internal/gateway/integrity_test.go`):
  - the first `tools/list` pins every real tool, and decoys are never pinned;
  - formatting and key order are not changes;
  - a changed description, and separately an added schema parameter, each send one warning
    for that tool, once per session;
  - the reply is relayed with the changed definition intact;
  - a new tool is pinned silently;
  - pins survive a restart, and an unaccepted change warns in every later session until
    `AcceptPin`;
  - with no integrity block nothing is pinned;
  - the pin file holds fingerprints only, and the callback carries the tool name, never
    the description.
- **Server** (`internal/store/integrity_test.go`, `internal/alert/exposure_test.go`): the
  touch is a warning at ingest/steered and is not queued. A decoy touch after it in the
  session is Critical. The OCSF finding is Low and says how to accept a reviewed change.
- **End to end** (`cmd/snare/integrity_e2e_test.go`): a real server, `plant gateway` and a
  scripted server that rewrites `send_email`'s description between two sessions:
  - the first session records nothing;
  - the second records the warning and the decoy call in one incident, steered > recon;
  - `snare gateway pins` lists `send_email` as CHANGED.
- **CLI:** `snare gateway pins -config F [-accept TOOL]` (`cmd/snare/pins_test.go`).
- **Planting:** `snare plant gateway` mints the token by default, and `snare init` inherits
  it. `-integrity=false` turns it off.

## Changelog

- 2026-11-27: design registered before implementation.
