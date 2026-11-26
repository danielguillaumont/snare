# M6 — Snare Gateway

**Goal:** a proxy between an MCP client and the agent's real MCP servers. It puts decoys
inside the real tool list, gives every touch a session id, and catches a honey value being
sent out through any real tool. This is the foundation for M7–M10 ([DEPTH.md](DEPTH.md)).
**Budget: $0.** No model calls.

## Shape

```
MCP client ──stdio──▶ snare gateway -config gw.json -- <real server command> ──stdio──▶ real server
                           │
                           └─ callbacks (HTTPS) ──▶ Snare callback listener
```

`snare gateway` starts the real server as a child process and relays newline-delimited
JSON-RPC between the two. A client config entry that ran `npx some-server` now runs
`snare gateway -config gw.json -- npx some-server`. Streamable HTTP transport is later work.

## 1. Relay

- **Unchanged by default.** Every message the gateway doesn't need to change is forwarded
  byte for byte, in order, in both directions. That covers:
  - requests and notifications it doesn't recognize;
  - server-to-client requests (sampling, roots, elicitation) and their responses;
  - JSON-RPC batches (arrays);
  - malformed lines.
- **Two messages are changed:**
  - **`tools/list` responses** to the client's own `tools/list` requests, matched by
    request id. Decoys are appended to the final page only (the one with no
    `nextCursor`).
  - **`tools/call` for a decoy name.** It is answered by the gateway and never reaches the
    real server.
- **Lifecycle.**
  - When the client closes stdin, the gateway closes the child's stdin and exits with the
    child's exit code.
  - When the child exits, the gateway exits.
  - The child's stderr passes through.
- **Fail-open.** Callbacks are asynchronous with a timeout. Inspection errors and panics are
  recovered and logged. Relaying continues whatever happens on Snare's side.

## 2. Decoys inside the real server

- **Names match the server's own style.** With `style: auto`, the gateway reads the real
  tool names from the first `tools/list` reply and picks the majority style: `snake`,
  `camel` or `kebab`. It then generates names from the config's seed with the existing
  screened generator (`decoys.Pick`). A fixed style or per-install overrides work as they do
  for `snare plant mcp`.
- **Real tools always win.** A decoy whose name equals a real tool's is dropped, and that
  name is never intercepted.
- **Answer and callback.** A decoy call gets the same bland `accepted` reply as from
  `snare decoy-mcp`. The gateway sends a callback carrying the decoy's token. Arguments are
  never sent anywhere.

## 3. Honey values in tool arguments (egress layer)

The gateway must recognize Snare tokens in arguments without holding anything a hijacked
agent could use, even if it reads the gateway's config.

- **Fingerprints, not tokens or keys.** The config holds a random salt and a set of
  fingerprints:

  ```
  fingerprint = hex(SHA-256("snare/fp/v1|" + salt + "|" + body))[:32]
  ```

  `body` is a token without its prefix: v2 base32 (32 chars), v2 hex (40), or a whole v1
  token. The server computes fingerprints for every token in the tenant, under the current
  and previous keys, in both encodings. They come from `POST /api/fingerprints`, an admin
  route scoped to the tenant.
- **Scan.** For each `tools/call` to a real tool, the gateway scans the raw `arguments` JSON
  with the same candidate windows the listener uses, hashes each window, and looks it up.
  - There is a cap of 4,096 windows per call. SHA-256 on a few KB is microseconds.
  - Arguments are scanned in memory and never logged or stored.
- **Report.** On a match, the matched window *is* the honey token, which the agent already
  holds. The gateway sends a normal callback with it, so the listener verifies the MAC and
  records the touch on that tripwire as usual. Nothing new leaves the machine.
  - The forwarded call is not blocked: M6 observes, and blocking is M8.
- **Staleness.** Fingerprints are a snapshot. `snare plant gateway -refresh -config F`
  re-fetches them after new tripwires are planted.

Recognized formats: unprefixed or custom-prefixed v2, b32 or hex, and v1. A value that was
re-encoded before sending (base64, split across fields) is not recognized. That is a known
limit.

## 4. Session ids and callback context

- The gateway draws a random session id at start (one stdio process serves one client
  session).
- Every callback it sends carries `?layer=<tool|egress>&tool=<name>&session=<id>`.
- The HTTP listener copies only these three query parameters into the event's detail, and
  only when they match `^[A-Za-z0-9._-]{1,64}$`. Anything else is dropped.
- A token is still required for anything to be recorded, so a forged query on a forged
  token records nothing. A valid token with a forged `layer` mislabels its own touch, and
  only the holder of that token can do that.

M7 turns `session` into a column and groups incidents by it. In M6 it is in the event detail
and therefore in the OCSF finding (`unmapped.detail`).

## 5. Planting

`snare plant gateway -config gw.json [-style auto|snake|camel|kebab] [-seed N] [-exclude a,b]`:

1. Mints one decoy token per catalog decoy.
2. Fetches fingerprints with a fresh salt.
3. Writes the config, refusing to overwrite.
4. Prints the client entry to wrap a server with.

`-refresh` updates only the fingerprints of an existing config.

## Threat model additions

| Threat | Control | Tested by |
|---|---|---|
| Gateway bug breaks the agent's real tools | Byte-for-byte relay of everything it doesn't own; fail-open on Snare's side; fuzzed message handling | Relay tests (byte equality across message kinds), fuzz target |
| Hijacked agent reads `gw.json` to learn which values are traps | Fingerprints are salted SHA-256 of 80-bit random MAC material: not invertible, and no token or key in the file. Decoy tokens **are** in the file, as they are for `decoy-mcp`; keep the config outside the agent's workspace | Config contents test |
| Gateway leaks tool arguments | Arguments are never logged, stored or sent; only a matched honey token (already in the agent's hands) is reported | Callback contents test |
| Gateway becomes a person-in-the-middle for the agent's tools | It runs as the user, with the user's own server command; it has no network listener. Compromising it means compromising the user's account, which already controls the client config | Design (no listener) |
| Forged callback context labels | Allowlisted keys and charset; a valid token is still required | Listener test |

## Exit criterion

- **Relay.** Relay tests show byte-for-byte forwarding for every message kind in §1.
  Decoys are injected only into the final `tools/list` page, and real-name collisions are
  dropped.
- **End to end** (`internal/server`), with a scripted downstream server that has real tools:
  - an injected decoy call is a touch with `layer=tool` and the session id;
  - a honey credential passed to a real tool is a touch on that credential's tripwire with
    `layer=egress`;
  - the real tool still receives the call unchanged.
- **Overhead.** Round-trip overhead of the relay is measured against a direct pipe and
  published, with raw output.
- **Config.** `gw.json` holds no signing key and no honey token.

Not in M6: streamable HTTP transport, blocking (M8), session columns and incidents (M7), and
running against third-party MCP servers in CI. That last one needs network installs; the
scripted server covers the protocol paths.

## Results

| Item | Status | Evidence |
|---|---|---|
| Relay | ✅ | `internal/gateway/gateway_test.go`: byte-for-byte relay of requests, notifications, batches, malformed lines, server-to-client requests and their replies, including `\r\n` endings and a 300 KB line. `FuzzRelay` checks the same invariant on arbitrary input: about 313,000 inputs in 40 s locally, and it runs in the CI fuzz matrix. |
| Decoys in real servers | ✅ | Final `tools/list` page only, real names win, and `auto` style follows the server (camelCase server, camelCase decoys). A decoy call never reaches the server. A server request that reuses a pending id doesn't consume it; that test was added after a mutation check showed the gap. |
| Egress fingerprints | ✅ | `internal/token/fingerprint_test.go`: b32, hex, prefixed and v1 bodies; no match outside the set; window cap. `TestFingerprintsCoverOwnTokensOnly`: a tenant's fingerprints don't recognize another tenant's tokens, and contain no token or id. |
| Session context | ✅ | `internal/server/gateway_e2e_test.go`, against a real Snare server and a scripted MCP server with real tools. An injected decoy call is a touch with `layer=tool`. A honey key emailed through `send_email` is a touch on that key's tripwire with `layer=egress tool=send_email`. Both carry the same session id, and the real tool received the call unchanged. |
| Overhead | ✅ | One 1 KB `tools/call` round trip over in-process pipes, checking 500 tripwires (4,500 fingerprints). Median **25.2 µs direct, 54.4 µs through the gateway** (10 runs each), so about 29 µs added per call. Worst-case scan (a 64 KB base32 run, capped at 4,096 windows): median **1.7 ms**, 2 allocations. An earlier version allocated per window (8,193 allocations, 3.5–10.6 ms) and was rewritten before merge. Raw output: [bench/gateway-roundtrip.txt](../bench/gateway-roundtrip.txt) and [bench/gateway-scan-worstcase.txt](../bench/gateway-scan-worstcase.txt). Measured on a laptop CPU (i7-11370H, Windows), so this is not a capacity guarantee. |

Not measured:
- behaviour with third-party MCP servers, which are not run in CI;
- the benign-trip rate and utility cost of decoys inside a real server's list.

Both are M13's job, and the second is why `auto` names stay in the screened generator.
