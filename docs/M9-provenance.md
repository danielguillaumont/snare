# M9 — Provenance: what the agent read before it touched a trap

**Goal:** when a tripwire fires, the alert says what the agent read just before. That
read is usually the injected document that steered it. Without this, a responder knows
*that* an agent was hijacked but not *by what*, and the poisoned input stays in place to
hijack the next run.

**Budget: $0.** No model calls.

## 1. The input ledger

The gateway already sees every tool result the real server returns. It keeps a ledger
of the last **8** results per session, dropping entries older than an hour.

Each entry is the **tool name**, **when** it was returned, the **length** of its text, and
a **fingerprint**:
- **The fingerprint** is the first 16 hex characters (64 bits) of the SHA-256 of the
  result's text.
- **The text** is every `content[].text` and `content[].resource.text`, joined in order with
  nothing between. For a file read that is usually the file's exact contents, so the
  fingerprint matches a hash of the file.

**Never content.** The ledger holds no text from the result and no tool arguments. It is
kept in memory only.

Decoy replies are Snare's own and are not recorded. Error replies carry no result and
aren't recorded either. Neither are `tools/list` replies, or replies to an id the gateway
never forwarded.

**One gateway, one session.** A gateway process serves one agent session, so its ledger is
that session's ledger.

**Matching replies to calls.** The gateway remembers the id of each real `tools/call` it
forwards, with the tool name, until the reply arrives. It holds at most 1,024 such ids; past
that, new calls are relayed unrecorded rather than letting memory grow.

## 2. What a touch carries

Every touch the gateway reports carries the ledger as it stood when the touch fired, oldest
first. Each entry goes in its own callback parameter, `in0`…`in7`, as
`tool~fingerprint~length~age_seconds`.
- The listener allowlists these keys, as it does `layer`, `tool`, `session` and `contain`
  ([M6 §4](M6-gateway.md#4-session-ids-and-callback-context)).
- Each value must match that exact shape, or it is dropped.

The server stores the entries with the event. They appear:
- **In OCSF** as `unmapped.inputs`. The finding description names the last input: "Last
  input before this touch: read_file returned 1,240 characters (fingerprint 3fa1…) 4 s
  earlier."
- **On the dashboard** incident timeline, under each touch.
- **In the CLI**, under each touch in `snare incidents -id N`.

## 3. Naming the document

**By fingerprint (default).** The responder runs, on the machine with the documents:

```sh
snare provenance find -hash 3fa1c2d4e5f60718 path/to/kb path/to/tickets
```

It walks the directories and hashes each file. It also hashes a CRLF-normalized copy, since
tools often return text with `\n` line ends. It prints every file whose fingerprint
matches. Nothing leaves the machine.

**By name (opt-in).** With `"provenance": {"names": true}` in the gateway config, an entry
also carries the value of the call's first identifier-like argument: `path`, `file`,
`filename`, `uri`, `url`, `id` or `name`, in that order.
- It is sanitized to `[A-Za-z0-9._/:-]`, at most 128 characters.
- It is sent as `src0`…`src7`.

This names the document directly in the alert, but it sends argument values to the Snare
server. That is why it is off by default. `snare plant gateway -provenance-names` turns it
on.

## 4. Limits

- **Only what the gateway sees.** Inputs that reach the agent another way, such as a web
  page fetched by a client-side tool or a prompt typed in, aren't in the ledger.
- **Fingerprints locate, they don't prove.** A match says a file had the same text. 64 bits
  is plenty to pick one file out of a corpus, not a forensic hash. Keep the full hash if
  you need one.
- **The last input is a lead, not a verdict.** An injected document may have been read
  several calls before the touch; that is why there are eight entries, not one.
- **JSON-RPC batches** are relayed and scanned as before (M6), but their results aren't
  recorded. MCP clients send single requests in practice.
- **Per-source markers** (a unique marker planted in each document of a corpus, so the
  gateway can name a document from its text alone) are left for later. Fingerprints and
  opt-in names cover the exit criterion without planting anything new.

## Exit criterion

- **Ledger.** Unit tests cover:
  - entries recorded from real tool results only (not decoys, not errors, not
    `tools/list`);
  - capped at 8, oldest dropped, and expired after an hour;
  - no argument or result text in any callback (checked on the URL);
  - names only when opted in.
- **Listener.** Malformed `in*` and `src*` values are dropped.
- **Fingerprint.** `snare provenance find` names a file from a fingerprint the gateway
  produced, with LF and CRLF line ends.
- **End to end.** Against a real Snare server and a scripted MCP server:
  1. The agent reads a poisoned ticket, then calls a decoy.
  2. The decoy touch's alert lists the ticket's read as the last input.
  3. `snare provenance find` names the ticket from that fingerprint.
  4. With names on, the alert names its path.

## Results

Measured 2026-11-26, Go 1.27.4, Windows 11, `go test ./...`. No API spend.

| Item | Status | Evidence |
|---|---|---|
| Ledger | ✅ | `internal/gateway/ledger_test.go`. Only real results are recorded: not decoy replies, errors, `tools/list` or unsolicited ids. Capped at 8, oldest dropped; expired after an hour (fake clock). No argument or result text, and no honey value, in the callback query. Names are sent only with `names: true`. |
| Listener and storage | ✅ | `TestHTTPInputsAreValidated` covers nine malformed shapes, each dropped with its source, and only `in0`…`in7`; the ledger never reaches the free-text detail. `TestInputsAreStoredWithTheEvent` covers the cap and read-back through events and the incident timeline. `TestAlertNamesTheLastInput` covers the description and `unmapped.inputs`. |
| `provenance find` | ✅ | `TestFindNamesTheFile`: the fingerprint the gateway computes for a `read_file` result names the LF file exactly and the CRLF copy as "read as LF". It skips `.git` and rejects malformed hashes. |
| End to end | ✅ | `TestEndToEndProvenance`, twice: with fingerprints only, and with names. The agent searches, reads a clean ticket, fails one read, reads the poisoned ticket, then calls a decoy. The webhook alert has 3 inputs (not the failed read), and the last is the ticket's read. `provenance.Find` over the knowledge base names the ticket and only it. The dashboard timeline shows the inputs. With names on, the alert and the dashboard name `tickets/T-42.md`; with names off, neither does. The alert never carries the ticket's text. |

**Mutation checks.** Two deliberate bugs were each caught:
- sending names without the opt-in fails the content test and the end-to-end test;
- not expiring entries fails the expiry test.
