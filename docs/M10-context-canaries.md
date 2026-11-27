# M10 — Context canaries: a leaked system prompt or memory is a touch

**Goal:** arm the context layer (L2 in [DEPTH.md](DEPTH.md#the-idea-layers-along-the-agent-kill-chain)).
An agent's system prompt and its memory are not tools and not files in a repo, so no
existing tripwire sits there. Prompt extraction and memory poisoning are common first moves
against an agent. Today Snare can't see either.

**Budget: $0.** No model calls.

## 1. Two new kinds

| Kind | Planted in | Layer, stage when touched directly |
|---|---|---|
| `prompt_canary` | The agent's system prompt (or `AGENTS.md`, a custom-instructions file) | context, steered |
| `memory_canary` | The agent's long-term memory: a vector store, a memory MCP server, a notes folder | context, steered |

Each plant is a short passage that reads like something a team really puts in a prompt or
in memory: an internal link and a service key, marked staff-only. Each value is its own
token, as for every Snare plant ([M3a fix](M3a-fix-antifingerprint.md)), so the alert says
which value was used. The wording never mentions Snare, canaries or traps, and is picked
from several phrasings by seed, so one deployment's plant doesn't fingerprint the next.

The classification follows M7's rules:
- **Fetched or resolved directly** (someone opened the link or resolved the name): context,
  steered.
- **Found in a tool call's arguments by the gateway:** egress, exfiltration. The agent is
  sending its prompt or memory out.
- **Presented as a credential:** use. The key left and is being tried.

## 2. What counts as a touch, and what doesn't

**A prompt canary fires when the prompt leaves.** That covers three cases:
- the agent writes its instructions into a tool call (the gateway sees the token in the
  arguments);
- someone who extracted the prompt opens the link or tries the key;
- a client renders the leaked prompt as Markdown and fetches the link.

A benign agent has no reason to do any of these: the passage says the values are not for
the assistant.

**A memory canary fires when a recalled memory is acted on or sent**, the same three ways.
**Recall alone is not a touch.** A vector search can return the record for an innocent
query, and paging on that would teach people to ignore the layer. Recall is still on the
record: if the memory store is behind the gateway, the record's read is in the M9 ledger,
so the eventual alert names it as an input.

**Gateway users must refresh.** The gateway looks for the fingerprints in its config. After
planting context canaries, run `snare plant gateway -refresh -config gw.json`, as for any
new tripwire.

## 3. Planting

```sh
snare plant prompt [-dry-run] [-manifest F] [-seed N] [-file F]
snare plant memory [-dry-run] [-manifest F] [-seed N] [-count N] [-format jsonl|md] <dir>
```

**`plant prompt`** prints the passage to paste into the system prompt. With `-file`, it
appends the passage to that file instead. It refuses if the file already holds a prompt
canary planted by Snare, checked through the manifest, not by a marker in the file: a
marker would be a tell.

**`plant memory`** writes `-count` records, 3 by default and at most 10, into `<dir>`:
- **`-format jsonl`** (default) writes one file, `memory-notes.jsonl`, one record per line:
  `{"id", "text", "metadata"}`. That is the shape most vector-store loaders and memory
  servers import. The operator loads it with their own tooling. Snare doesn't talk to the
  store.
- **`-format md`** writes one Markdown note per record, for file-based memory folders.

It refuses to overwrite existing files.

Both record their tokens in the manifest with type `prompt` or `memory`. `snare advise
-manifest` then reports the context layer as armed.

## 4. Limits

- **A prompt that never leaves through something Snare sees is not caught.** For example,
  a model that paraphrases its prompt to a user in chat without the link or key. The
  canary catches verbatim leaks and use of the values.
- **Recall is not detected** (§2), by design.
- **Loading into a vector store is the operator's step.** Snare writes the records. It has
  no connector for each store.
- **Placement matters.** A canary in a prompt that is never deployed arms nothing. `advise`
  counts what the manifest says was planted, not what is live.

## Exit criterion

- **Classification.** `TestClassify` has rows for both kinds, direct and through egress and
  use.
- **Planting.**
  - Tests cover each value getting its own token and the passage containing no "snare",
    "canary" or "trap".
  - Different seeds give different phrasings.
  - `-file` appends once and refuses a second time; dry runs mint nothing.
  - `plant memory` writes valid JSONL and Markdown, respects `-count` and its limit, and
    refuses to overwrite.
- **Coverage.** `advise -manifest` reports the context layer armed by either kind, and
  unarmed with the command to arm it otherwise.
- **End to end.** Against a real Snare server, with a gateway in front of a scripted MCP
  server:
  1. A system prompt carrying a planted canary is pasted by the agent into `send_email`.
     That is a touch: kind `prompt_canary`, egress, exfiltration.
  2. The prompt canary's link opened directly is a touch at context, steered.
  3. A memory record from `plant memory`, served by a scripted memory server, is recalled.
     Recall raises no touch. The agent then passes the record's link to a fetch tool behind
     the gateway, which gives two `memory_canary` touches:
     - at egress, from the gateway, with the M9 ledger naming the recall as its last input;
     - at context, steered, when the fetch reaches the link.

     The record that was never recalled has no touches.

## Results

Measured 2026-11-26, Go 1.27.4, Windows 11, `go test ./...`. No API spend.

| Item | Status | Evidence |
|---|---|---|
| Classification | ✅ | `TestClassify`: six new rows, both kinds direct (context, steered), through egress and as a used credential. |
| Planting | ✅ | `TestPromptPassage`, `TestPromptFileAppendsOnce`, `TestMemoryRecords` cover:<br>• two tokens per passage or record;<br>• no "snare", "canary", "trap", "tripwire", "honey" or "decoy" in any planted text or file name;<br>• at least 3 phrasings across 12 seeds;<br>• `-file` appends once, a second plant is refused through the manifest without minting, and a missing file is an error;<br>• dry runs mint and write nothing;<br>• JSONL parses one record per line with unique ids, and Markdown writes one note per record;<br>• `-count` bounds and unknown formats are rejected, and existing files are never overwritten. |
| Coverage | ✅ | `TestCoverage`: either kind alone arms the context layer. Unarmed, it names `snare plant prompt` and `snare plant memory`. Context canaries also count as values for a gateway to find. |
| End to end | ✅ | `TestEndToEndContextCanaries`, all three steps above, on the real planting code, gateway and server. |

**Mutation check.** With `prompt_canary` left out of the classification, the end-to-end test
and `TestClassify` both fail.
