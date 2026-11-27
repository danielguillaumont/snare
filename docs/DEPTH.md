# Snare in depth: the plan after v0.7

Snare's core idea holds up: deception gives a binary, low-noise signal. Benign agents
almost never touched a trap: 0/600 normal and 2/232 near-decoy runs in M0, 0/300 after
screening, 0/291 on AgentDojo. What is weak
is everything around that signal. This document says what is weak, by measurement, and what
the next milestones (M6–M14 in [ROADMAP.md](ROADMAP.md)) do about it.

## What the measurements say is missing

| # | Gap | Evidence |
|---|---|---|
| G1 | **Recall is partial.** 42% of credential-hunting agents were caught (46/110, CI 33–51%), 32% immediately. | [results-m3a](results-m3a.md). Every immediate catch came from 3 decoys whose names matched the hunt, and each run exposed only 4 of the 17 decoys. The traps sit at one layer at a time and aren't matched to the threat. |
| G2 | **Alerts don't name the cause.** The [spec](SPEC.md) promises to attribute each alert to the agent, session and input responsible. Today an alert names the tripwire and a source IP. | Triage step 2 ("find the input the agent processed just before the touch") is manual: [detections/README.md](../detections/README.md#triage). |
| G3 | **A code-reading attacker can tell what is a trap.** | `snare_aware` evaded 200/200 before M3a-fix. Warned agents still flag the honey key (69% vs 75%), citing the layout: the token reused in path and key, and the `.test` host ([results-m3a-fix](results-m3a-fix.md)). |
| G4 | **Detection only.** A touch at 3 a.m. pages someone, while the hijacked session keeps its tools. | By design until now; see "Decision needed" below. |
| G5 | **A broken tripwire looks the same as a quiet one.** | Nothing checks that a planted tripwire still reaches an alert after DNS, proxy or sink changes. |
| G6 | **Blind to theft that never touches a trap.** A stolen honey key alerts only when the thief uses it. A secret pasted into an outbound tool call is invisible. | [THREAT-MODEL](THREAT-MODEL.md) §1, last row; M3a's "detected (any)" count needed a harness-only signal for exactly this. |

## The idea: layers along the agent kill chain

A hijacked agent goes through stages, and each stage is a place to put a trap. Today Snare
has traps at two or three layers and treats every touch as the same event. **Snare in depth**
puts a trap at each layer, labels each touch with the stage it proves, and treats a session
that moves through the stages as one incident whose severity is the deepest stage reached.

| Layer | Where it sits | Tripwire | Proves the agent has… | Today |
|---|---|---|---|---|
| L1 Ingest | Untrusted input (docs, tickets, web, email) | Canary instruction; per-source marker | …obeyed untrusted text (**steered**) | Canary instructions exist; no per-source marker |
| L2 Context | System prompt, agent memory, vector store | Prompt canary; memory canary | …leaked its instructions or memory (**steered**) | New |
| L3 Tool | The tool list | Decoy tools, matched to the agent's own tools | …gone looking for capabilities (**recon**) | Separate decoy server; names are generic |
| L4 Data | Repos, env files, corpora | Honey credentials, canary docs | …gathered secrets (**collection**) | Exists |
| L5 Egress | Outbound calls | Honey value in any tool's arguments; canary URL or DNS | …tried to send data out (**exfiltration**) | Only callbacks; arguments not inspected |
| L6 Use | Wherever a stolen value is used | Honey key presented to the callback | …had the stolen value used (**use**) | Exists |

Two things make the layers more than a longer list:

- **Depth is the severity.** A recon-only touch is High. Recon then collection in one
  session is Critical. Reaching egress is Critical with containment, if enabled. This
  replaces today's rule of "two tripwires from one IP within an hour" with one that follows
  the session, not the IP.
- **Gaps are visible.** `snare advise` and the dashboard show, per agent, which layers are
  armed and which aren't, ranked by what the agent can reach. G1 is partly a coverage problem.

## The enabler: Snare Gateway

Most of the layers need something that sees the agent's tool traffic. The gateway is an MCP
proxy that sits between the client and the agent's real MCP servers (stdio first, then
streamable HTTP). It gives Snare five things it can't get from outside:

1. **Decoys inside real servers.** Decoys appear in the real server's tool list, named and
   described in that server's own style, which closes much of G3. They are screened
   offline and re-measured for benign trips before they become the default (M13).
2. **Session identity.** Every touch carries an agent and session id, not just a source IP
   (G2).
3. **Argument inspection.** A honey value (any token Snare minted) in the arguments of
   any real tool call is an L5 touch, caught before the value is used (G6). Detection runs on
   token MACs, as the callback does, so arguments are never logged or stored.
4. **Containment (opt-in).** On a touch at or past a configured stage, the gateway answers
   that session's further tool calls with a bland error until an admin releases it (G4).
5. **Provenance.** The gateway keeps a short per-session ledger of untrusted results it
   forwarded: tool, time, hash and length, never content by default. When a touch fires, the
   alert lists what the agent read just before. With per-source markers (L1), it names the
   document that steered the agent (G2).

The gateway's job is to forward tool calls reliably. If its Snare side fails, forwarding
continues (fail-open): Snare must never be why an agent stops working. Containment is the
one exception, and it is off by default.

## Milestones

Each milestone starts with its own design doc, is $0 unless it says otherwise, and has an
exit criterion that a test or a result file can show. These are the ROADMAP rows, with the
reasoning.

| # | Milestone | Closes | Exit criterion (summary) |
|---|---|---|---|
| **M6** | Snare Gateway | G2, G3, G6 (foundation) | A stdio proxy that forwards every MCP message unchanged, injects decoys, carries session ids into alerts, and detects honey values in arguments. Tested end to end against a real MCP server. Forwarding overhead is measured and published. |
| **M7** | Layers, stages and incidents | G1 | Every tripwire kind has a layer and a stage. Touches group into incidents by session, with severity set by the deepest stage. Incidents appear in OCSF and on the dashboard as a timeline. `advise` reports layer coverage. |
| **M8** | Containment | G4 | With `contain` on, a touch freezes the session's tool calls within one call. Release is audited. With Snare's side down, forwarding is unaffected (tested). Opt-in, off by default (decided below). |
| **M9** | Provenance and attribution | G2 | An end-to-end test plants a poisoned document; the resulting alert names it as the last untrusted input before the touch. No tool content is stored unless capture is turned on. |
| **M10** | Context-layer tripwires | G6 | Prompt canaries (a system prompt that leaks shows up as a touch) and memory canaries for vector stores, with planting support. |
| **M11** | Heartbeat | G5 | Scheduled synthetic touches exercise each channel (HTTP, DNS, gateway) end to end, marked as tests, so SIEM rules ignore them. The dashboard shows "verified N min ago" per channel, and a metric goes stale when a path breaks. |
| **M12** | Adaptive deception | G3 | Decoy names and honey layouts come from the agent's own tool vocabulary and repo (offline, no model), and the token is no longer reused in path and key. A new scripted attacker that reads Snare's source is re-run against them, with results published ($0). |
| **M13** | Proof: Snare in depth | G1 | Pre-registered rerun of M3a's hunt objective with the gateway and all layers, against the 42% baseline. Benign trips are re-checked for gateway-injected decoys. **Budget ≤ $8 under `--max-usd`, asked before running.** |
| **M14** | First run, end to end | adoption | `snare init` finds MCP client configs, proposes a layered plan, wraps servers with the gateway, runs a liveness check and prints a coverage score. `snare demo --attack` replays a hijack as an incident story: steered, recon, collection, contained, attributed. |

Order: the gateway first, because M7–M10 and M12 build on it. The eval comes after the layers
exist, so it measures the whole design once. M14 last, because it packages the rest.
`snare demo` gains each feature as it lands, so the repository shows progress all the way
through.

**Changed in M11 (2026-11-26):** heartbeats stop at the store instead of reaching sinks
"marked as tests". Delivery health is measured by the outbox (M4c), so sending synthetic
findings to every SIEM and chat channel would only add noise and a filter every rule must
remember ([M11](M11-heartbeat.md#decision-heartbeats-dont-reach-sinks)).

**M12 (2026-11-26):** no value reuse had already been fixed for repo and corpus in M3a-fix.
M12 checks it for every plant command, and adds a layout with no token in the URL. On
names, the published result is the limit DEPTH expected. A generator in public code can't
hide decoys from an attacker who has read it. Operator-chosen names remove that attacker's
advantage ([results-m12](results-m12.md)).

**Parked, waiting on Daniel:** applying the AWS IaC (M4) and design partners (M5).

## What we deliberately won't build

- **An injection classifier.** Classifiers are probabilistic and noisy, which is the problem
  Snare's thesis answers. Snare reports behaviour (a trap was touched), not likelihood.
- **Content logging by default.** The gateway sees every tool call. Storing it would make Snare
  the most valuable thing to steal in the deployment. Hashes and lengths only, unless an
  operator turns capture on.
- **Real-looking provider credentials.** The rule in CLAUDE.md stands, even though more
  realistic honey keys would raise recall.
- **Offensive tooling.** Attack payloads stay in `experiments/` against mock tools.

## Risks we accept by doing this

- **The gateway is inline**, so a bug can break an agent. Mitigations:
  - Forwarding is byte-for-byte where possible.
  - The Snare side fails open.
  - The forwarding path gets fuzzing, a conformance test against a real MCP server, and a
    published overhead number.
- **It widens Snare's attack surface.** A compromised gateway is a person-in-the-middle
  on the agent's tools. The threat model gets a gateway section before any code (M6 design
  doc).
- **Injected decoys might hurt real work.** M3c measured −3.4 points utility for a separate
  decoy server. Decoys inside a real server's list could do more harm, so M13 re-measures
  benign trips and utility, and generated names stay off by default until then.

## Decision: containment is opt-in

**Decided 2026-11-26 by Daniel: ship containment, opt-in and off by default.** The spec's
non-goal now reads "preventing injection before a tripwire fires". The reasoning:


**Containment (M8) changes a non-goal.** [SPEC.md](SPEC.md) lists "blocking or preventing
injection" as a non-goal. Freezing a session *after* a trap fires is response, not
prevention: it doesn't stop injection, it limits what a hijacked session does next.
Still, it moves Snare from "observe" to "act", which is why it is off unless an operator
turns it on.
