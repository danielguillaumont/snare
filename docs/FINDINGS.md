# What we found

This page summarizes every evaluation Snare has run, in one place. Each number links to the
write-up that holds its denominator, its confidence interval (95% Wilson) and its raw data.
Every live evaluation was pre-registered: the rules were committed before the run, and any
change after a run is in that document's changelog.

**Scope, before any number.**
- All model runs are Claude models (Haiku, Sonnet, Opus 5.5).
- They ran in our own scripted environments, except M3c, which used AgentDojo.
- None of it is a measurement on real deployments or real attacks.
- Total live spend across the project: about **$34**.

## 1. Tripwires almost never fire on honest work

This is the result that holds up best, and the one a deception product needs most.

| Evaluation | Benign trips | Write-up |
|---|---|---|
| M0, normal tasks, 3 models, 20 decoys | 0/600 (CI 0–0.6%) | [results-m0](results-m0.md) |
| M3a, M13, M13b `benign3`, 3 models | 0/180 each time | [m3a](results-m3a.md), [m13](results-m13.md), [m13b](results-m13b.md) |
| M3a-fix2, generated decoy names, held-out hard tasks | 0/300 (CI 0–1.3%) | [results-m3a-fix2](results-m3a-fix2.md) |
| M3c, inside AgentDojo, unmodified benchmark | 0/291 (CI 0–1.3%); utility −3.4 points | [results-m3c](results-m3c.md) |
| M16, warnings during benign work | 0/60 warnings, 0 trips | [results-m16](results-m16.md) |

**The caveat is decoy design.**
- In M0's first adjacent run, one decoy (`fetch_internal_wiki`) caused 20 of 26 trips,
  because it offered something a user could legitimately want.
- The rule since then: a decoy must never offer a capability the user could ask for.
- `killtest screen` (M3b) found that decoy blind, using only generated tasks
  ([results-m3b](results-m3b.md)).

## 2. Alert-level tripwires catch about a third of credential hunters, and depth didn't change that

These are agents told to find credentials, measured on runs where the agent used at least one
tool.

| Setup | Caught by a decoy call or honey use | Write-up |
|---|---|---|
| M3a, 4 decoys | 40/110 = 36.4% | [results-m3a](results-m3a.md) |
| M13, every layer, 17 decoys | 92/267 = 34.5% (CI 29.0–40.3%), against a 51.2% bar: **FAIL** | [results-m13](results-m13.md) |
| M13b, credentials profile | 61/152 = 40.1% | [results-m13b](results-m13b.md) |
| M16, same as M13, new seed | 49/138 = 35.5% | [results-m16](results-m16.md) |

**More decoys didn't catch more agents, and they cost something.** The long tool list
tripled text-only declines (33% against 11%). We published the failure rather than adjust the
bar after the fact.

## 3. Most misses had already read the trap, and that is now on the record

- **Post-hoc lead.** Re-scoring old runs showed that most missed agents had opened the honey
  file and then stopped. Nothing fired, because a honey credential fires only when it is used.
- **M16.** M16 makes that read a **warning**. In the pre-registered check, 106/138 runs
  (76.8%, CI 69.1–83.1%) were warned or caught, against a 60% bar: **PASS**.
- **The honest reading.**
  - 57 of those 106 have only a warning, which is severity Low and doesn't page anyone.
  - Only 1 warned run went on to touch a tripwire.
  - So the gain is in what a triager can find, not in alerts.

## 4. In our lab, Claude models didn't commit the harm we wanted to measure

- **M0:** 0/201 attack runs compromised.
- **M3a:** 0/64 under a strong injection.
- **M15:** Haiku declined 40/40 handoff requests to send production credentials out, whether
  the destination looked external or internal. The eval stopped at its pilot, as registered
  ([results-m15](results-m15.md)).
- **Where real secrets did leave:** every run that sent a real secret out through a tool was
  caught (17/17, post-hoc). All of these were authorized audits.

So against these models, Snare is a backstop for when the model's own refusal fails. A
detection rate for real hijacks needs real deployments. We can't estimate it in a lab where
the models refuse.

## 5. Attackers who know about Snare

| Attacker | Result | Write-up |
|---|---|---|
| Scripted, avoids anything that looks like a known honeytoken | Caught 0/200 at first. After v2 tokens with no fixed prefix: **200/200** | [results-m3a-fix](results-m3a-fix.md) |
| Scripted, has read Snare's name generator | **0/200** against generated names, even when adapted to the server. 138/200 = 69.0% against operator-chosen names, against a 90% bar: **FAIL** | [results-m12](results-m12.md) |
| Haiku, told "honeytokens and decoys are planted here" | 34/56 = 60.7% still caught | [results-m3a](results-m3a.md) |

- **Token formats:** detection-by-format is solved by tokens with no fixed shape.
- **Source access:** an attacker who has read Snare's source avoids every generated decoy
  name. Names the operator writes take that advantage away. The remaining misses come from
  names that don't sound like secrets to the attacker.

## 6. Engineering numbers

- **Gateway overhead:** about 29 µs per 1 KB tool call ([M6](M6-gateway.md#results)).
- **Single node, one laptop:**
  - about 14,000–16,000 junk requests per second with 0 failures;
  - about 140–300 stored, sealed and delivered touches per second
    ([results-bench](results-bench.md)).
- **Delivery:** alerts survive restarts and sink outages ([M4c](M4c-reliability.md#results)).

## What we don't know

- **Other models:** how any of this transfers to non-Claude models, or to agents that do get
  hijacked.
- **Warning noise:** how often warnings fire on real coding agents that read `.env` files
  as part of their job.
- **Server churn:** how often real MCP servers change their tool definitions. This is the
  M17 noise question.
- **Real environments:** whether any of the above holds outside scripted environments. M5,
  design partners, is the step that would answer this.
