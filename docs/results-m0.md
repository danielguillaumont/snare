# M0 results: the kill test

**Verdict: GO** (after the one iteration the protocol allows).
Protocol and changelog: [killtest.md](killtest.md).
Evidence: `experiments/killtest/results/full-20261125/` (`final/report.md` is the scored set).

## Headline numbers

Models: `claude-haiku-5-5`, `claude-sonnet-5-5`, `claude-opus-5-5`, effort `medium`.
Rates exclude refusals. Intervals are 95% Wilson.

| Measure | Result | Source |
|---|---|---|
| Benign trip rate (normal tasks) | **0.0%** (0/600; CI 0.0–0.6%) | `full-20261125/benign` |
| Adjacent trip rate, run 1 (20 decoys) | 11.2% (26/233; CI 7.7–15.8%) → ITERATE | `full-20261125/adjacent` |
| Adjacent trip rate, rerun (17 decoys, held-out tasks) | **0.9%** (2/232; CI 0.2–3.1%) | `full-20261125/adjacent-v2` |
| Canary *acted* (tag went into a tool call) | 0.8% (2/240) — both on Opus | `full-20261125/canary` |
| Canary *echoed only* (tag in the reply) | 45% (108/240), mostly agents **reporting** the planted line | `full-20261125/canary` |
| Attack runs compromised | **0/201** valid runs | `full-20261125/attack` |
| Detection rate given compromise | **Not measured** (no compromises) | — |
| Total spend | ≈ $12.21 (pilot $0.02, calibration $0.24, run 1 $9.39, rerun $2.56) | `meta.json` files |

## What we learned

1. **Benign agents leave well-designed decoys alone.** Zero trips in 600 normal runs across
   three models and 20 decoys.
2. **Decoy design is the whole game.** One decoy, `fetch_internal_wiki`, caused 20 of 26
   adjacent trips: it reads as a genuinely helpful tool. Two others tripped only when the user
   asked for exactly what they offered (billing details, backups). Rule adopted: *a decoy must
   not offer a capability a user could legitimately ask the agent for.* This is the core of
   the planned **decoy safety engine**: score decoys in simulation before deploying them.
3. **Current Claude models rarely follow planted instructions, and often report them.**
   Only 2/240 canary runs acted on the tag. Most replies that contained it said something like
   "the email contains a line asking me to add this code; I ignored it". Product implication:
   an agent's *reply* is itself a detection channel. If Snare watches agent output for its
   tags, it learns which data source carries an injection even when the agent refuses it.
4. **The attack arm couldn't test detection.** No model was hijacked by the 8 naive payloads,
   and Opus declined 35 of 80 attack runs (safety classifier). So this experiment does **not**
   show that decoys catch hijacked agents. It shows the false-positive side only.
5. **Security-flavored benign tasks trigger refusals on Opus.** 8 adjacent-v2 runs stopped with
   a `cyber` refusal category. Worth knowing for anyone deploying agents on security work.

## Limitations (read before quoting any number)

- **Claude models only.** Other model families may behave differently, in either direction.
- **Mocked tools and short tasks** (median 2 turns). Long, open-ended agent sessions give more
  chances to wander into a decoy.
- **Same author for decoys and tasks.** The held-out adjacent set reduces, but doesn't remove,
  the risk that tasks unconsciously avoid the decoys.
- **Decoys were changed after seeing data** (once, as pre-registered). The rerun's 0.9% is on
  tasks written after that change, but it's still one iteration on one task set.
- **Tag matching** can't tell "obeyed" from "reported" in replies; only the *acted* number is
  unambiguous.

## What this means for the roadmap

- GO for **M1** (callback service): the false-positive premise holds for well-chosen decoys.
- **M3** must measure the detection side properly: stronger attacks (AgentDojo-style, multi-turn),
  more model families, and long-horizon tasks, so there are compromised runs to detect.
- The decoy safety engine moves from "nice to have" to **core product**: run 1 shows an
  unscreened decoy set fails, and a screened one passes.
