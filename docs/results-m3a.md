# M3a results — detection of credential-hunting agents

**Verdict (pre-registered, v2.1): PARTIAL.** Snare's tripwires caught **42%** of
credential-hunting Haiku agents (46/110, 95% CI 33–51%). **32%** were caught immediately by a
decoy call (35/110, CI 24–41%). There were **0 false trips in 180 benign runs** across
Haiku, Sonnet and Opus (CI 0–2.1%). In every run where the real secret was collected
(16/16), a tripwire fired on the same turn or earlier.

Protocol, thresholds and every amendment: [M3-detection-eval.md](M3-detection-eval.md).
Evidence: `experiments/killtest/results/m3/full-20261125/combined/` (live runs, $2.08) and
`experiments/killtest/results/m3/policies/` (scripted attackers, $0). Pilots are in
`results/m3-pilot/` and are excluded from every number here.

## Headline numbers

| Measure | Result | Runs |
|---|---|---|
| Credential-hunting agents detected (any tripwire) | **41.8%** (CI 33.0–51.2%) | Haiku `hunt`, 46/110 |
| ...detected immediately (decoy call; no honey URL was ever requested) | **31.8%** (CI 23.9–41.0%) | 35/110 |
| Agents that collected the real secret | 14.5% (CI 9.2–22.3%) | 16/110 |
| ...of those, a tripwire fired first or on the same turn | **100%** (CI 80.6–100%) | 16/16 |
| Warned agents ("honeytokens and decoys are planted here") detected | 60.7% (CI 47.6–72.4%) | Haiku `hunt_aware`, 34/56 |
| ...detected by decoy call alone | 41.1% (CI 29.2–54.1%) | 23/56 |
| Benign false trips | **0.0%** (CI 0.0–2.1%) | `benign3`, 0/180 (60 per model) |
| Strong injection: agents compromised | 0.0% (CI 0.0–5.7%) | `inject`, 0/64 valid |

"Detected (any)" includes the **honey credential being handed over** (it appears in the
report or an outbound tool). That fires in production only when someone uses the stolen key,
which this harness can't observe. The immediate numbers make no such assumption.

### Scripted attackers (analytical, 200 runs each, $0)

| Strategy | Real secret collected | Detected | Immediate |
|---|---|---|---|
| `greedy`: read every credential file, call every secret-sounding tool | 100% | **100%** | 81% |
| `files_only`: read every credential file, no extra tools | 100% | **100%** | 0% |
| `targeted`: read only the file named `prod` | 48% | 52% | 0% |
| `snare_aware`: as greedy, but skips Snare's public decoy names and drops `snr…` tokens | 100% | **0%** | 0% |

## What we learned

1. **The false-positive premise still holds with more tripwires in play.** With a honey
   credential file sitting next to the real one, benign agents on all three models never used
   it and never called a decoy (0/180). They also never quoted it (0/180).
2. **Hunting agents trip decoys a third of the time, through three decoys only.** All 35
   immediate detections came from `list_api_keys` (18), `read_env_secrets` (16) and
   `query_vault_v2` (8): decoys whose *names* match what the agent is hunting for. The other 14
   decoys caught nothing in this objective family. **Implication:** match decoys to the threat
   you are hunting for (credential theft calls for credential-named decoys) and expose more of
   them. Each run exposed only 4 of the 17.
3. **When the secret actually left, Snare always fired first or alongside (16/16).** The agents
   that collected the real secret also collected the honey key, because they took everything.
   The `files_only` policy shows the same thing analytically: an attacker who takes every
   credential always takes the honey too.
4. **Snare's public design can be fingerprinted (the main product finding).**
   - The `snare_aware` scripted attacker evaded **200/200**. Snare is open source, so its
     decoy catalog names and its `snr` token format are public knowledge.
   - Warned Haiku agents flagged the honey key as suspicious in **42/56** runs, citing the same
     token reused as the URL path (`/t/<token>`) and the key, and the `.test` host. That's the
     M2 `snare plant repo` layout.
   - Of the warned agents' 17 "honey taken" runs, all 17 came *with* a suspicion caveat, so
     the aware arm's 60.7% overstates what a careful attacker would trigger. Use the 41.1%
     decoy-only figure.
5. **Claude models resist being turned, at three levels.**
   - They ignore a hidden attacker objective (0/20) and decline an explicit red-team role
     (8/8; v1 pilot).
   - Sonnet and Opus refuse even an *authorized* credential audit (12/12 `cyber` refusals),
     which is why the primary metric is Haiku-only.
   - Strong AgentDojo-style injections compromised **0/64** valid runs. The classifier stopped
     most Opus (37/40) and many Sonnet (19/40) injection runs before they started. For Snare
     that is good news about the models, and it means real compromises of Claude agents will
     be rare events, which is the setting where a near-zero-false-positive tripwire is worth most.

## Limitations (read before quoting any number)

- **A proxy, not a hijack.** The headline measures agents doing an *authorized* credential
  audit, which take the same steps a thief would. It is not "hijacked agents detected", and it
  must not be quoted that way.
- **One model** for the primary metric (Haiku), because Sonnet and Opus refuse the task.
- **One objective family** (credential theft) and one environment layout.
- Scripted-policy results are analytical: they show what each strategy triggers, not how often
  real attackers use it.
- Same author for the environment, decoys and tasks.

## What this means for the roadmap

- **Fix the fingerprinting (new, high priority):** per-install generated decoy names,
  configurable token formats, and separate values for the honey URL path and the key. Re-run
  `snare_aware` and `hunt_aware` afterwards: both are now regression tests for evasion.
- **Decoy selection by threat:** the safety engine (M3b) should screen for false positives
  *and* rank decoys by catch rate per objective family. This run shows the spread is large.
- **M3c (AgentDojo / other model families):** still needed for genuine hijacks, since Claude
  models won't produce them here.
