# M12 results — adaptive deception against scripted attackers

Pre-registration and changelog: [M12-adaptive-deception.md](M12-adaptive-deception.md).
Run 2026-11-26, seed 41, 200 runs per policy on `hunt`, scripted policies only. **Spend $0.**

Evidence:
- `experiments/killtest/results/m12/policies-adapt/`;
- `experiments/killtest/results/m12/policies-adapt-names/`.

The baseline is M3a-fix's `results/m3fix/policies/`.

## Verdict: 1 of 2 criteria met

| # | Criterion | Result | |
|---|---|---|---|
| C1 | `snare_aware` detected ≥ 90% in `adapt` | **200/200** (95% CI 98.1–100%) | **PASS** |
| C2 | `source_reader` detected ≥ 90% in `adapt-names` | **138/200 = 69.0%** (CI 62.3–75.0%) | **FAIL** |

## Results in detail

Detected means a decoy call or the honey key used. Immediate means a decoy call, or the key sent
to the honey host. The real secret taken is the attacker's goal. Each policy gets its own plan
draws, so real-secret shapes differ slightly between rows.

### `adapt`: names adapted to each scenario's real tools, key layout

| Policy | Knows | Real secret taken | Detected | Immediately |
|---|---|---|---|---|
| `greedy` | nothing | 200/200 | 200/200 | 165/200 |
| `files_only` | nothing | 200/200 | 200/200 | 0/200 |
| `targeted` | reads only `prod` files | 89/200 | 111/200 | 0/200 |
| `snare_aware` | v1 public names, `snr` prefix | 200/200 | **200/200** | 136/200 |
| `code_reader` | M3a-fix's 204 names, v2 shapes | 89/200 | **59/200** (29.5%, CI 23.6–36.2%; M3a-fix: 0/200) | 59/200 |
| `source_reader` | M12's generator, v2 shapes | 100/200 | **0/200** (CI 0–1.9%) | 0/200 |

- **List-based fingerprinting stops working once names depend on the server.** `code_reader`
  knows every name the M3a-fix generator can produce, and evaded 200/200 there. Here it calls a
  decoy in 59/200 runs: whenever adaptation shows a name outside its list.
  - In these servers that is only 6–12% of names, because they already use the catalog's verbs
    and no namespace. That figure was computed before the run and is recorded in the
    changelog.
  - A server with its own namespace or verbs moves every name. `TestAdapt*` and the gateway
    tests show this, but no run here measures it.
- **The attacker who has read M12's code evades every decoy, as stated before the run.**
  `source_reader` re-derives each name's canonical form (namespace dropped, verb class) and
  skips any that matches the generator's stems. It drops every token-shaped value, so it
  never takes the honey key.
  - **The cost to it is unchanged from M3a-fix.** It gets the real secret only when the secret
    isn't token-shaped: 100/200, and 200/200 runs agree with that rule.

### `adapt-names`: every decoy under an operator-defined name

The 17 names were written before any run (`data/operator_names.json`).

| Policy | Real secret taken | Detected | Immediately |
|---|---|---|---|
| `greedy` | 200/200 | 200/200 | 143/200 |
| `snare_aware` | 200/200 | 200/200 | 135/200 |
| `code_reader` | 89/200 | 135/200 | 135/200 |
| `source_reader` | 100/200 | **138/200** | 138/200 |

- **Operator names take away the code reader's advantage on decoys, but C2 fails as
  registered.**
  - `source_reader` calls a decoy in every run where one of the four decoys shown sounds like a
    secret to it: 138 of 138 runs.
  - In the other 62 runs no decoy is called, because nothing shown matches the
    secret-sounding words it looks for.
  - The cause is the names, not the generator. Only 4 of the 17 operator names contain one of
    those words (`atlas_runtime_secrets`, `ledgerd_breakglass_credentials`,
    `partner_gateway_keys`, `atlas_vault_read`).
- **Compare `greedy`, who knows nothing.** It calls a decoy in 143/200 runs under the same names
  (CI 64.9–77.3%). That overlaps `source_reader`'s 62.3–75.0%: reading the code bought it
  nothing against these decoys.
- **What would raise it, not tested here:** operator names that sound like what this attacker
  hunts for. Choosing them is the operator's call, and it trades off against benign trips
  (M0, M3a-fix2), which only an LLM run can measure.

## What changed in the product

1. **`style: adapt`** for the gateway (`snare plant gateway -style adapt`). Decoy names and
   arguments take the real server's namespace, verbs, naming and argument style, and its
   description punctuation. `snare decoys -adapt tools.json` previews them.

   Not the default. Adapted names haven't been screened for benign trips; M13 screens them.
2. **`plant repo -layout key`.** The base URL carries no token, so no path segment looks like
   one. The key fires when it is used against the URL, as the end-to-end test shows; opening
   the URL alone is silent.
3. **`plant repo -adapt`.** It follows the variable prefix and quoting of the dotenv files
   already in the directory.
4. **No value reused.** A test checks the output of every plant command: one token per field.

## Limitations

- These are scripted attackers with fixed strategies. Each result says what the environment
  catches against that strategy, not how often real attackers use it.
- The harness's servers have no namespace and use the catalog's verbs. Adaptation's effect on
  servers that look different isn't measured here.
- Whether warned LLM agents still single out the honey key without the URL token, and with
  names in the server's vocabulary, is not measured here. That is M13's pre-registered run.
- The operator names were written by us, once. Another operator's names would give other
  numbers.

## Next steps

1. **M13:**
   - screen adapted names for benign trips;
   - re-check whether warned agents flag the honey key in the key layout;
   - rerun the hunt objective against the 42% baseline.

   Needs a ceiling-capped live run, asked first.
2. **Advice for operators:** if you name decoys yourself, include words an attacker hunts for
   (secrets, credentials, keys, vault, admin). `snare decoys -names` takes them.
