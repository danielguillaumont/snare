# Snare

[![ci](https://github.com/danielguillaumont/snare/actions/workflows/ci.yml/badge.svg)](https://github.com/danielguillaumont/snare/actions/workflows/ci.yml)

**Tripwires for AI agents.** Snare plants decoy tools, canary instructions and honey
credentials across everything your agents touch. Legitimate work never touches a trap, so
when one fires you get a high-confidence alert that names the agent, the session and the
input that turned it.

> Status: **M0 kill test passed (GO).** Across Haiku, Sonnet and Opus, benign agents touched
> a decoy in 0 of 600 normal runs (95% CI 0–0.6%) and 2 of 232 runs on tasks deliberately
> close to a decoy's purpose (0.9%, CI 0.2–3.1%), after retiring 3 decoys that failed the
> first run. The detection side (catching hijacked agents) is not yet measured.
> Details, limitations and evidence: [docs/results-m0.md](docs/results-m0.md).
>
> **M3a detection eval: PARTIAL.** Tripwires caught 42% of credential-hunting agents (46/110,
> 95% CI 33–51%; 32% immediately) with 0/180 benign false trips. An attacker who knows Snare's
> public decoy names and token format evaded all 200 scripted runs, so that's the next fix.
> Measured on an authorized-audit proxy, not real hijacks: [docs/results-m3a.md](docs/results-m3a.md).
>
> **M3a-fix anti-fingerprinting: 1 of 3 criteria met.** Tokens no longer have a fixed prefix,
> each honey field gets its own token, and decoys can take per-install names. The scripted
> attacker that evaded 200/200 is now caught 200/200. Warned agents still flag the honey key
> about as often (69% vs 75%), generated names need screening (4/120 hard-benign trips), and an
> attacker who reads this code still evades unless you set your own names:
> [docs/results-m3a-fix.md](docs/results-m3a-fix.md).
>
> **M3a-fix2: generated decoy names screened, PASS.** Each of the 68 names was screened on hard
> benign tasks. One variant was retired, and the survivors tripped 0/300 runs on a held-out task
> set (upper bound 1.3%): [docs/results-m3a-fix2.md](docs/results-m3a-fix2.md).
>
> **M3b decoy safety screen: PASS.** `killtest screen` checks a team's own decoys against
> their agent's tools before deployment. We gave it M0's 20 decoys blind, with model-written
> tasks only. It retired the decoy M0 had retired by hand (`fetch_internal_wiki`, 14/129
> adjacent exposures) and kept all 17 that M0 kept (800 runs, $4.02):
> [docs/results-m3b.md](docs/results-m3b.md).
>
> **M1 callback server and M2 tripwire kit are built** and covered by end-to-end tests
> (plant → touch → signed alert). Not yet deployed as a hosted service.

## Why

- Prompt injection has no complete fix. Agents still read untrusted email, tickets, pages and code.
- Classifier-style defenses guess and produce noise.
- A hijacked agent uses its own legitimate permissions, so normal logs see nothing unusual.

Snare does not try to prevent injection. It **detects** it with a binary signal: a trap was
touched, or it wasn't.

## Repository layout

| Path | What it is |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | Product spec: problem, users, components, non-goals |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Milestones M0–M5 and their exit criteria |
| [docs/killtest.md](docs/killtest.md) | Pre-registered protocol and go / iterate / kill thresholds |
| [experiments/killtest/](experiments/killtest/) | The kill-test harness (Python, Claude API) |
| [cmd/snare](cmd/snare), [internal/](internal/) | Go CLI and services: callback server (M1), decoy MCP server and planting (M2) |
| [examples/](examples/) | Sample repo and RAG corpus used as planting targets in tests |
| [CLAUDE.md](CLAUDE.md) | Working rules for Claude Code in this repo |

## Running the kill test

```powershell
cd experiments/killtest
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest
.venv\Scripts\python -m killtest run --dry-run --arm all --runs 40     # offline fake model, $0
.venv\Scripts\python -m killtest run --arm benign --runs 60 --models claude-haiku-5-5 --max-usd 1   # pilot, ~$0.09
.venv\Scripts\python -m killtest report results/latest
.venv\Scripts\python -m killtest run --dry-run --arm m3 --runs 40          # M3a arms, offline
.venv\Scripts\python -m killtest run --policy all --arm hunt --runs 200    # scripted attackers, $0
```

Live runs need Anthropic API credentials (`ANTHROPIC_API_KEY`, or `ant auth login`).
Every live run has a hard `--max-usd` ceiling.

## Running the callback server (M1)

```powershell
go build -o bin/snare.exe ./cmd/snare
bin\snare.exe keygen                       # prints SNARE_KEY, SNARE_ADMIN_KEY, SNARE_WEBHOOK_SECRET
# set those plus SNARE_ZONE / SNARE_DNS_ADDR / SNARE_WEBHOOK_URL as needed (see docs/M1-callback.md)
bin\snare.exe serve
bin\snare.exe mint -kind honey_credential -label "payments-api .env: OPENAI_API_KEY"
bin\snare.exe events
go test ./...                               # includes the M1 (< 5 s alert) and M2 (plant → fire) end-to-end tests
```

## Planting tripwires (M2)

With `snare serve` running (and `SNARE_PUBLIC_URL`, optionally `SNARE_ZONE`, set):

```powershell
bin\snare.exe plant repo   -dry-run path\to\repo        # preview; mints and writes nothing
bin\snare.exe plant repo   path\to\repo                 # .env.legacy with honey base URL, key, DB host
bin\snare.exe plant corpus path\to\kb-folder            # break-glass runbook with honey link, image, creds
bin\snare.exe plant mcp    -config decoy-mcp.json -exclude list_api_keys   # 16 screened decoy tools
bin\snare.exe decoy-mcp    -config decoy-mcp.json         # stdio MCP server (plant mcp prints the client snippet)
```

Before planting decoy tools, screen them against your own agent's tools with
`killtest screen` (see [docs/M2-tripwire-kit.md](docs/M2-tripwire-kit.md#screening-decoys-against-your-own-agent-m3b)).

Each tripwire gets its own token, so an alert names the exact file or tool. Planting never
overwrites files, and the manifest (`snare-planted.json`) must live outside the planted
directory. Design and rules: [docs/M2-tripwire-kit.md](docs/M2-tripwire-kit.md).

## License

[Apache-2.0](LICENSE).
