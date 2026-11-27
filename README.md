# Snare

[![ci](https://github.com/danielguillaumont/snare/actions/workflows/ci.yml/badge.svg)](https://github.com/danielguillaumont/snare/actions/workflows/ci.yml)

**Tripwires for AI agents.** Snare plants decoy tools, canary documents and honey
credentials where your agents work. Legitimate tasks have no reason to touch them. When a
prompt-injected agent does, you get a high-confidence alert that names the exact tripwire,
in your SIEM's format.

![Snare dashboard: three tripwires, one touched by an agent following a canary link](docs/img/dashboard.png)

## Why

- Prompt injection has no complete fix. Agents still read untrusted email, tickets, pages and code.
- A hijacked agent uses its own legitimate permissions, so ordinary logs see nothing unusual.
- Classifier-style defenses guess, and produce noise.

Snare doesn't try to prevent injection. It **detects** it with a binary signal: a trap was
touched, or it wasn't. A binary signal can be measured, so that's what this project does
before making claims.

## How it works

1. **Plant.**
   - `snare plant` writes honey credentials and canary docs into repos and RAG corpora.
   - `snare decoy-mcp` serves decoy tools beside the real ones, or `snare gateway` wraps a
     real MCP server and slips decoys into its own tool list. The gateway also catches a
     honey value being sent out through any real tool.
   - Every tripwire gets its own unprefixed, HMAC-signed token.
2. **Touch.** A steered agent calls a decoy, uses a honey key, follows a canary link, or
   resolves a canary hostname. Snare's HTTP and authoritative-DNS listeners verify the MAC
   before doing anything else. The toucher gets a bland reply.
3. **Alert.** The hit becomes an OCSF 1.3 Detection Finding. It is routed to a signed webhook,
   Splunk, Elastic or Microsoft Sentinel, and shown on a multi-tenant dashboard, where admins triage touches and disable tripwires.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). What it defends against, and what it
doesn't: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Wiring it into Claude Desktop,
Claude Code, other MCP clients and your SIEM: [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## What's measured

Every number below comes from a results directory linked beside it, with denominators and
95% CIs. Thresholds were pre-registered in [docs/killtest.md](docs/killtest.md). Models: Claude
Haiku, Sonnet and Opus.

| Question | Result | Source |
|---|---|---|
| Do benign agents touch decoys? | **0/600** normal runs (CI 0–0.6%); **2/232** on tasks built to sit next to a decoy's purpose (0.9%, CI 0.2–3.1%), after retiring 3 decoys | [M0](docs/results-m0.md) |
| Can a team screen its own decoys before deploying? | `killtest screen` blindly retired the one decoy M0 had retired by hand, and kept all 17 that M0 kept (800 runs) | [M3b](docs/results-m3b.md) |
| Are generated per-install decoy names safe? | **0/300** trips on held-out hard-benign tasks (upper bound 1.3%) | [M3a-fix2](docs/results-m3a-fix2.md) |
| Safe on an external benchmark? | AgentDojo, unmodified: **0/291** benign trips, utility **−3.4 points** (pre-registered limit −5) | [M3c](docs/results-m3c.md) |
| Do tripwires catch hijacked agents? | About one in three credential-hunting agents, by what Snare can actually see: **92/267** (34.5%, CI 29–40%) with every layer and all 17 decoys in the tool list. That is no better than the single layer (M3a: 46/110 = 42% counting honey quoted in replies; 36% by the same measure). 0/180 benign trips. Measured on an authorized-audit proxy, not real hijacks | [M13](docs/results-m13.md), [M3a](docs/results-m3a.md) |
| Can an attacker who knows Snare evade it? | Scripted evader: 200/200 evaded → **200/200 caught** after anti-fingerprinting. An attacker who reads this repo still evades generated names, including names adapted to the server (0/200 caught). Under operator-chosen names it is caught as often as one who knows nothing: 138/200 vs 143/200 | [M3a-fix](docs/results-m3a-fix.md), [M12](docs/results-m12.md) |

## Limitations

- **Recall is partial and only measured on a proxy.** On AgentDojo, no tool-using injection
  succeeded, so that benchmark gives no detection evidence either way.
- **Agents warned about honeypots still avoid honey keys** about as often (69% vs 75%).
- **Answer-only injections are invisible.** If the injection never makes the agent touch
  anything, there is nothing to trip.
- **The hosted service is built and its IaC is validated in CI, but it has never been
  deployed.** It runs as one node on SQLite.
- **No external security review yet.**

## Where should tripwires go?

`snare advise` reads an agent's MCP config and checks whether the agent has all three of
untrusted input, private data and a way to send data out. That combination is where an
injection does damage. It never connects to anything:

```text
$ snare advise -config examples/agent-configs/support-agent.json
  untrusted input: fetch, gmail, zendesk
  private data:    customer-db, files, zendesk
  way out:         fetch, gmail

Risk: HIGH (all three: an injection here can reach data and send it out)

Recommendations:
2. ... Add the decoy MCP server. Screen the decoy names against this agent's real tools ...
   $ snare plant mcp -config decoy-mcp.json
4. files exposes /srv/support/shared-docs to the agent. Plant honey credentials there. ...
   $ snare plant repo /srv/support/shared-docs
```

## Try it in two minutes

Needs only Go. Everything runs locally and no model is called.

```bash
go run ./cmd/snare demo     # starts Snare, plants 3 tripwires, sets two off, prints a dashboard key
# open http://127.0.0.1:18090 and sign in with the printed key
go test ./...               # includes end-to-end tests: plant -> touch -> alert, two-tenant isolation
```

In the demo, a simulated agent follows a canary link and then uses a honey API key. Two
tripwires from one source make the second touch **Critical**. From another terminal,
`snare events` lists the touches and `snare triage` records what each turned out to be.

**Without Go.** From v0.7.0, each [release](https://github.com/danielguillaumont/snare/releases)
attaches static `snare` binaries for Linux, macOS and Windows (amd64 and arm64), with a
`SHA256SUMS` file signed by the release workflow. Verify before running:

```bash
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/danielguillaumont/snare/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

## Status

| Milestone | State |
|---|---|
| M0 kill test: are decoys safe at all? | ✅ GO |
| M1 callback server (HTTP + DNS, signed alerts) | ✅ Built, alert end to end in < 5 s (tested) |
| M2 tripwire kit (planting, decoy MCP server) | ✅ Built |
| M3a/b/c detection eval, anti-fingerprinting, decoy screen, AgentDojo | ✅ Published, including the partial results |
| M4 multi-tenant service, OCSF/SIEM sinks, dashboard, IaC | 🟡 Built and tested; IaC not yet applied |
| M4b hardening: supply chain, fuzzing, audit log, placement advisor, Slack | ✅ Built |
| M4c reliability: durable alert outbox, metrics, correlation, SIEM rules, key rotation | ✅ Built |
| M4d operations: dashboard severity, labels sealed at rest, measured capacity | ✅ Built |
| M4e lifecycle: disable tripwires, triage touches, one-command demo | ✅ Built |
| M4f distribution: signed release binaries, event retention, integration guide | ✅ Built |
| M6 gateway: decoys inside real MCP servers, egress detection, session ids | ✅ Built, about 29 µs per call ([results](docs/M6-gateway.md#results)) |
| M7 layers, stages and incidents: kill-chain severity, incident timeline, layer coverage | ✅ Built ([results](docs/M7-incidents.md#results)) |
| M8 containment (opt-in): the leaking call is blocked, the session frozen, release audited | ✅ Built ([results](docs/M8-containment.md#results)) |
| M9 provenance: the alert says what the agent read just before it touched a trap | ✅ Built ([results](docs/M9-provenance.md#results)) |
| M10 context canaries: a leaked system prompt or acted-on memory is a touch | ✅ Built ([results](docs/M10-context-canaries.md#results)) |
| M11 heartbeat: each path (HTTP, DNS, gateway) shows when it was last verified, and goes stale when it breaks | ✅ Built ([results](docs/M11-heartbeat.md#results)) |
| M12 adaptive deception: decoy names in the real server's vocabulary, a tokenless honey URL, and a code-reading attacker re-run | ✅ Published, 1 of 2 criteria met ([results](docs/results-m12.md)) |
| M13 proof in depth: pre-registered rerun with every layer | ❌ Published: detection not improved (34.5% vs a 51.2% bar), 0/180 benign trips ([results](docs/results-m13.md)) |
| M13b smaller default decoy set: pre-registered screen | ❌ Published: declines 24% vs 33% but missed the bar (CI upper 30.4% vs < 28.8%); detection 40%, 0/180 benign trips. Default stays all 17; `-profile credentials` ships as an option ([results](docs/results-m13b.md)) |
| M15 detection where harm happens: pre-registered | ⏹ Stopped at the pilot stage: 0/40 harmful runs. Haiku wouldn't send credentials, so there was nothing to measure ([results](docs/results-m15.md)) |
| M14 first run, end to end | Planned ([docs/DEPTH.md](docs/DEPTH.md)) |
| M5 design partners | Not started |

Full plan and exit criteria: [docs/ROADMAP.md](docs/ROADMAP.md).

## Repository layout

| Path | What it is |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | Product spec: problem, users, components, non-goals |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | How the pieces fit; what Snare defends against and what it doesn't |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Milestones M0–M5 and their exit criteria |
| [docs/killtest.md](docs/killtest.md) | Pre-registered protocol and go / iterate / kill thresholds |
| [experiments/killtest/](experiments/killtest/) | The kill-test harness (Python, Claude API) |
| [cmd/snare](cmd/snare), [internal/](internal/) | Go CLI and services: callback server (M1), decoy MCP server and planting (M2), tenancy, sinks and dashboard (M4) |
| [detections/](detections/) | Splunk, Sentinel, Elastic and Sigma rules for Snare findings, checked in CI |
| [bench/](bench/) | Raw benchmark and load-test output behind [docs/results-bench.md](docs/results-bench.md) |
| [deploy/](deploy/), [Dockerfile](Dockerfile), [scripts/](scripts/) | M4: Terraform for AWS, Caddy config, secrets bootstrap and the post-deploy smoke test |
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
pip install -e ".[agentdojo]"                                              # M3c only
.venv\Scripts\python -m killtest dojo --dry-run --out results\dojo-dry     # AgentDojo suites, offline
```

Live runs need Anthropic API credentials (`ANTHROPIC_API_KEY`, or `ant auth login`).
Every live run has a hard `--max-usd` ceiling.

## Running the callback server (M1)

```powershell
go build -o bin/snare.exe ./cmd/snare
bin\snare.exe keygen                       # prints SNARE_KEY, SNARE_ADMIN_KEY, SNARE_WEBHOOK_SECRET, SNARE_SEAL_KEY
# set those plus SNARE_ZONE / SNARE_DNS_ADDR / SNARE_WEBHOOK_URL as needed (see docs/M1-callback.md)
bin\snare.exe serve
bin\snare.exe mint -kind honey_credential -label "payments-api .env: OPENAI_API_KEY"
bin\snare.exe events
go test ./...                               # includes the M1 (< 5 s alert) and M2 (plant → fire) end-to-end tests
```

## Tenants, sinks and the dashboard (M4)

With `SNARE_SEAL_KEY` and `SNARE_DASHBOARD_ADDR` set, the same binary serves several tenants.
The operator key manages tenants. Each tenant gets its own API keys and sees only its own
tokens, events and sinks.

```powershell
bin\snare.exe tenant create -name "Acme"                # prints the tenant id
bin\snare.exe tenant key -tenant tn_... -role admin     # prints a tenant key once; only its hash is stored
$env:SNARE_ADMIN_KEY = "snk_..."; bin\snare.exe mint -kind canary_url -label "runbook link"   # as the tenant
```

A tenant adds its own SIEM or chat with `POST /api/sinks` (`splunk_hec`, `elastic`, `sentinel`,
`slack` or `webhook`), and `GET /api/events/export` streams its findings as OCSF NDJSON. Deployment is in
[deploy/README.md](deploy/README.md).

**Alerts don't get lost.**
- Each alert is queued in a durable outbox in the same transaction as the event.
- Each destination retries for about 3 hours, and queued alerts survive restarts.
- A delivery that gives up is kept and counted. `snare deliveries -state dead` lists them,
  and `-retry ID` requeues one.
- `GET /metrics` (operator key) exports Prometheus metrics. Alert rules are in
  [deploy/prometheus](deploy/prometheus/snare-rules.yml).
- Each touch is labelled with the kill-chain stage it proves: steered, recon, collection,
  exfiltration or use. Touches from one gateway session (or one source) form an
  **incident**; `snare incidents -id N` and the dashboard show it as a timeline.
- An alert is **Critical** when the incident or source has touched two or more tripwires
  or stages, or when the touch is itself exfiltration or use. It lists the others
  ([docs/M7-incidents.md](docs/M7-incidents.md)).
- Ready-made rules for Splunk, Sentinel, Elastic and Sigma are in [detections/](detections/).
  CI checks them against the fields Snare emits. Design and evidence:
  [docs/M4c-reliability.md](docs/M4c-reliability.md).

## Planting tripwires (M2)

With `snare serve` running (and `SNARE_PUBLIC_URL`, optionally `SNARE_ZONE`, set):

```powershell
bin\snare.exe plant repo   -dry-run path\to\repo        # preview; mints and writes nothing
bin\snare.exe plant repo   path\to\repo                 # .env.legacy with honey base URL, key, DB host
bin\snare.exe plant repo   -layout key -adapt path\to\repo  # tokenless URL; follows the repo's .env style
bin\snare.exe plant corpus path\to\kb-folder            # break-glass runbook with honey link, image, creds
bin\snare.exe plant mcp    -config decoy-mcp.json -exclude list_api_keys   # 16 screened decoy tools
bin\snare.exe decoy-mcp    -config decoy-mcp.json         # stdio MCP server (plant mcp prints the client snippet)
bin\snare.exe plant gateway -config gw.json               # decoys inside a real server, styled like its tools
bin\snare.exe gateway -config gw.json -- npx some-mcp-server   # wrap it; honey values in tool arguments alert too
```

Before planting decoy tools, screen them against your own agent's tools with
`killtest screen` (see [docs/M2-tripwire-kit.md](docs/M2-tripwire-kit.md#screening-decoys-against-your-own-agent-m3b)).

Each tripwire gets its own token, so an alert names the exact file or tool. Planting never
overwrites files, and the manifest (`snare-planted.json`) must live outside the planted
directory. Design and rules: [docs/M2-tripwire-kit.md](docs/M2-tripwire-kit.md).

## License

[Apache-2.0](LICENSE).
