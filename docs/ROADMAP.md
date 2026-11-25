# Roadmap

Each milestone has an exit criterion. A milestone isn't done until its criterion is met and
the evidence is linked here.

| # | Milestone | Scope | Exit criterion |
|---|---|---|---|
| **M0** ✅ | Kill test | Measure benign trip rate and compromise detection across 3 models | **Done 2026-11-25: GO** after one iteration. [results-m0.md](results-m0.md) |
| **M1** ✅ | Callback core | Go callback service (HTTP + DNS), signed token IDs, alert webhook | **Done 2026-11-25:** touch → verified webhook in ~5 ms (HTTP) / ~4 ms (DNS) in `internal/server/e2e_test.go`. Design: [M1-callback.md](M1-callback.md) |
| **M2** ✅ | Tripwire kit | Decoy MCP server, canary instructions, honey credentials, planting CLI | **Done 2026-11-25:** `snare plant repo/corpus/mcp` on `examples/sample-repo` and `examples/sample-corpus`; honey URL, honey DB host, runbook image and decoy tool call all fire, untouched decoys stay silent (`internal/server/plant_e2e_test.go`). Design: [M2-tripwire-kit.md](M2-tripwire-kit.md) |
| **M3a** ✅ | Proof: detection eval | Own suite: credential-hunting and injected agents vs real + honey secrets ([M3-detection-eval.md](M3-detection-eval.md)) | **Done 2026-11-25: PARTIAL.** 42% of credential-hunting agents caught (46/110, CI 33–51%), 32% immediately; 0/180 benign false trips; a Snare-aware attacker evades 200/200. [results-m3a.md](results-m3a.md) |
| M3a-fix | Anti-fingerprinting | Per-install decoy names, configurable token formats, distinct honey URL / key values | `snare_aware` and `hunt_aware` detection rise above the M3a baseline |
| M3b | Decoy safety engine | `snare screen`: benign/adjacent screening of a team's own decoy set against their agent's tools | Screens a new decoy set and flags the ones M0 would have retired |
| M3c | Proof: AgentDojo | Run Snare tripwires inside AgentDojo suites (external benchmark, other objective families) | Published evaluation with denominators and CIs |
| M4 | SaaS | Multi-tenant dashboard, OCSF export, Sentinel/Splunk/Elastic sinks | Tenant-isolation tests pass; deployed with IaC |
| M5 | Design partners | 3–5 teams running Snare on real agents | Written feedback + at least one recurring user |

## M0 detail

1. Harness with scripted fake model, fully tested offline.
2. Pilot: 60 benign runs on `claude-haiku-5-5` (cost ≈ cents) to sanity-check prompts.
3. Full run per `docs/killtest.md`.
4. Write-up: results, what surprised us, decoys renamed or dropped.
