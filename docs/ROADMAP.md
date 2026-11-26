# Roadmap

Each milestone has an exit criterion. A milestone isn't done until its criterion is met and
the evidence is linked here.

| # | Milestone | Scope | Exit criterion |
|---|---|---|---|
| **M0** ✅ | Kill test | Measure benign trip rate and compromise detection across 3 models | **Done 2026-11-25: GO** after one iteration. [results-m0.md](results-m0.md) |
| **M1** ✅ | Callback core | Go callback service (HTTP + DNS), signed token IDs, alert webhook | **Done 2026-11-25:** touch → verified webhook in ~5 ms (HTTP) / ~4 ms (DNS) in `internal/server/e2e_test.go`. Design: [M1-callback.md](M1-callback.md) |
| **M2** ✅ | Tripwire kit | Decoy MCP server, canary instructions, honey credentials, planting CLI | **Done 2026-11-25:** `snare plant repo/corpus/mcp` on `examples/sample-repo` and `examples/sample-corpus`; honey URL, honey DB host, runbook image and decoy tool call all fire, untouched decoys stay silent (`internal/server/plant_e2e_test.go`). Design: [M2-tripwire-kit.md](M2-tripwire-kit.md) |
| **M3a** ✅ | Proof: detection eval | Own suite: credential-hunting and injected agents vs real + honey secrets ([M3-detection-eval.md](M3-detection-eval.md)) | **Done 2026-11-25: PARTIAL.** 42% of credential-hunting agents caught (46/110, CI 33–51%), 32% immediately; 0/180 benign false trips; a Snare-aware attacker evades 200/200. [results-m3a.md](results-m3a.md) |
| **M3a-fix** ✅ | Anti-fingerprinting | v2 tokens with no fixed prefix, one token per honey field, credential-header detection, generic URL path, per-install decoy names ([M3a-fix-antifingerprint.md](M3a-fix-antifingerprint.md)) | **Done 2026-11-25: 1 of 3 criteria.** `snare_aware` now caught 200/200 (was 0/200). Warned agents' suspicion unchanged (69% vs 75%, CIs overlap). Generated names: 4/120 benign+adjacent trips, above the 5% bar. A code-reading attacker still evades. [results-m3a-fix.md](results-m3a-fix.md) |
| **M3a-fix2** ✅ | Screen generated decoy names | Per-name benign + adjacent screen of all 68 names, retire trippers, held-out re-check ([M3a-fix2-name-screen.md](M3a-fix2-name-screen.md)) | **Done 2026-11-25: PASS.** 1 variant retired; survivors 0/300 on held-out hard-benign tasks (upper bound 1.3%). Generated names stay the default. [results-m3a-fix2.md](results-m3a-fix2.md) |
| **M3b** ✅ | Decoy safety engine | `killtest screen`: lint, generated adjacent/benign tasks, and a live per-decoy screen of a team's own decoys against their agent's tools ([M3b-decoy-screen.md](M3b-decoy-screen.md)) | **Done 2026-11-25: PASS.** Given M0's 20 decoys blind, with generated tasks only, it retired `fetch_internal_wiki` (14/129) and none of the 17 kept decoys. [results-m3b.md](results-m3b.md) |
| **M3c** ✅ | Proof: AgentDojo | Run Snare tripwires inside AgentDojo suites (external benchmark, other objective families) ([M3c-agentdojo.md](M3c-agentdojo.md)) | **Done 2026-11-25: published.** Decoys are safe on an external benchmark: 0/291 benign trips, −3.4 points utility. No detection evidence: the only successful injection used no tools. [results-m3c.md](results-m3c.md) |
| **M4** 🟡 | SaaS | Multi-tenant dashboard, OCSF export, Sentinel/Splunk/Elastic sinks ([M4-saas.md](M4-saas.md)) | Tenant-isolation tests pass; deployed with IaC. **2026-11-25: built, isolation tests pass, smoke test passes in CI. IaC written, not yet applied** (needs the owner's AWS account). |
| **M4b** ✅ | Hardening + advisor | Supply chain (govulncheck, CodeQL, SBOM, signing), fuzzing, hash-chained audit log, placement advisor (`snare advise`), Slack sink ([M4b-hardening.md](M4b-hardening.md)) | **Done 2026-11-26.** govulncheck found and we fixed one reachable stdlib issue. 3 fuzz targets ran 2 min each, no failures. Audit, advisor and Slack exits are covered by tests. No API spend. |
| **M4c** ✅ | Reliability + detection content | Durable delivery outbox, Prometheus metrics, multi-tripwire correlation, tested SIEM detection rules, signing-key rotation ([M4c-reliability.md](M4c-reliability.md)) | Alerts survive restarts and sink outages; one dead sink delays no one else; rule fields checked against real alerts in CI; old-key tokens still alert after rotation. **Done 2026-11-26.** All five exit criteria are met by tests ([results](M4c-reliability.md#results)). The SIEM rules are field-checked but not run inside the products. No API spend. |
| **M4d** ✅ | Operator view, data at rest, capacity | Dashboard severity and delivery health, token labels sealed at rest, measured single-node capacity ([M4d-operations.md](M4d-operations.md)) | Critical touches and undelivered alerts visible per tenant; no label plaintext in the database file; a reproducible capacity table. **Done 2026-11-26.** Benchmarks found two ways an unauthenticated sender could degrade the callback; both were fixed and re-measured ([results-bench.md](results-bench.md)). No API spend. |
| **M4e** ✅ | Tripwire lifecycle, triage, first run | Disable and re-enable a tripwire (audited, touches still recorded), triage states with OCSF status mapping, a cross-platform `snare demo` ([M4e-lifecycle.md](M4e-lifecycle.md)) | A muted touch never alerts; triage is visible in export and dashboard; the demo runs from one command on any OS. **Done 2026-11-26.** Evidence in [M4e results](M4e-lifecycle.md#results). No API spend. |
| **M4f** ✅ | Distribution, retention, integration | Signed release binaries for six targets, opt-in event retention that never deletes untriaged touches, a guide to wiring Snare into MCP clients and SIEMs ([M4f-distribution.md](M4f-distribution.md)) | A team installs without Go, can bound database growth, and can check a tripwire is live without paging anyone. **Done 2026-11-26.** Evidence in [M4f results](M4f-distribution.md#results). No API spend. |
| M5 ⏸ | Design partners | 3–5 teams running Snare on real agents | Written feedback + at least one recurring user. **Parked until Daniel picks it up.** |

### Next: Snare in depth (M6–M14)

Proposed 2026-11-26. The reasoning, the layer model and the risks are in [DEPTH.md](DEPTH.md).
Each row gets its own design doc before code.

| # | Milestone | Scope | Exit criterion |
|---|---|---|---|
| M6 | Snare Gateway | MCP proxy in front of real servers: decoys injected into real tool lists, session ids on every touch, honey values detected in tool arguments | Forwards every message unchanged, tested end to end against a real MCP server; forwarding overhead measured and published |
| M7 | Layers, stages, incidents | Every tripwire has a layer (ingest, context, tool, data, egress, use) and a kill-chain stage; touches grouped into incidents by session; severity = deepest stage | Incidents in OCSF and as a dashboard timeline; `advise` reports layer coverage |
| M8 | Containment (opt-in) | Gateway freezes a session's tool calls after a touch; audited release | Frozen within one call; forwarding unaffected when Snare's side is down. Opt-in, off by default (decided 2026-11-26, [DEPTH.md](DEPTH.md#decision-containment-is-opt-in)) |
| M9 | Provenance and attribution | Per-session ledger of untrusted inputs (hashes, not content); per-source markers | A poisoned document is named in the alert as the last untrusted input before the touch |
| M10 | Context-layer tripwires | Prompt canaries and memory / vector-store canaries | A leaked system prompt or recalled memory canary is a touch |
| M11 | Heartbeat | Scheduled synthetic touches per channel, marked as tests | "Verified N min ago" per channel; a stale metric when a path breaks |
| M12 | Adaptive deception | Decoys and honey layouts generated from the agent's own tools and repo | A scripted attacker that reads Snare's source is re-run and published ($0) |
| M13 | Proof: Snare in depth | Pre-registered rerun of M3a's hunt objective with all layers; benign and utility re-check | Published against the 42% baseline. **≤ $8 under `--max-usd`, asked before running** |
| M14 | First run, end to end | `snare init` (find configs, plan layers, wrap servers, liveness check, coverage score); `snare demo --attack` incident replay | One command from install to a verified, layered deployment |

## M0 detail

1. Harness with scripted fake model, fully tested offline.
2. Pilot: 60 benign runs on `claude-haiku-5-5` (cost ≈ cents) to sanity-check prompts.
3. Full run per `docs/killtest.md`.
4. Write-up: results, what surprised us, decoys renamed or dropped.
