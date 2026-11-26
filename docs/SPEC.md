# Snare — product spec (v0.1)

## Problem

AI agents read untrusted content (email, tickets, web pages, repos, documents) and hold real
permissions (tools, API keys, data access). Prompt injection can turn an agent against its
owner, and there is no complete preventive fix. Existing defenses are probabilistic
classifiers that produce noise. Security teams have no high-confidence signal that an agent
has been hijacked, or that a credential an agent held has leaked.

## Thesis

Deception gives a binary, low-noise signal: legitimate work never touches a trap. Snare
applies deception to every surface an agent touches and attributes each alert to the agent,
session and input responsible.

## Users

| Segment | Job to be done |
|---|---|
| Security / detection teams at 200–5,000-person tech companies rolling out agents | Know when an agent has been turned, in the SIEM they already use |
| AI platform teams shipping agent products | Continuous, measurable evidence for customers and auditors |
| MSSPs / MDR providers | A multi-tenant AI-security service to sell |
| Individual developers (free tier) | Know if a coding agent leaked their keys |

## Tripwire types

1. **Decoy tools** — tools exposed to an agent that no legitimate task needs.
2. **Canary instructions** — benign, uniquely tagged instructions embedded in data. An agent
   that obeys proves it follows untrusted text, and the tag identifies the source.
3. **Honey credentials** — fake keys and config values planted in repos, env files and
   vector stores; any use calls back to Snare.
4. **Canary documents and links** — classic coverage.

## Core components (target architecture)

| Component | Tech | Notes |
|---|---|---|
| Callback service | Go | HTTPS callbacks + authoritative DNS for the canary domain; signed token IDs; rate limiting |
| Planting CLI / SDK | Go | Plants tripwires in repos, MCP configs, RAG corpora, env files |
| Decoy MCP server | Go | Standalone server that serves decoy tools |
| Decoy safety engine | Python | Simulation harness that scores decoys before deployment (grows out of the kill test) |
| Placement advisor | Go | Scores agents for untrusted input + private data + exfiltration path |
| Alert pipeline | Go | OCSF events; webhook, Sentinel, Splunk, Elastic (M4) and Slack (M4b) sinks; durable outbox, multi-tripwire correlation, Prometheus metrics, tested SIEM rules in `detections/` (M4c) |
| Dashboard | Go, server-rendered (M4) | Tripwire inventory and touch timeline. Changed from Next.js: no JavaScript allows a CSP with no exceptions |

## Key metrics

- **Benign trip rate** (false positives): share of benign agent runs that touch any decoy.
- **Compromise detection rate**: share of hijacked runs in which a tripwire fired.
- **Time to alert**: callback received → alert delivered.

## Non-goals (v1)

- Preventing injection before a tripwire fires (that is gatehouse's job; Snare integrates, not
  replaces). After a touch, Snare may contain the session, opt-in and off by default (M8,
  decided 2026-11-26; see [DEPTH.md](DEPTH.md#decision-containment-is-opt-in)).
- Endpoint agents or kernel-level collection.
- Using real third-party credential formats that could trip other organizations' scanners.
