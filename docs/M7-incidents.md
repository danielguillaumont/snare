# M7 — Layers, stages and incidents

**Goal:** every touch says how far an attack got, and touches from one hijack read as one
incident. This is the "Snare in depth" model from [DEPTH.md](DEPTH.md) made concrete.
**Budget: $0.** No model calls.

## 1. Layer and stage of a touch

A touch's stage is what it proves about the agent. It depends on what was touched and how,
so it is decided once, when the touch is recorded, and stored with it.

| Touch | Layer | Stage |
|---|---|---|
| A token reported by the gateway in a real tool's arguments (`layer=egress`) | egress | **exfiltration** |
| A token presented as a credential (`Authorization`, `X-Api-Key`, `Api-Key`) | use | **use** |
| A canary instruction obeyed | ingest | **steered** |
| A decoy tool called (decoy server or gateway) | tool | **recon** |
| A honey value or canary doc/link used: base URL fetched, host resolved, link followed | data | **collection** |

Stages are ordered: steered < recon < collection < exfiltration < use. Egress and use
come from how the token arrived, so they override the kind. A honey key pasted into an
email is exfiltration whatever its kind.

The listener passes how the token arrived to the pipeline as a structured value
(`listener.Context`), not only as text in the detail:
- `via=egress` when the callback says `layer=egress` (the gateway);
- `via=use` when the token was in a credential header;
- the gateway's session id.

No other `layer` value is a via, so a callback can't promote a touch to some other stage.

## 2. Incidents

- **Key.** A touch joins an incident by key. With a session id (the gateway) the key is the
  session. Without one it is the source IP, which is today's correlation key.
- **Gap rule.** A touch joins the key's latest incident if it arrives within **1 hour** of
  that incident's previous touch. Otherwise it starts a new one.
  - An attack that touches a trap every 30 minutes for three hours is one incident.
  - The fixed one-hour lookback used until now would have split it.
- **Id.** The incident's id is the id of its first event. It is assigned inside the
  `RecordHit` transaction, so concurrent touches can't split an incident.
- **Scope.** Incidents never span tenants.
- **Older events.** Events recorded before M7 have no incident. Their alerts keep the
  source-IP correlation, so a re-export of an old finding doesn't change.

**Order.** The gateway reports touches asynchronously, so two touches a few milliseconds
apart can arrive in either order. An incident's stages are listed in kill-chain order, and
its timeline in the order the touches arrived.

**DNS caveat.** A DNS touch's source is the agent's resolver, not the agent. DNS touches
group by resolver IP, as they correlated before. Use the gateway's session id when attribution
matters.

## 3. Severity

A touch is **Critical** when any of these holds over its correlated touches, counting those
up to and including this one:

1. two or more distinct tripwires (the pre-M7 rule);
2. two or more distinct stages, i.e. the attack moved through the kill chain;
3. its own stage is exfiltration or use: data left, or a stolen value was used.

Otherwise it is **High**. Severity is computed from events recorded before the touch, so a
retried delivery gets the same answer.

**Correlated touches** are the incident's earlier touches **plus** the same source's touches
in the hour before. That second part is the whole pre-M7 rule, kept as a floor.
- **Why the floor.** The session id arrives in the callback query, so whoever holds a token
  chooses it.
- **What it stops.** Without the floor, a fresh `session=` on each touch would split every
  touch into its own incident. Two tripwires from one source would then raise two High
  alerts where Snare used to raise a Critical one.
- **What it leaves.** A forged session can still split the incident *list*, but never lower
  severity.

DEPTH.md proposed replacing the IP rule with the session; this keeps both, for that reason.

Rule 2 matters on its own when one tripwire is touched at two stages. Example: a honey key
is used as a credential, and later its base URL is fetched. The later touch is only
collection, but the incident has already reached use, so the touch stays Critical.

## 4. Where it shows

- **OCSF.** New `unmapped` fields:
  - `layer`, `stage`, `session_id` and `incident_id`;
  - `correlated_stages` (distinct stages over the correlated touches, in kill-chain order)
    and `correlated_touches`;
  - `critical_because`: why the alert is Critical, in words.

  `correlated_tripwires` and `finding_info.related_events` keep their meaning, over the
  correlated touches of §3. Slack headers use `critical_because` when the alert is Critical
  for a reason other than several tripwires.
- **API.**
  - `GET /api/incidents` lists incidents, most recently active first, each with stages,
    touches, tripwires, first and last seen, and how many touches are still open.
  - `GET /api/incidents/{id}` returns the incident and its touches in time order, each with
    its tripwire's kind and label.
- **CLI.** `snare incidents` lists them; `snare incidents -id N` prints the timeline.
- **Dashboard.**
  - An Incidents page and an incident timeline. The timeline shows each touch with its
    stage, so the page reads as the attack's story: steered, recon, collection,
    exfiltration.
  - The overview gains a Stage column linking each touch to its incident. Its severity
    follows the same rules as the alert.
- **`snare advise`.** With `-manifest`, it reads what has been planted and reports per
  layer whether it is armed, by what, and what to plant to arm it. `-manifest` works with
  or without `-config`.

## Not in M7

- **MITRE ATLAS / ATT&CK technique ids in `finding_info.attacks`.** The mapping has to be
  checked against the current ATLAS release before Snare claims it.
- **Context-layer tripwires (M10).** Until they exist, the context layer always reports
  unarmed.

## Exit criterion

- **Classification.** A table test covers every row of §1, including egress and credential
  header overriding the kind.
- **Grouping.** Store tests cover:
  - session grouping, and IP grouping when there is no session;
  - the gap rule (59 minutes joins, 61 minutes starts a new incident);
  - two sessions from one IP staying apart;
  - tenant separation.
- **Severity.** Alert tests cover each of the three Critical rules and the High case, and a
  rebuilt (retried) alert matches the first.
- **Isolation.** The new store methods and routes are in the tenant-isolation matrices.
- **End to end.** The gateway flow (decoy call, then a honey key emailed out) produces one
  incident with stages `recon, exfiltration`. The egress touch is Critical, and the
  dashboard timeline shows both.

## Results

Built 2026-11-26. No model calls, no API spend. Every item is a test in `go test ./...`.

| Item | Status | Evidence |
|---|---|---|
| Classification | Done | `TestClassify` (every §1 row, both vias, an ignored via); `TestHTTPArrivalContext` |
| Incident grouping | Done | `TestIncidentGroupsBySessionThenIP`, `TestIncidentGapRule` (59 min joins, 61 starts a new one, measured from the previous touch), `TestTwoSessionsFromOneIPStayApart`, `TestIncidentsNeverSpanTenants`, `TestPreM7EventsKeepIPCorrelation` |
| Severity | Done | `TestSeverityRules` (each rule alone, and High), `TestForgedSessionsCannotHideCorrelation`, `TestCorrelationIsStableAcrossRetries`. Mutation check: weakening any one rule fails its own subtest |
| Isolation | Done | `ListIncidents` and `GetIncident` in `TestTenantIsolationMatrix`; both routes in `TestAPITenantIsolationMatrix`; dashboard incident pages in `TestSignInAndTenantScopedPages` |
| API, CLI, dashboard | Done | `TestEndToEndGateway`: decoy call, then the honey key emailed out. Result: one incident `recon, exfiltration`; the exported egress finding is Critical with `critical_because`; the dashboard timeline shows both in order |
| Layer coverage in `advise` | Done | `TestCoverage`, `TestLoadManifest` |

**What this does not show.** Grouping by session needs the gateway. Touches that don't come
through it (a honey key used from another host, a DNS lookup) join an incident only by
source IP, as before M7. Whether the stage labels help an analyst is untested; M13 is the
measured run.
