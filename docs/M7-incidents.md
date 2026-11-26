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

The listener passes the context (gateway layer, tool, session, credential header) to the
pipeline as structured values, not only as text in the detail.

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

**DNS caveat.** A DNS touch's source is the agent's resolver, not the agent. DNS touches
group by resolver IP, as they correlated before. Use the gateway's session id when attribution
matters.

## 3. Severity

A touch is **Critical** when any of these holds within its incident, counting touches up to
and including this one:

1. two or more distinct tripwires (today's rule, now per incident);
2. two or more distinct stages, i.e. the attack moved through the kill chain;
3. its own stage is exfiltration or use: data left, or a stolen value was used.

Otherwise it is **High**. Severity never goes down, and it is computed from events recorded
before the touch, so a retried delivery gets the same answer.

## 4. Where it shows

- **OCSF.** New `unmapped` fields: `layer`, `stage`, `session_id`, `incident_id`,
  `incident_stages` (distinct stages so far, in kill-chain order) and `incident_touches`.
  - `finding_info.related_events` lists the incident's other tripwires.
  - `correlated_tripwires` keeps its meaning, now counted per incident.
- **API.** `GET /api/incidents` (newest first, with stages, touches, tripwires, first and
  last seen, and whether any touch is still open). `GET /api/incidents/{id}` returns the
  incident and its touches in time order.
- **CLI.** `snare incidents` lists them; `snare incidents -id N` prints the timeline.
- **Dashboard.** An Incidents page and an incident timeline. The timeline shows each touch
  with its stage, so the page reads as the attack's story: steered, recon, collection,
  exfiltration.
- **`snare advise`.** With `-manifest`, it reads what has been planted and reports per
  layer whether it is armed, by what, and what to plant to arm it.

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

| Item | Status | Evidence |
|---|---|---|
| Classification | Not started | |
| Incident grouping | Not started | |
| Severity | Not started | |
| API, CLI, dashboard | Not started | |
| Layer coverage in `advise` | Not started | |
