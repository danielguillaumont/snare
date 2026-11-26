# M4c — Alert reliability, observability and detection content

**Goal:** make sure a touched tripwire always reaches a person, and that the people running
Snare can see when it doesn't. Snare's whole value is one high-confidence signal. An alert
that silently disappears is the worst failure it can have, worse than a false positive.
**Budget: $0.** No model calls, no cloud resources.

## Gaps this closes

| Gap (as of v0.5.0) | Consequence |
|---|---|
| Deliveries live in an in-memory queue with 3 retries over about 1 s | A restart, a full queue, or a SIEM outage longer than a second loses the alert. The event is stored, but nobody is told. |
| No metrics | An operator can't alert on "deliveries are failing" or "nothing has been delivered for a day". |
| Each touch is its own alert | An agent that touches three tripwires in a minute produces three unrelated High alerts. That pattern is the strongest signal Snare has, and it isn't surfaced. |
| SIEM sinks ship data but no detections | Every customer writes the same rule by hand, and the rule can drift from the field names Snare emits. |
| One signing key, no rotation | Rotating `SNARE_KEY` invalidates every planted tripwire. In practice the key is never rotated. |

## 1. Durable delivery outbox

- **Same transaction.** When a hit is not suppressed by dedup, `RecordHit` writes the event
  and a fan-out marker in one transaction. A stored, alertable event without a pending
  delivery can't commit.
- **Fan-out.** A worker expands each marker into one `deliveries` row per destination. That
  is every operator sink (`op:log`, `op:webhook`) plus the tenant's own sinks (by sink id).
  The marker is deleted in the same transaction. Sinks are resolved when the marker is
  expanded, so a sink added a second after a touch doesn't receive it.
- **Delivery.** The alert is rebuilt from the stored event and token at send time. It is
  deterministic, so a retry sends the same body with the same `finding_info.uid`.
- **Retries.** Exponential backoff from 2 s, doubling, capped at 15 min, with ±20% jitter.
  After 20 attempts (about 2.8 h of retrying) the row is `dead`. Dead rows stay visible and can be
  retried by hand.
- **A dead SIEM can't starve the others.** Each attempt has a 10 s timeout. At most 2
  attempts per destination run at once, out of 8 workers. Each row has its own schedule.
- **Semantics: at least once.** A crash between a successful send and the status update
  resends it on restart. Receivers dedupe on `finding_info.uid`, which is stable. This is
  documented for each sink.
- **Bounded.** When more than 100,000 deliveries are pending, new events are still stored,
  but no delivery is queued. A counter is incremented and an error is logged. A flood of
  touches can't grow the database without bound.
- **Retention.** Delivered rows are purged after 7 days. Dead rows are kept until retried or
  purged by the operator.
- **Visibility.**
  - `GET /api/deliveries`: tenant-scoped, through `TenantStore`, so the isolation matrix
    covers it.
  - `POST /api/deliveries/{id}/retry`: tenant admin.
  - `GET /api/operator/deliveries`.
  - `snare deliveries [-state dead] [-retry ID]`.

**Exit:**
- A sink that fails for longer than the old retry window still receives the alert once it
  recovers.
- Alerts queued before a restart are delivered after it.
- A sink that is down doesn't delay another tenant's delivery.
- A tenant can't see or retry another tenant's deliveries.

## 2. Metrics

`GET /metrics` on the admin listener, in the Prometheus text format, behind the operator key
(`authorization: Bearer`). Written by hand (about 150 lines) rather than taking a dependency.
Label values come from fixed sets, so cardinality is bounded.

| Metric | Type | Labels |
|---|---|---|
| `snare_hits_total` | counter | `channel` |
| `snare_alerts_suppressed_total` | counter | — (dedup) |
| `snare_alerts_shed_total` | counter | — (outbox full) |
| `snare_deliveries_total` | counter | `sink` (type), `result` (`ok`, `retry`, `dead`) |
| `snare_delivery_latency_seconds` | histogram | — (touch to delivered) |
| `snare_deliveries_pending`, `snare_deliveries_dead` | gauge | — |
| `snare_oldest_pending_delivery_seconds` | gauge | — |

The deploy runbook ships three alert rules: dead deliveries above zero, oldest pending
delivery above 15 min, and no scrape.

**Exit:** the output parses as the Prometheus text format, and the values match a scripted
run.

## 3. Correlation and severity

When an alert is built, Snare counts the distinct tripwires the same source touched in the
same tenant during the previous hour.

- If two or more tripwires were touched, the alert is **Critical** (`severity_id` 5) instead
  of High (4).
- `unmapped.correlated_tripwires` and `unmapped.correlation_window` carry the count and the
  window.
- `finding_info.related_events` lists the other touches (up to 10), using OCSF's own
  attribute.

**Why source IP:** it is the only identity every channel has. It's weak behind NAT or a
shared resolver, so correlation only raises severity and never suppresses an alert. A DNS
touch comes from the agent's resolver, not the agent, so DNS and HTTP touches from the same
agent may not correlate. This is documented as a limitation.

**Exit:**
- Touching two different tripwires from one source makes the second alert Critical.
- The same tripwire touched twice does not.
- Another tenant's touches from the same IP never count.

## 4. Detection content (`detections/`)

Rules shipped for each supported SIEM, checked against what Snare actually emits:

- **Splunk:** SPL saved searches.
- **Microsoft Sentinel:** KQL analytics rules.
- **Elastic:** a rule in the detection-rule export format.
- **Sigma:** rules over the OCSF fields.

Each covers two detections:

1. **Any tripwire touched.**
2. **Several tripwires touched by one source** (Critical).

A Go test extracts every field path each rule uses, builds a real correlated alert, and fails
if a path doesn't exist in the shape that SIEM receives. Renaming a field in `internal/alert`
without updating the rules breaks CI.

**Exit:** every rule's fields exist in a real alert, and the test fails when one is broken
deliberately.

## 5. Signing-key rotation

- `SNARE_KEY` signs new tokens.
- `SNARE_KEY_PREVIOUS` (comma-separated, at most 3) still verifies old ones.
- A hit verified by a previous key is recorded normally and marked
  `unmapped.verified_by_previous_key`, so teams can find tripwires that still need replanting.
- The scanner's MAC-attempt cap is shared across keys, so junk traffic costs no more with
  extra keys.
- Dashboard sessions use a key derived from the current key only, so rotation signs everyone
  out.

**Exit:**
- A token minted under the old key still alerts after rotation.
- A token under a key that isn't configured is rejected.
- The per-input attempt cap holds with 4 keys.

## Results

| § | Status | Evidence |
|---|---|---|
| 1. Outbox | ✅ Built | `internal/store/outbox_test.go`: marker in the same transaction as the event, shedding at the cap, idempotent fan-out, retry schedule, audited manual retry, tenants never see the operator's deliveries. `internal/alert/outbox_test.go`: a sink failing 7 times still receives the alert; queued alerts are delivered after a restart; a hung sink holds exactly its cap of 2 of 4 workers while another sink receives all 20 alerts in under 1 s; the backoff totals about 2.8 h, as stated above. Isolation: `TenantStore.ListDeliveries` and `RetryDelivery` are in the store matrix, and both routes are in the API matrix. |
| 2. Metrics | ✅ Built | `internal/metrics` output is checked line by line against the exposition grammar; `rules_test.go` fails if a shipped rule names a metric Snare doesn't export (checked by renaming one); the smoke test reads the hit and delivery counters through `/metrics` and checks that a tenant key gets 404. |
| 3. Correlation | ✅ Built | `internal/alert/correlation_test.go`: touching a second tripwire from one source makes it Critical with the first as a `related_event`, and a third counts 3. Four non-cases stay High: the same tripwire twice, another source, outside the window, another tenant's touch from the same IP. Touches recorded after an event don't change its rebuilt alert, so retries send identical bodies. The export endpoint uses the same builder. The Slack header escalates. |
| 4. Detection content | ✅ Built, not run in a SIEM | [detections/](../detections/): Splunk, Sentinel, Elastic (rules and index template) and Sigma. `internal/alert/detections_test.go` checks every field path against a real correlated alert, Sentinel identifiers against `SentinelRecord`, and template mappings against the alert. Breaking one field per file (5 mutations) made it fail each time. The rules have not been executed in the products themselves. |
| 5. Key rotation | Not started | |
