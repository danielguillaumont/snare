# M4d — Operator view, data at rest and measured capacity

**Goal:** close the gaps an operator would hit in the first week of running Snare: the
dashboard doesn't show what M4c added, a copy of the database tells a reader where every
tripwire is planted, and nobody knows how much traffic one instance can take.
**Budget: $0.** No model calls, no cloud resources.

## Gaps this closes

| Gap (as of M4c) | Consequence |
|---|---|
| The dashboard shows each touch the same way | A Critical, multi-tripwire touch looks like any other row. A tenant whose SIEM is down has no way to see that its alerts gave up. |
| Token labels and memos are plaintext in SQLite | A label says where a tripwire is planted ("billing-svc/.env: PAYMENTS_API_KEY"). A leaked backup or snapshot is a map an attacker can use to avoid every tripwire. Listed as residual risk in [THREAT-MODEL.md](THREAT-MODEL.md). |
| No capacity numbers | "Single node" is documented, but not what a single node can handle, or what junk traffic on the public callback port costs. |

## 1. Dashboard: severity and delivery health

- Each touch on the overview shows the severity its alert carried. **Critical · N
  tripwires** when the same source touched N ≥ 2 distinct tripwires within the correlation
  window (M4c §3), **high** otherwise. A touch verified by a retired key is tagged **old
  key** (M4c §5), so the tenant knows to replant it.
- Two counters: critical touches, and **undelivered** alerts (dead deliveries to the
  tenant's own sinks). Both are hidden at zero.
- The sinks page lists recent deliveries: sink, state, attempts, last error, and the command
  to requeue.
- The correlation query used by the dashboard is the alert's, exposed on the tenant view,
  and it is covered by the tenant-isolation matrix.

**Exit:** a dashboard test where one source touches two tripwires and a sink delivery is
dead. The overview shows one critical touch and one undelivered alert; another tenant sees
neither.

## 2. Token labels and memos sealed at rest

- **When.** When `SNARE_SEAL_KEY` is set (it already is in the reference deployment, for
  sink credentials), labels and memos are sealed with AES-256-GCM before they're written.
  The associated data is the tenant id and token id, as for sinks. A sealed label copied
  onto another token, or into another tenant, fails to open.
- **Stored form.** The column keeps its TEXT type. A sealed value is `sealed:v1:` followed by
  base64. Plaintext rows from before stay readable, so the change ships without a flag day.
- **Migration.** At startup with a seal key, any remaining plaintext labels and memos are
  sealed in one transaction. It is idempotent and logs a count.
- **Failure is visible, never silent, and never blocks an alert.** A label that can't be
  opened (wrong key, tampered row, seal key removed) reads as
  `(sealed label: cannot open)`. The alert is still delivered with every other field
  intact. A tripwire firing matters more than its description.
- **What this doesn't cover.** Token kind, creation time and the events table stay in
  plaintext. Events hold source IPs and request details, which an operator needs to query.
  Someone holding both the database and the seal key reads everything. The seal key lives
  in SSM, apart from the volume and its snapshots, and that separation is the point.

**Exit:** store tests show the following.
- Labels and memos round-trip.
- The raw column holds no plaintext.
- Legacy rows are migrated.
- A label moved between tokens or tenants doesn't open.
- With a wrong key, a hit still records and alerts with the placeholder label.

An end-to-end test shows a touched tripwire alerting with its real label while the label
is sealed in the database file.

## 3. Measured capacity

The aim is reproducible benchmarks with the method written down next to the numbers.

- **Token matching** (`internal/token`). `Match` on a request line with a valid v2 token,
  with junk of the same shape, and with 8 KiB of text that has no candidates. Cases with 1
  and 4 keys, because rotation multiplies MAC work.
- **Recording a hit** (`internal/store`). `RecordHit` against a file database in WAL mode,
  the production configuration, for both alerting and dedup-suppressed hits.
- **End to end** (`internal/server`). A real server on loopback, with concurrent clients:
  - **touches/s:** valid tokens, each stored and queued for delivery;
  - **junk/s:** requests with no valid token, which is what the public port mostly sees.

  For both, p50 and p99 latency.
- Results go in [results-bench.md](results-bench.md) with the machine, Go version, command,
  run count and spread. Numbers are labelled as one developer laptop, not a capacity
  guarantee.

**Exit:** `go test -bench` commands in the results file reproduce the table. The README
quotes no number that isn't in that file.

## Results

| Section | Status | Evidence |
|---|---|---|
| 1. Dashboard | ✅ Built | `TestCriticalTouchesAndUndeliveredAlerts`. `RelatedTouches` is in the store isolation matrix. PR #14. |
| 2. Sealed labels | ✅ Built | `internal/store/labels_test.go`. Labels and memos round-trip through every read path: `GetToken`, `ListTokens`, `RecordHit`, `AlertData` and `Related`. The raw column holds no plaintext. Legacy rows are migrated once, and a second run seals 0. A sealed label copied onto another token, within a tenant or across tenants, reads as the placeholder. With a wrong key or no key, a hit is still recorded and queued, with the placeholder label. `internal/server/sealed_labels_e2e_test.go`: a real server mints and touches a tripwire, and the webhook alert carries the real label and memo. The database and WAL files don't contain either. Mutation check: with sealing disabled in the server, that test fails. |
| 3. Capacity | Not started | |
