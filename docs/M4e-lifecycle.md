# M4e — Tripwire lifecycle, triage and first run

**Goal:** the things a security team asks for in its first week with Snare, after "does it
detect anything":
- How do I switch off a tripwire I removed, or one a test leaked?
- How do I record that I looked at an alert, and what it turned out to be?
- How do I try it in two minutes, on my own laptop?

**Budget: $0.** No model calls, no cloud resources.

## Gaps this closes

| Gap (as of v0.6.0) | Consequence |
|---|---|
| A minted tripwire alerts forever | Removing a decoy from a repo or rotating a test fixture leaves a token that can still page someone. The workaround, deleting a sink, mutes everything. |
| Touches have no state | The dashboard can't distinguish a new Critical from one already handled. Nobody can record "false positive", which is the one number that tells a team a tripwire is badly placed. |
| The demo is a bash script that needs `openssl` | Windows users, and anyone evaluating from a release binary, can't run it. |

## 1. Disabling a tripwire

- **API.** `POST /api/tokens/{id}/disable` and `/enable` (admin role). Each change is written
  to the audit log in the same transaction, with action `token.disable` or `token.enable`.
- **Behaviour while disabled:**
  - A touch is still verified and recorded, so the forensic trail survives.
  - The stored event is marked `muted`. No alert is queued, and
    `snare_hits_muted_total` counts it.
  - In export, a muted event is an OCSF finding with `status_id` 3 (Suppressed).
- **Why record at all.** A disabled tripwire that is still being touched is information. It
  usually means the old value leaked further than the team thought.
- **Threat.** Muting is what an insider holding an admin key would want. Every disable is
  in the hash-chained audit log. The dashboard shows disabled tripwires and muted touches
  plainly, never hidden. The threat model lists this as residual risk.

**Exit:** store, admin and end-to-end tests show the following.
- A touch of a disabled tripwire is stored, muted and not delivered.
- Re-enabling restores alerts.
- Another tenant can't disable or enable it, and the change is in the audit log.

## 2. Triage

- **States.** Each event has a status: `open` (default), `acknowledged`, `resolved` or
  `false_positive`, plus an optional note (at most 500 characters). Any state can move to
  any other, so a triage can be reopened.
- **API.** `POST /api/events/{id}/triage` with `{status, note}` (admin role). The change is
  audited as `event.triage`. The audit detail records the new status and the note's length,
  not its text, so the audit log doesn't become a second copy of analyst notes.
- **Reading.** `GET /api/events?status=open` filters, and
  `snare events -status open` does the same from the CLI.
- **CLI.** `snare triage -event ID -status false_positive -note "red-team exercise"`.
- **Export.** OCSF `status_id`: open → 1 New, acknowledged → 2 In Progress, resolved and
  false positive → 4 Resolved. `status_detail` carries the Snare status.
- **False positives are a placement signal.** The token page shows a tripwire's
  false-positive count. At 2 or more, it suggests retiring or moving it, which is the same
  rule M0 used to retire decoys.

**Exit:** tests cover the following.
- Transitions and validation.
- Tenant isolation: an event id from another tenant answers 404.
- The status filter.
- OCSF status mapping.
- The audit record omits the note's text.

## 3. `snare demo`

- **One command.** `snare demo` starts a complete instance in-process, with a temporary
  database and random keys. It creates a tenant and plants three tripwires, then plays an
  "attacker" that follows the canary link and uses the honey key. The second touch is
  Critical.
- It prints the dashboard address and a viewer key, and cleans up on Ctrl-C.
- **No dependencies beyond the binary.** Nothing leaves the machine, and it runs the same on
  Windows, macOS and Linux, from a release binary or from the container image.
- `scripts/demo.sh` becomes a thin wrapper around it.

**Exit:** a test runs the demo with a short-lived context. It checks that the dashboard
answers and shows a Critical touch, and that the temporary directory is removed afterwards.

## Results

| Section | Status | Evidence |
|---|---|---|
| 1. Disabling | ✅ Built | `internal/store/lifecycle_test.go`: a touch of a disabled tripwire is stored and muted, with no delivery queued. Disabling twice keeps the original time, and re-enabling restores alerts. The audit log records each change with its actor. Store and API isolation matrices: another tenant gets 404 and nothing changes. `internal/server/lifecycle_e2e_test.go` runs disable → touch (no webhook) → enable → touch (webhook) on a real server. Mutation check: with muting removed, that test fails. |
| 2. Triage | ✅ Built | `TestTriageEvent`: validation, the status filter, reopening, and an audit detail of `status=false_positive note_bytes=33` that never contains the note. `TestOCSFStatusFollowsTriage`: all 7 mappings, and severity is never changed. End to end: the export shows the muted touch as Suppressed (3) and the false positive as Resolved (4). Bad status values answer 400. Dashboard: `TestTriageAndDisabledTripwiresShown` covers a resolved critical that is no longer counted as open, the note shown, the disabled and muted tags, and the placement hint after 2 false positives. |
| 3. Demo | ✅ Built | `cmd/snare/demo_test.go` runs `snare demo` on free ports. It signs in to the dashboard with the printed key and finds "critical · 2 tripwires" and 3 tokens. After cancelling, the temporary directory is gone. Passes on Windows locally and on Linux in CI. |
