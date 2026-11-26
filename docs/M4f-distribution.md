# M4f — Distribution, retention and integration

**Goal:** make Snare something a team can install, keep running for a year, and wire into
the agents it already has, without reading the source.
**Budget: $0.** No model calls. GitHub Actions minutes on a public repository are free, and
no cloud account is involved.

## Gaps this closes

| Gap (as of M4e) | Consequence |
|---|---|
| Releases ship only a container image | `snare plant`, `snare advise` and `snare demo` are meant to run on a developer's machine. Today that means installing Go. |
| Events are kept forever | The database grows without bound, and a team with a data-retention policy can't apply it. |
| No guide for real agent clients | `snare plant mcp` writes a config entry, but nothing explains where it goes in Claude Desktop, Claude Code or other MCP clients, or how to check that a decoy is live. |

## 1. Release binaries

- **Targets.** On a version tag, the release workflow builds `snare` for linux, darwin and
  windows, on amd64 and arm64.
  - `CGO_ENABLED=0`: the SQLite driver is pure Go, so the binaries are static.
  - Built with `-trimpath`, with `ProductVersion` stamped from the tag.
- **Artifacts.**
  - One archive per target: `.tar.gz`, or `.zip` for Windows.
  - A `SHA256SUMS` file.
  - A Sigstore bundle for `SHA256SUMS`, signed keylessly with the workflow's OIDC identity,
    the same identity that signs the image.
  - Users verify with `cosign verify-blob`, then `sha256sum -c`.
- **Attached to the GitHub release.** The release is created if missing; the notes are
  written separately.
- **Checked before tagging.** CI cross-compiles all six targets on every PR, so a broken
  target fails before a release, not during one.

**Exit:**
- The cross-compile check passes in CI.
- A tagged release has 6 archives, `SHA256SUMS` and its bundle.
- `cosign verify-blob` succeeds against the documented identity.
- A downloaded binary runs `snare version` with the tag's version.

## 2. Event retention

- **Configuration.** `SNARE_EVENT_RETENTION` takes a number of days. Unset or `0` keeps
  events forever, which is the default and today's behaviour.
- **What is deleted.** An hourly job deletes events older than the retention period
  **unless they are still open**. A touch nobody has looked at is never removed by a timer:
  untriaged evidence disappearing on a schedule is the wrong failure for a detection
  product. Muted touches have no one to triage them, so they age out normally. Their
  delivery rows are deleted in the same transaction.
  - An event whose alert is still pending in the outbox is kept until the alert is
    delivered or dead, even when closed: until then the row is the only copy.
- **Visible.**
  - Each run that deletes anything appends one audit record, `events.purge`, by `system`,
    with the cutoff and count, to each tenant that lost events. Records are per tenant so
    each tenant's own audit log explains where its events went.
  - `snare_events_purged_total` counts deletions.
  - Open events older than the cutoff are what keep the database growing.
    `snare_events_open_expired` reports how many there are, so an operator can see that
    triage is the bottleneck.
- **Scope.** Retention is per instance, not per tenant. A tenant that needs a shorter
  period exports with `GET /api/events/export` and keeps its own copy.

**Exit:** store tests cover:
- Only closed or muted events older than the cutoff are deleted.
- Their deliveries go with them.
- Open old events survive.
- The audit record holds the count.
- Retention 0 deletes nothing.

A server test checks the env parsing (`30` and `0`, with garbage refused).

## 3. Integration guide

`docs/INTEGRATIONS.md` covers:
- Where `snare plant mcp` output goes for MCP clients that use the common `mcpServers` JSON
  shape.
- How to confirm a decoy is live without tripping it for real: mint a test tripwire, touch
  it, triage it as `false_positive`, then disable it.
- How to route alerts to the tools a team already has.

Every command in the guide is one the CLI accepts. A test reads each `snare` command from
the guide's code blocks and checks the subcommand exists and that every flag it passes is
one that subcommand's real `FlagSet` defines (read from its `-h` output), so they can't drift.

**Exit:**
- The guide exists, and its commands parse.
- The README links it from "How it works".

## Results

| Section | Status | Evidence |
|---|---|---|
| 1. Binaries | ✅ Built. The first tagged release will exercise the upload and signing | `scripts/build-release.sh`; CI job `cross` builds all six targets on every PR and runs the Linux binary's `snare version`. The release job `binaries` signs `SHA256SUMS` and attaches the assets. |
| 2. Retention | ✅ Built | `internal/store/retention_test.go`: only closed or muted events past the cutoff go, open ones and ones with a pending alert stay, deliveries go with them, one audit record per tenant with the count, and an empty run audits nothing. `internal/server/retention_test.go`: env parsing (`""`, `0`, `30` accepted; `-1`, `30d`, `1.5` and overflow refused), the purge counter, and the open-expired gauge (0 with retention off). Mutation checks: dropping the open-status guard or the pending-delivery guard each fails a test. |
| 3. Integration guide | ✅ Written | [INTEGRATIONS.md](INTEGRATIONS.md). `cmd/snare/integrations_test.go` checks its commands against the real flag sets; renaming a flag in the guide (`-status` to `-state`) or a subcommand (`tokens` to `tripwires`) each fails it. |
