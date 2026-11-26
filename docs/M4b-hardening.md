# M4b — Hardening and the placement advisor

**Goal:** close the open items from [THREAT-MODEL.md](THREAT-MODEL.md), harden the supply
chain, and build the last unbuilt SPEC component that needs no model calls. **Budget: $0.**
No model calls, no cloud resources.

## 1. Supply chain

| Control | How |
|---|---|
| Known-vulnerable dependencies | `govulncheck` in CI. It reports only vulnerabilities in code paths we actually call, so a finding is real. |
| Static analysis | CodeQL for Go and Python, on PRs and weekly. |
| Dependency drift | Dependabot for Go modules, pip and GitHub Actions, weekly and grouped. |
| What's in the image | The release build attaches an SBOM and SLSA provenance attestations to the image (`buildx --sbom --provenance=mode=max`). |
| Who built the image | Keyless cosign signature (Sigstore, using the workflow's OIDC identity), so anyone can check it came from this repo's release workflow. See `cosign verify` in [deploy/README.md](../deploy/README.md). |

**Exit:** CI runs govulncheck, and its result is clean or every finding is documented. CodeQL
runs. The next release is signed and carries an SBOM.

## 2. Fuzzing the untrusted-input paths

Everything an attacker can send reaches three functions: the token scanner, the HTTP
listener and the DNS listener. Each gets a native Go fuzz target with these invariants:

- **Scanner:** never panics. Every token it reports verifies under the key. MAC checks per
  input stay within the documented cap. A real token embedded in random text is always
  found.
- **HTTP:** never panics. The reply is always the bland `200 {"status":"ok"}` (or 429 when
  rate limited). Input without a token never records a hit.
- **DNS:** never panics on arbitrary query names and types. Names outside the zone never
  record a hit.

Seed corpora are checked in, so `go test` replays them on every run. A separate CI job fuzzes
each target for a short fixed time.

**Exit:** all three targets exist. Each has run locally for at least 2 minutes with no
failures, and any crash found is fixed with its input added as a regression seed.

## 3. Operator and tenant audit log

**Gap:** the operator key is all-powerful and leaves only ordinary log lines.

- **What is recorded:** tenant create, disable and enable; API key issue and revoke; sink
  create and delete; dashboard sign-in. Token minting is not recorded: it is high-volume, and
  the tokens table already records it.
- **Fields per record:** time, actor (`operator` or a key id), tenant, action, target id, and
  a short detail. Never secret values.
- **Tamper evidence:** each row stores `hash = SHA-256(prev_hash ‖ canonical row)`. Changing
  or deleting a past row breaks the chain from that point. An attacker with database write
  access can still rewrite the whole chain. The defense against that is keeping a copy of
  the chain head somewhere else: `GET /api/operator/audit/verify` checks the chain and
  returns the head hash, for the operator to record off the box. A later head that doesn't
  extend the recorded one means history was rewritten.
- **Access:** tenants read their own records at `GET /api/audit`, through the `TenantStore`
  view, so the isolation matrix covers it automatically. The operator reads everything.

**Exit:** each action above writes exactly one record. Tenants see only their own records.
Changing any field of any past row, or deleting it, makes verify fail at that row.

## 4. Placement advisor (`snare advise`)

SPEC lists a placement advisor: score agents on **untrusted input + private data + an
exfiltration path**. An agent with all three is the one where a successful injection does
damage, so it needs tripwires most.

- **Input:** an MCP client config (`mcpServers`, as used by Claude Desktop, Claude Code and
  others). Optionally, a `tools/list` dump per server for finer classification. The advisor
  never connects to anything.
- **Classification:** fixed, tested rules over server names, commands, packages, URLs and
  (if given) tool names and descriptions. Each server gets zero or more capabilities:
  - `untrusted_input`: email, tickets, chat, web fetch, browser, issue trackers, public repos.
  - `private_data`: filesystems, databases, drives, internal wikis, CRM, secrets managers.
  - `exfiltration`: anything that sends data out — HTTP fetch, email or chat send, PR/issue
    writes, webhooks.

  Unknown servers are reported as unknown, never guessed.
- **Output:** text or JSON.
  - Which capability each server provides, and whether all three are present.
  - Concrete recommendations that map to existing `snare plant` commands. For example:
    decoy tools named for the private-data domain; honey credentials under each filesystem
    root; canary docs in knowledge bases; DNS canaries when the exfiltration path is web fetch.
- **Honesty:** the rules are heuristics. Output says "based on names and descriptions; verify
  against what the servers really do".

**Exit:** table-driven tests over realistic configs, including the three-capability case, a
safe read-only case, unknown servers and a tools dump that overrides a name-based guess. The
CLI runs on `examples/` fixtures.

## 5. Slack sink

A Slack incoming webhook (`https://hooks.slack.com/services/...`) receives a short Block Kit
message with the tripwire label, channel, source and time, plus the finding uid.

- **The webhook URL is the credential.** It is stored sealed and never returned by
  `Public()`.
- **Validation:** host must be exactly `hooks.slack.com` over https, through the egress
  policy like every other sink.

**Exit:** a wire-format test against an httptest server; tests that validation refuses
other hosts and that the URL never appears in API responses.

## Changelog

- 2026-11-26: design fixed before code.
- 2026-11-26, results:
  - **govulncheck** found GO-2026-6859 (`net/http` server crash), reachable from the
    callback listener. Moving to Go 1.27.4 fixed it, and the rerun is clean.
  - **Fuzzing,** 2 minutes per target, no failures:

    | Target | Executions |
    |---|---|
    | `FuzzFind` | ~194k |
    | `FuzzHTTP` | ~254k |
    | `FuzzDNS` | ~1.16M |

    The first listener run did fail, but the bug was in the test: seeds were minted in a
    different process than the workers. The invariant now asks "the id comes from a token
    that verifies in the input" instead of "the id equals the planted one".
  - **Audit log:** sign-in auditing is best effort. A failed write is logged and the sign-in
    still succeeds, because a sign-in changes nothing. Every real change fails if its audit
    record can't be written.
  - **Slack:** besides the planned checks, attacker text is escaped against mention and link
    injection, and a negative control (escaping removed) makes the test fail.
  - **Release signing** takes effect from the next tag. v0.4.0 is unsigned.
