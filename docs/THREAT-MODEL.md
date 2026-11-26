# Threat model

Snare is a detection control, so it has two threat models:
- **Detection:** what it is meant to catch, and how that can fail.
- **The service:** how Snare itself can be attacked.

Each claim links to the test or result that backs it. Where nothing backs a claim, it is
listed under residual risk.

## 1. What Snare detects

**Scenario:** an agent with legitimate tools reads attacker-controlled input (a ticket, email,
web page or RAG document) and is steered into an action its user didn't intend. Snare
places things in the agent's environment that no legitimate task has a reason to touch:
- decoy tools
- honey credentials
- canary documents and links

A touch is the alert.

| Failure mode | Status | Evidence |
|---|---|---|
| **False positives:** benign agents touch decoys | Measured low | 0/600 normal runs, 2/232 near-decoy runs (M0); 0/300 held-out hard-benign after screening (M3a-fix2); 0/291 on AgentDojo (M3c). See [results-m0](results-m0.md), [results-m3a-fix2](results-m3a-fix2.md), [results-m3c](results-m3c.md) |
| **Decoys hurt the agent's real work** | Small | −3.4 points utility on AgentDojo, inside the pre-registered −5 limit ([results-m3c](results-m3c.md)) |
| **Hijacked agent never touches a trap** | Partly measured | 42% of credential-hunting agents caught (46/110) on an authorized-audit proxy ([results-m3a](results-m3a.md)). On AgentDojo, no tool-using injection succeeded, so detection there is **unmeasured** |
| **Attacker fingerprints Snare** (known decoy names, token prefix) | Mitigated in part | Fixed prefix removed, per-field tokens, per-install decoy names. The scripted evader went from 200/200 evasions to 200/200 caught. An attacker who reads this repo still evades unless you set your own names ([results-m3a-fix](results-m3a-fix.md)) |
| **Agent is warned about honeypots and avoids them** | Not solved | Warned agents still flag the honey key about as often (69% vs 75%) ([results-m3a-fix](results-m3a-fix.md)) |
| **Exfiltration without touching the network or a decoy** | Out of scope | Snare only sees touches. An injection that only changes the agent's answer (AgentDojo travel task 6) is invisible to it, by design |

**Bottom line:** Snare is a high-precision, partial-recall tripwire. It belongs beside
prevention (input isolation, tool permissions), not in place of it.

## 2. Attacks on the service

### Actors

| Actor | Capability assumed |
|---|---|
| Internet scanner / toucher | Sends arbitrary HTTP and DNS to the callback listeners |
| Hijacked agent | Holds honey values; may probe the callback service |
| Tenant A | Holds a valid admin or viewer key for tenant A |
| Network attacker | Can reach the public ports; cannot break TLS |
| Holder of a database copy | Has `snare.db` (stolen snapshot, backup) but not the env secrets |
| Operator | Holds `SNARE_ADMIN_KEY`; trusted |

### Threats and controls

| Threat | Control | Tested by |
|---|---|---|
| **Forged or guessed tokens flood the DB or trigger fake alerts** | 80-bit ids with an 80-bit truncated HMAC. MAC is checked before any DB access, constant-time, with a cap on checks per input. Per-IP rate limits (per /64 for IPv6) in a bounded table with constant work per request. Measured: about 14,000 junk requests/s on one laptop, including past 50,000 distinct sources. | `internal/token`, `internal/listener` tests; [results-bench.md](results-bench.md) |
| **Toucher learns it hit a honeypot** | Bland, uniform responses on HTTP and DNS. No product name in responses. | `internal/listener` tests |
| **Honey values trip other companies' secret scanners** | No real provider prefixes; the optional custom prefix is checked against known ones. | `internal/token` tests |
| **Tenant A reads or changes tenant B's data** | Every tenant query goes through a `TenantStore` bound to one tenant id. Foreign ids get the same 404 as missing ones. | Store isolation matrix (reflection over the interface) and source lint; API matrix (every route × 10 callers × own/foreign ids, with a leak check on bodies); dashboard cross-tenant tests; `scripts/smoke.sh` in CI |
| **Tenant uses its sink URL for SSRF** (cloud metadata, internal services) | Egress policy refuses private, loopback, link-local, CGNAT, NAT64, 6to4 and IPv4-mapped addresses. It re-checks at dial time to defeat DNS rebinding; no redirects, no proxy, https only. On AWS, IMDS hop limit 1 is a second layer. | `internal/egress` tests, sink-endpoint SSRF test |
| **DB copy exposes tenants' SIEM credentials** | Sink configs sealed with AES-256-GCM under `SNARE_SEAL_KEY`. Associated data binds tenant id and sink id, so moving a ciphertext to another row fails. | `internal/seal` tests, seal-binding test |
| **DB copy exposes API keys** | Only SHA-256 hashes of 160-bit random keys are stored. | `internal/store` tests |
| **Stolen dashboard cookie, or key revoked mid-session** | HMAC-signed session that names the key id. Revocation and tenant disablement are checked on every request; 8 h expiry; HttpOnly, Secure, SameSite=Strict. | Dashboard session tests |
| **XSS via attacker-influenced labels or event details** | `html/template` contextual escaping. CSP `default-src 'none'` with no inline script or style. | Escaping and header tests |
| **CSRF / clickjacking on the dashboard** | Per-form CSRF tokens on sign-in and sign-out, SameSite=Strict, `frame-ancestors 'none'`. The dashboard has no state-changing actions besides sign-out. | CSRF tests |
| **Key brute force on sign-in** | Per-client-IP limiter (behind the proxy, the last `X-Forwarded-For` entry). Bounded memory. The limiter is mainly for noise: keys are not guessable. | Rate-limit tests |
| **Silent alert loss** (restart, SIEM outage, full queue) | Event and outbox row commit in one transaction; per-destination retries for about 3 h survive restarts; dead deliveries are kept, counted in `/metrics` and retryable; a full outbox sheds loudly (counter + error log), never silently. Shipped Prometheus rules alert on each. | `internal/alert/outbox_test.go` (recovery, restart, hung sink, dead + manual retry), `rules_test.go`, smoke test |
| **Customers' SIEM rules drift from Snare's fields** (a rename silently disables a detection) | Shipped rules for Splunk, Sentinel, Elastic and Sigma are checked against a real alert in CI | `internal/alert/detections_test.go` |
| **Alert tampering in transit** | Webhooks are HMAC-signed with a timestamp (replay window); SIEM sinks use TLS and their own auth. | `internal/alert` tests |
| **Undetected admin changes** (who issued that key, who removed that sink) | Each change and its audit record commit together; records are hash-chained; tenants can read their own trail. | `internal/store/audit_test.go` (one record per action, tampering caught at the right row), API attribution test, smoke test |
| **Mention or link injection in Slack alerts** | Attacker-controlled text is escaped (`&`, `<`, `>`) before it reaches Slack, and link unfurling is off. The webhook URL is treated as a secret. | `internal/alert/slack_test.go` |
| **Parser bugs on the untrusted-input path** | Native Go fuzz targets for the token scanner and both listeners, with invariants. CI fuzzes them on every PR. | `internal/token/fuzz_test.go`, `internal/listener/fuzz_test.go` |
| **Vulnerable or tampered dependencies and images** | govulncheck and CodeQL in CI, Dependabot; release images carry an SBOM and provenance and are cosign-signed. govulncheck found one reachable stdlib issue (GO-2026-6859), fixed by moving to Go 1.27.4. | CI `govulncheck`, `codeql` |
| **Instance compromise via the host** | Distroless non-root container, read-only root filesystem, all capabilities dropped. No SSH (Session Manager only). Secrets live in SSM, never in Terraform state. | CI `image` job checks the user; IaC review |

### Residual risk (known, accepted or not yet addressed)

- **A tenant admin key can mute tripwires.** Disabling a tripwire (M4e) is exactly what
  an insider who wanted to go unnoticed would do. It can't be done silently:
  - every disable is in the hash-chained audit log;
  - touches of a disabled tripwire are still recorded and shown as muted;
  - `snare_hits_muted_total` counts them.

  Nothing stops a legitimate admin key from doing it, though. Alert on `token.disable` in
  the audit log if that matters to you.
- **Operator key is all-powerful, and shared.** Since M4b, every tenant, key and sink
  change, and every dashboard sign-in, is written to a hash-chained audit log in the same
  transaction as the change (`snare audit -verify`). There is still no per-operator identity,
  and someone with database write access can rewrite the whole chain. Recording the chain
  head off the box is what detects that.
- **No per-user accounts or SSO inside a tenant.** Keys are shared credentials. This is out
  of scope for M4 by decision ([M4-saas.md](M4-saas.md)).
- **Single node.** Availability matches one instance; there's no HA. Backups are daily
  snapshots, so up to 24 h of events can be lost.
- **Token metadata other than labels is plaintext.** Since M4d, labels and memos, which say
  where each tripwire is planted, are sealed under `SNARE_SEAL_KEY` and bound to their tenant
  and token ([M4d-operations.md](M4d-operations.md) §2). A copy of the database still shows
  token ids, kinds and every event: source IPs, times and request details. Someone with both
  the database and the seal key reads everything. Without `SNARE_SEAL_KEY`, labels are stored
  as written.
- **Not externally reviewed or pen-tested.** The controls above are tested by this repo's own
  tests only.
- **The hosted deployment has never been applied.** The IaC is validated in CI, but no live
  stack exists ([deploy/README.md](../deploy/README.md)).
