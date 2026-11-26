# M4 — Hosted Snare: tenants, SIEM export, dashboard, IaC

**Goal (ROADMAP):** a multi-tenant dashboard, OCSF export, and Sentinel, Splunk and Elastic
sinks. **Exit criterion:** tenant-isolation tests pass, and the service deploys from IaC.

Until now one Snare process served one team, holding one admin key. A hosted service holds
many teams' tripwires, and **a tripwire is only useful while its existence is secret.** A
cross-tenant leak is worse here than in most SaaS. It hands an attacker a list of another
company's decoys, which is exactly the list that lets them avoid every one. So tenant
isolation is the security property M4 is built around, and the rest comes after it.

Status: design fixed 2026-11-25, before code. Changes get a dated changelog entry.

## Threat model for tenancy

| Actor | Can | Must not be able to |
|---|---|---|
| Tenant A's API key or dashboard session | Mint, list and export A's tokens and events; configure A's sinks | Read, infer or alter anything of tenant B's: tokens, labels, events, sink configs, counts |
| Attacker who touches B's tripwire | Trigger an alert to B | Learn that B is a Snare customer from the response (unchanged from M1: bland responses) |
| Operator (platform admin key) | Create tenants and issue or revoke their keys | – (trusted, audited) |
| Someone with a DB copy | Read token labels | Use sink credentials: they are encrypted at rest |

**Out of scope for M4:** SSO/SAML, per-user accounts inside a tenant, billing, and
multi-region. These are listed so their absence is a decision, not an oversight.

## Design

### Tenancy in the store (where isolation is enforced)

- New tables:
  - `tenants(id, name, created_at, disabled)`.
  - `api_keys(id, tenant_id, role, hash, created_at, last_used_at, revoked_at)`.
  - `sinks(id, tenant_id, type, config_enc, created_at)`.
  - `tokens` and `events` gain `tenant_id`. Events copy it from their token at hit time,
    and a scoped query never joins across tenants.
- **Every tenant-facing store method takes a `tenantID` and puts `tenant_id = ?` in the SQL.**
  No unscoped read is reachable from tenant code. The single operator path is a separate,
  explicitly named type (`store.Operator`).
- Another tenant's object returns `ErrNotFound`, the same as a missing one, so ids can't be
  probed.
- **Migration:** existing rows become tenant `default`. An existing single-team install keeps
  working unchanged.

### Keys and auth

- **Tenant API keys:**
  - Format: `snk_` plus 32 random base32 characters. The prefix is ours and matches no provider
    format. It exists so secret scanners can be taught to find leaked Snare keys.
  - Storage: SHA-256 hash only, lookup by hash, revocable.
  - Roles: `admin` (mint, sinks) and `viewer` (read only).
- **The operator key** is the existing `SNARE_ADMIN_KEY`.
  - It manages tenants and keys on `/api/operator/...`.
  - It also keeps working on the old endpoints for tenant `default`, so `snare plant` and
    existing scripts don't break.
- **Tenant context** comes only from the authenticated key, never from a request field. An
  `X-Snare-Tenant` header is honored for the operator key alone, and is rejected (403) for a
  tenant key that names another tenant.

### Alerts, OCSF and sinks

- **The alert gets proper OCSF 1.3 Detection Finding fields:**
  - `type_uid` 200401, `status_id`, `metadata.tenant_uid` and `metadata.product.version`.
  - An `observables` array listing the source IP and the token.
  - The Snare-specific fields stay under `unmapped`.
- **A unit test checks every alert** against the required attributes and enumerations of OCSF
  1.3 Detection Finding, from a vendored excerpt of the schema. We claim conformance to those
  required fields, not a full schema validation.
- **Export:** `GET /api/events/export` returns NDJSON of OCSF findings for the caller's tenant,
  filtered by `since`. Its purpose is backfill and SIEMs that pull.
- **Per-tenant sinks** are configured through the API. Secrets are sealed with AES-256-GCM
  under `SNARE_SEAL_KEY`, with the tenant id and sink id as associated data. A ciphertext
  copied to another tenant's row then fails to open.

| Sink | Endpoint and auth |
|---|---|
| Webhook (M1) | HMAC-signed POST |
| Splunk | HTTP Event Collector `POST /services/collector/event`, `Authorization: Splunk <token>`, sourcetype `snare:ocsf:detection_finding` |
| Elastic | `POST /<index>/_doc`, `Authorization: ApiKey <key>`, adds `@timestamp` |
| Microsoft Sentinel | Azure Monitor Logs Ingestion API: `POST {dce}/dataCollectionRules/{dcr}/streams/{stream}?api-version=2023-01-01`. Bearer token from Entra ID client credentials (scope `https://monitor.azure.com//.default`), cached until shortly before expiry |

- **Delivery:** the dispatcher resolves a tenant's sinks when it queues an alert. Each
  (alert, sink) pair retries on its own, so one dead SIEM doesn't delay the others, and a
  tenant's sink failures never reach another tenant.
- **Egress safety:** sink URLs must be `https`. Hosts that resolve to private, loopback or
  link-local addresses are refused at configuration time and again before each send. Without
  this, a sink becomes an SSRF primitive against our own infrastructure. A dev flag allows
  `http`/localhost for tests.

### Dashboard

- **Pages:** server-rendered (`html/template`, no JS framework), read-only for M4: tokens,
  recent events, sink status. **Sign-in:** a tenant key exchanged for a session cookie.
- **Cookie:** HMAC-signed, `HttpOnly`, `Secure` (unless dev), `SameSite=Strict`, 8 h. It holds
  the key id, so revoking the key ends the session on the next request.
- **Headers:** strict CSP (`default-src 'self'`), `X-Frame-Options: DENY`, and no third-party
  assets.
- **Forms:** read-only pages leave no CSRF surface beyond sign-in and sign-out, which carry a
  per-session token.

### Deployment (IaC)

The service uses SQLite, so it runs as **one node.** That is honest for the first design
partners and simple to secure. The scaling path (Postgres, several stateless nodes) is a later
milestone.

- **Container:** a multi-stage Docker build into distroless static, running as non-root. It
  holds the binary only.
- **Terraform for AWS:**
  - **Compute:** one Graviton EC2 instance with an encrypted EBS data volume and an Elastic IP.
  - **Network:** security groups open only 80, 443 and 53 (TCP and UDP). The admin API and the
    dashboard sit behind TLS via Caddy.
  - **Secrets:** SSM Parameter Store SecureStrings, readable only by the instance role.
  - **Access:** IMDSv2 required, and SSM Session Manager instead of SSH (no port 22).
  - **DNS:** Route 53 records, with NS delegation of the callback zone to the instance.
- **CI:** `terraform fmt -check` and `terraform validate` run in CI.

**Deploying needs the owner's AWS account and spends money.** That is the owner's call. M4 is
"deployable from IaC" once a `terraform apply` from a clean account brings the service up and
the smoke test (`scripts/smoke.sh`: mint → touch → alert) passes. Until then the README says
"IaC written, not yet applied".

## Tests (the exit criterion)

1. **Store-level isolation matrix.** Two tenants each mint tokens and record events. Then every
   tenant-scoped store method is called with tenant A and tenant B's ids, and must return
   `ErrNotFound` or an empty result. The method list comes from reflection over the
   `store.Tenant` interface, so a new method can't be added without being covered.
2. **API-level matrix.** Every route × {A's key, B's key, viewer key, operator key, revoked
   key, no key} × {own id, other tenant's id}. This checks status codes, and checks that no
   response body contains any of the other tenant's token ids or labels.
3. **Hit routing.** A touch on B's token produces exactly one alert, delivered only to B's
   sinks.
4. **Sealed secrets.** Moving A's sink ciphertext to B's row fails to decrypt.
5. **Sinks.** `httptest` servers check the exact wire format, auth headers and retry
   behavior of each SIEM sink, including Sentinel token refresh.
6. **SSRF guard.** Private, loopback, link-local and IPv6-mapped addresses are refused.
7. **Dashboard.** Session forging and tampering are rejected, revoked keys log out, the
   security headers are present, and no cross-tenant data appears.

## Changelog

- 2026-11-25: design fixed before code.
