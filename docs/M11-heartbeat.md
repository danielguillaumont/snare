# M11 — Heartbeat: know a path works before an attacker tests it

**Goal:** a tripwire that can't report is worse than none, because it looks armed. Today a
broken path stays silent: a DNS delegation lapses, a proxy drops `/v1/`, or a gateway stops
reaching Snare. Nobody notices until the touch that mattered goes unrecorded. M11 sends
scheduled synthetic touches down each path. It shows, per channel, when each was last
verified, and exposes a metric that goes stale when a path breaks.

**Budget: $0.** No model calls.

## 1. Heartbeat tokens

A new kind, `heartbeat`. A touch of a heartbeat token goes through the same listener,
signature check and store transaction as any touch. At the point where a touch becomes an
event, it instead updates a heartbeat record for its tenant and channel: the last time seen,
a count, and the source.

A heartbeat touch never becomes an event, an incident or an alert, so it never reaches a
sink. It cannot page anyone or skew detection metrics.

| Channel | Sent by | Path it proves |
|---|---|---|
| `http` | the Snare server, every `SNARE_HEARTBEAT` | public URL, any proxy or load balancer, the HTTP listener, the store |
| `dns` | the Snare server, if a zone is set | the zone's delegation, resolvers, the DNS listener, the store |
| `gateway` | each gateway, every `heartbeat` in its config | the agent's machine to Snare, the gateway's callback, the store |

**The server probe goes out the front door.** It fetches its own `SNARE_PUBLIC_URL` and
resolves its own name through the system resolver. A heartbeat proves the path an attacker's
touch would take, not a loopback shortcut.

**The server's heartbeat token is derived, not random.** It is an HMAC of the signing key,
so it is the same token after every restart and the token list doesn't grow. Gateways mint
theirs when planted.

**What a heartbeat doesn't cover: alert delivery.** The outbox already measures delivery
(dead letters, pending age, per-sink results;
[M4c](M4c-reliability.md)), and `POST /api/sinks/{id}/test` sends a marked test finding.
[DEPTH.md](DEPTH.md) said heartbeats would reach SIEMs "marked as tests". That changes here
([decision](#decision-heartbeats-dont-reach-sinks)).

## 2. Showing it

- **Dashboard.** The overview lists each channel with "verified N min ago", or **stale**,
  or **never**.
- **CLI.** `snare heartbeat` prints the same table.
- **API.** `GET /api/heartbeats` returns it, viewer access.
- **Metrics:**
  - `snare_heartbeat_age_seconds{channel}`: seconds since the newest heartbeat on that
    channel, across tenants;
  - `snare_heartbeat_stale{channel}`: 1 when that age is over `SNARE_HEARTBEAT_STALE`, or
    when an expected channel has never been seen.

  A channel is expected when the server probes it (`http`, and `dns` with a zone), or once
  any gateway has beaten. Alert on `snare_heartbeat_stale == 1`.

`SNARE_HEARTBEAT_STALE` defaults to three server intervals, or 45 minutes when the server
probe is off. Gateways default to a 15-minute heartbeat, so three missed beats are stale.

## 3. Configuration

- **`SNARE_HEARTBEAT`** sets the server probe interval, for example `15m`, with a minimum
  of `1m`. Empty is off, the default, because a server whose public URL isn't reachable
  from itself would only log failures.
- **`snare plant gateway -heartbeat 15m`** sets the gateway's beat. `15m` is the default,
  and `0` turns it off. It writes `"heartbeat": {"token": …, "every": "15m"}` into
  `gw.json`. The gateway beats once at start, then on the interval.

  An agent that reads `gw.json` learns the heartbeat token. Touching it only marks the
  gateway channel alive (§4).

## 4. Limits

- **A forged heartbeat can make a broken path look alive.** Anyone with a heartbeat token
  (from `gw.json`, or a captured probe) can keep a channel fresh from elsewhere. It can't
  create, hide or alter a touch. The gateway channel is labelled by the session parameter, so
  a forger can also mislabel an `http` beat as a gateway one. Heartbeats verify plumbing;
  they don't authenticate anything.
- **One number per channel.** The metric is the newest heartbeat across tenants, which keeps
  label cardinality fixed. One tenant's gateway failing while another's works is visible on
  that tenant's dashboard, not in the metric.
- **The server probe proves the server can reach its own public address.** An outage
  between the internet and the server that the server's own route avoids, such as split
  DNS, is not detected. Run `snare heartbeat` from outside, or a gateway on another
  network, for that.

## Decision: heartbeats don't reach sinks

[DEPTH.md](DEPTH.md#milestones) M11 said synthetic touches would be "marked as tests, so
SIEM rules ignore them". Sending one every 15 minutes per channel to every sink means a
Slack message every few minutes. It also means every SIEM rule must filter them, and any
rule that forgets pages someone.

Delivery health is already measured on its own (M4c), with a test-finding endpoint for
checking a mapping. So heartbeats stop at the store. Decided 2026-11-26; recorded in
DEPTH.md.

## Exit criterion

- **Store.**
  - A heartbeat touch updates the tenant's record for its channel, and creates no event,
    incident or outbox row.
  - Heartbeats are per tenant: the isolation matrix covers the new method.
- **Token.** The derived heartbeat token is stable for a key, differs between keys, and
  verifies like any token.
- **Gateway.** It beats at start with `layer=heartbeat` and its session, carries no ledger,
  and doesn't beat with no `heartbeat` in its config.
- **Metrics.** Age and stale gauges cover a fresh, an old and a never-seen expected channel.
- **End to end.** A real server with `SNARE_HEARTBEAT` on, with HTTP and DNS listeners, and
  a planted gateway:
  1. `http`, `dns` and `gateway` all show verified on the API, the dashboard and the
     metrics, with no events, incidents or deliveries.
  2. Then the DNS path is broken (the listener stopped) and time advanced past the stale
     limit: `dns` turns stale while `http` stays fresh.

## Results

Measured 2026-11-26, Go 1.27.4, Windows 11, `go test ./...`. No API spend.

| Item | Status | Evidence |
|---|---|---|
| Store | ✅ | `TestHeartbeatIsNotAnEvent`: five beats on three channels with alert requested; no event, incident or outbox row. The newest time is kept when a beat arrives late, and the source is the session for gateway beats. `ListHeartbeats` is in the isolation matrix. `TestBeatPolicy` covers ok, stale and never, a custom limit, and clock skew. |
| Token | ✅ | `TestDerive`: stable for one key and name; different across names and keys; verifies and matches like a minted token; same shape. |
| Gateway | ✅ | `TestHeartbeatAtStart`: one beat at start carrying only `layer` and `session`, with no tool and no ledger, and no second beat within the interval. No beat without a config. `TestHeartbeatConfig` rejects intervals under 1m and a missing token. `plant gateway` mints the token as `heartbeat`, and `-heartbeat 0` plants none. |
| Metrics | ✅ | `TestGaugeVecFunc` covers the labelled gauge's output, sorting and escaping. The age and stale gauges are checked on a live server in the end-to-end test. |
| End to end | ✅ | `TestEndToEndHeartbeat`, both steps on a real server, its real DNS listener and a planted gateway:<br>1. `http`, `dns` and `gateway` show verified on the API, the dashboard and the metrics. There are no events, incidents or deliveries, and one server heartbeat token.<br>2. With DNS stopped and the clock 4 h on, `http` stays fresh. `dns` (and the gateway, which hadn't beaten since) turn stale on the API, the metrics (`snare_heartbeat_stale{channel="dns"} 1`) and the dashboard. |

**Mutation check.** With heartbeats no longer diverted from events, both the store test
and the end-to-end test fail.
