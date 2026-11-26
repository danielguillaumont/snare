# Results: single-node capacity (M4d §3)

**Date:** 2026-11-26.

**What this is:**
- One developer laptop: Intel i7-11370H (4 cores, 8 threads), Windows 11, Go 1.27.4.
- Client and server run on the same machine over loopback, so they compete for CPU.

**What this isn't:** a capacity guarantee for a cloud instance. Treat these numbers as
orders of magnitude, and rerun them on the hardware you deploy to.

Raw output is in [`bench/`](../bench/). `bench/summarize.py` turns `go test -bench` output
into the medians and ranges below.

## Summary

| What | Result | Spread |
|---|---|---|
| Junk requests (scanner paths, forged tokens), 60,000 distinct sources | **~14,000–16,000 req/s**, p50 ≈ 1.3 ms, p99 ≈ 14–18 ms, 0 failed | 3 runs |
| Touches (valid tokens: stored, sealed, queued, delivered) | **~140–300 touches/s**, p50 ≈ 73–120 ms, p99 0.5–1.6 s, 0 failed | 3 runs × 2 scenarios |
| Token matching per request line | **3–8 µs** with a valid or forged token, depending on key count | 5 runs |

**How touch throughput compares to need.**
- Touches are bounded by durable commits (fsync), and they vary a lot on a laptop SSD.
- They don't need to be fast. A touch is an incident: a planted secret was used. A real
  attack produces a handful.
- The flood case is junk, and junk never reaches the database.

## Two bugs the benchmarks found

Both let an unauthenticated sender on the public callback port degrade it for everyone,
including real touches.

### 1. Token scanning ran at about 3 MB/s

`Match` found candidates with three regular expressions, e.g. `[a-z2-7]{32,}`. Go's regexp
engine expands the counted repetition into dozens of states. Every request's host, path,
query and credential headers are scanned, up to 16 KiB of headers, so junk text cost
about 0.2 ms per KiB of CPU.

**Fix.** Single-pass loops with no allocations (`internal/token/scan.go`).
- `TestScanMatchesRegexpOracle` and `FuzzScanMatchesRegexp` check them against the original
  expressions as an oracle: 329k fuzz executions, no differences.
- `FuzzFind`, including the rotated 4-key signer, still passes.

`go test ./internal/token -run '^$' -bench . -benchmem -count 5`
([before](../bench/token-before.txt), [after](../bench/token-after.txt)):

| Benchmark | Before | After | Speed-up |
|---|---|---|---|
| `valid/keys=1` | 5.01 µs (4.81–5.37) | 3.57 µs (3.07–4.50) | 1.4× |
| `valid-oldest-key/keys=1` | 8.6 µs (4.88–18.2) | 3.44 µs (3.33–4.47) | 2.5× |
| `junk-same-shape/keys=1` | 28.7 µs (21.4–42.3) | 3.1 µs (2.78–3.48) | 9.2× |
| `8KiB-no-candidate/keys=1` | 1.61 ms (1.40–2.32) | 87.3 µs (85–108) | 18.4× |
| `adversarial-long-run/keys=1` | 1.09 ms (0.998–2.41) | 577 µs (546–620) | 1.9× |
| `valid/keys=4` | 12.8 µs (7.81–36.3) | 4.01 µs (3.56–4.21) | 3.2× |
| `valid-oldest-key/keys=4` | 12.3 µs (11.5–14.2) | 8.2 µs (7.93–8.89) | 1.5× |
| `junk-same-shape/keys=4` | 25.4 µs (21–26) | 8.05 µs (7.95–9.11) | 3.2× |
| `8KiB-no-candidate/keys=4` | 1.39 ms (1.31–1.83) | 92 µs (89.7–94.1) | 15.1× |
| `adversarial-long-run/keys=4` | 646 µs (518–665) | 495 µs (455–603) | 1.3× |

Medians of 5 runs, with min–max in parentheses. The "before" runs are noisy; the laptop
was not isolated.

**Remaining worst case: about 0.5 ms per `Match` call.**
- `adversarial-long-run` is one long base32 run, where every offset is a candidate.
- It is bounded by the 256-MAC cap, not by scanning.
- A request triggers at most two `Match` calls (URL and credential headers), so at most
  about 1 ms of CPU.
- With per-source rate limits (5/s, burst 20), that's the cost an attacker can buy per
  address.

### 2. The per-IP rate limiter degraded past 50,000 sources

**Cause.** The limiter kept one map. Once it held 50,000 entries, every new source address
triggered a scan of the whole map, under the lock, looking for idle entries. In a flood
nothing is idle, so the scan ran on every request and freed nothing. IPv6 makes millions
of source addresses cheap.

**Fix** (`internal/listener/limiter.go`).
- Two generations of buckets, with constant work per request. Memory is bounded to 100,000
  buckets.
- Sources that keep sending keep their bucket through a flood
  (`TestLimiterTableIsBoundedAndKeepsActiveSources`).
- IPv6 is limited per /64 (`TestHTTPRateLimitIPv6Prefix`).
- `BenchmarkLimiterNewSources`: 0.62 µs per new source after 500,000 sources.

Load test, 40,000 junk requests per scenario. The forged-path scenario is the second
40,000, so it runs entirely past 40,000 sources and crosses 50,000. Single runs:

| Scenario | Before | After |
|---|---|---|
| Scanner paths (sources 1–40,000) | 15,250 req/s | 14,446 req/s |
| Forged token paths (sources 40,001–80,000) | **277 req/s**, p99 513 ms | **14,842 req/s**, p99 13.7 ms |

## End to end

```powershell
$env:SNARE_LOADTEST=1; $env:SNARE_LOADTEST_JUNK=60000; $env:SNARE_LOADTEST_TOUCH=3000
go test ./internal/server -run TestLoad -v -count 1
```

**Setup** (`internal/server/load_test.go`).
- A real server with a file database (WAL, `synchronous=FULL`) and `SNARE_SEAL_KEY` set.
- 32 concurrent clients over keep-alive connections.
- Each request carries a new `X-Forwarded-For` address (`TrustProxy` on), as a distributed
  sender's would, so the per-source limiter doesn't hide the work behind it.
- Alerts go to the log sink only, so no network sink is involved.

| Scenario | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Junk: scanner paths (60,000) | 14,923 req/s · p50 1.22 ms · p99 14.4 ms | 16,184 · 1.23 ms · 13.3 ms | 12,792 · 1.47 ms · 18.0 ms |
| Junk: forged token paths (60,000) | 14,327 · 1.38 ms · 15.2 ms | 15,506 · 1.32 ms · 14.4 ms | 14,876 · 1.34 ms · 14.1 ms |
| Touches: new tokens (3,000) | 304 · 72.6 ms · 468 ms | 143 · 120 ms · 1.59 s | 279 · 76.5 ms · 562 ms |
| Touches: same tokens, new sources (3,000) | 235 · 92.3 ms · 668 ms | 170 · 113 ms · 1.18 s | 270 · 83.5 ms · 535 ms |

No request failed in any run. Raw output: [run 1](../bench/load-run1.txt),
[run 2](../bench/load-run2.txt), [run 3](../bench/load-run3.txt).

## Durability costs 4×, and we keep it

**Measurement.** In one exploratory run (300 touches, n=1), `PRAGMA synchronous=NORMAL`
raised touch throughput from 293 to 1,164/s and cut p99 from 495 ms to 119 ms.
- With NORMAL in WAL mode, a commit survives a process crash but can be lost on power loss
  or an OS crash.
- That loss would be a recorded touch whose alert was never queued.

**Decision.** `synchronous=FULL` stays, now explicit in the DSN and checked by
`TestFileDatabaseIsDurable`.
- At 140–300 durable touches/s, one instance has orders of magnitude more headroom than
  tripwires need.
- If that ever changes, the fix is batching commits, not weakening them.

## Not measured

- **Cloud hardware.** The Terraform deployment (t4g.small) has never been applied (M4).
- **DNS channel throughput.**
- **Network sink delivery.** That is bounded by the receiving SIEM; M4c covers retry
  behaviour, not speed.
- **The dashboard and admin API.** They are authenticated and low-volume.
