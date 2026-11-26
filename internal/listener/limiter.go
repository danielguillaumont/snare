package listener

import (
	"net/netip"
	"sync"

	"golang.org/x/time/rate"
)

// limiterTable holds one token bucket per source, in bounded memory with O(1) work per
// request.
//
// It keeps two generations of buckets. A lookup checks the current generation, then the
// previous one, and promotes a hit. When the current generation is full it becomes the
// previous one, and the old previous generation is dropped whole. A source that keeps
// sending stays in the table. A flood of new sources only cycles generations.
//
// This replaced a single map that, once it held 50,000 entries, scanned all of them under
// the lock for every new source. In a load test, 50k+ distinct senders took the forged-token
// path from about 10,000 to 277 requests/s, and every real touch waited behind them
// (docs/results-bench.md).
type limiterTable struct {
	mu        sync.Mutex
	cur, prev map[string]*rate.Limiter
	perGen    int
}

// limiterGeneration bounds the table at 2 × limiterGeneration buckets (about 20 MB).
const limiterGeneration = 50_000

func (t *limiterTable) get(key string, r rate.Limit, burst int) *rate.Limiter {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.perGen == 0 {
		t.perGen = limiterGeneration
	}
	if l, ok := t.cur[key]; ok {
		return l
	}
	l, ok := t.prev[key]
	if !ok {
		l = rate.NewLimiter(r, burst)
	}
	if t.cur == nil || len(t.cur) >= t.perGen {
		t.prev, t.cur = t.cur, make(map[string]*rate.Limiter, t.perGen)
	}
	t.cur[key] = l
	return l
}

func (t *limiterTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.cur) + len(t.prev)
}

// limitKey is the rate-limit identity of a source address. An IPv6 sender usually controls
// a whole /64, so per-address limits would mean nothing. IPv4 addresses and anything that
// doesn't parse are used as they are.
func limitKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Is4() || a.Is4In6() {
		return ip
	}
	p, err := a.Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}
