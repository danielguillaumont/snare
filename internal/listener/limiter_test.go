package listener

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestLimiterTableIsBoundedAndKeepsActiveSources(t *testing.T) {
	tb := &limiterTable{perGen: 100}
	busy := tb.get("203.0.113.9", rate.Every(time.Hour), 2)
	busy.Allow()
	busy.Allow()
	for i := 0; i < 10_000; i++ {
		tb.get(fmt.Sprintf("10.0.%d.%d", i>>8, i&255), 1, 1)
		if i%50 == 0 { // the busy source keeps sending through the flood
			if tb.get("203.0.113.9", rate.Every(time.Hour), 2) != busy {
				t.Fatalf("active source lost its bucket after %d new sources", i)
			}
		}
		if n := tb.size(); n > 200 {
			t.Fatalf("table grew to %d entries", n)
		}
	}
	if busy.Allow() {
		t.Fatal("active source got a fresh burst")
	}
}

func TestLimitKeyGroupsIPv6By64(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":          "203.0.113.9",
		"2001:db8:1:2:aaaa::1": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"::ffff:203.0.113.9":   "::ffff:203.0.113.9",
		"not-an-ip":            "not-an-ip",
	} {
		if got := limitKey(in); got != want {
			t.Errorf("limitKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// One IPv6 sender rotating through its /64 shares one bucket.
func TestHTTPRateLimitIPv6Prefix(t *testing.T) {
	h := &HTTP{Signer: newSigner(t), Recorder: &rec{}, Log: quiet, PerIPRate: 1, PerIPBurst: 3}
	limited := 0
	for i := 0; i < 10; i++ {
		if !h.allow(fmt.Sprintf("2001:db8:5:6::%x", i+1)) {
			limited++
		}
	}
	if limited != 7 {
		t.Fatalf("limited %d of 10 addresses in one /64, want 7", limited)
	}
}

// Cost per new source must not grow with the number of sources already seen.
func BenchmarkLimiterNewSources(b *testing.B) {
	tb := &limiterTable{}
	for i := 0; i < b.N; i++ {
		tb.get(fmt.Sprintf("10.%d.%d.%d", byte(i>>16), byte(i>>8), byte(i)), 5, 20)
	}
}
