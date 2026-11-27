package store

import (
	"testing"
	"time"
)

// A heartbeat touch updates its tenant's record for the channel and nothing else: no event,
// no incident, no outbox row, even with alert requested (docs/M11-heartbeat.md §1).
func TestHeartbeatIsNotAnEvent(t *testing.T) {
	h := newHitter(t)
	v := h.s.Tenant(DefaultTenant)
	if err := v.CreateToken(h.ctx, Token{ID: "hb", Kind: KindHeartbeat, Label: "server heartbeat"}); err != nil {
		t.Fatal(err)
	}
	before, _ := v.ListEvents(h.ctx, "", 0)
	due0, _ := h.s.Outbox().Due(h.ctx, h.t0.Add(24*time.Hour), 100)
	beats := []Event{
		{Channel: "http", SourceIP: "198.51.100.1", At: h.t0},
		{Channel: "http", SourceIP: "198.51.100.2", At: h.t0.Add(time.Minute)},
		{Channel: "http", SourceIP: "198.51.100.3", At: h.t0.Add(30 * time.Second)}, // late arrival
		{Channel: "dns", SourceIP: "198.51.100.4", At: h.t0.Add(2 * time.Minute)},
		{Channel: "http", SourceIP: "198.51.100.5", Session: "s0123456789ab", At: h.t0.Add(3 * time.Minute)},
	}
	for _, e := range beats {
		e.TokenID = "hb"
		tok, ev, found, queued, err := h.s.RecordHit(h.ctx, e, true)
		if err != nil || !found || queued || ev.ID != 0 || tok.Kind != KindHeartbeat {
			t.Fatalf("beat %+v: tok %+v ev %+v found %v queued %v err %v", e, tok, ev, found, queued, err)
		}
	}
	if after, _ := v.ListEvents(h.ctx, "", 0); len(after) != len(before) {
		t.Fatalf("heartbeats became events: %d -> %d", len(before), len(after))
	}
	if ins, _ := v.ListIncidents(h.ctx, 10); len(ins) != 0 {
		t.Fatalf("incidents: %+v", ins)
	}
	if due, _ := h.s.Outbox().Due(h.ctx, h.t0.Add(24*time.Hour), 100); len(due) != len(due0) {
		t.Fatalf("outbox rows: %d -> %d", len(due0), len(due))
	}
	hs, err := v.ListHeartbeats(h.ctx)
	if err != nil || len(hs) != 3 {
		t.Fatalf("heartbeats: %+v %v", hs, err)
	}
	got := map[string]Heartbeat{}
	for _, b := range hs {
		got[b.Channel] = b
	}
	if b := got[BeatHTTP]; b.Count != 3 || !b.LastAt.Equal(h.t0.Add(time.Minute)) || b.LastSource != "198.51.100.3" {
		t.Errorf("http: %+v", b) // newest time kept, even when a late beat arrives last
	}
	if b := got[BeatDNS]; b.Count != 1 || b.LastSource != "198.51.100.4" {
		t.Errorf("dns: %+v", b)
	}
	if b := got[BeatGateway]; b.Count != 1 || b.LastSource != "s0123456789ab" {
		t.Errorf("gateway: %+v", b)
	}
	latest, err := h.s.LatestHeartbeats(h.ctx)
	if err != nil || len(latest) != 3 || !latest[BeatGateway].Equal(h.t0.Add(3*time.Minute)) {
		t.Fatalf("latest: %+v %v", latest, err)
	}
}

func TestBeatPolicy(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	hs := []Heartbeat{
		{Channel: BeatGateway, LastAt: now.Add(-50 * time.Minute)},
		{Channel: BeatHTTP, LastAt: now.Add(-2 * time.Minute)},
		{Channel: BeatHTTP + "x", LastAt: now}, // unknown channels are not shown
	}
	got := BeatPolicy{Expected: []string{BeatHTTP, BeatDNS}}.Status(hs, now)
	want := []struct {
		ch, state string
		age       int64
	}{{BeatHTTP, BeatOK, 120}, {BeatDNS, BeatNever, -1}, {BeatGateway, BeatStale, 3000}}
	if len(got) != len(want) {
		t.Fatalf("status: %+v", got)
	}
	for i, w := range want {
		if got[i].Channel != w.ch || got[i].State != w.state || got[i].AgeSeconds != w.age {
			t.Errorf("%d: %+v, want %+v", i, got[i], w)
		}
	}
	// A custom limit, and a channel neither expected nor seen is absent.
	got = BeatPolicy{StaleAfter: time.Hour}.Status(hs, now)
	if len(got) != 2 || got[1].Channel != BeatGateway || got[1].State != BeatOK {
		t.Fatalf("custom: %+v", got)
	}
	// A beat from the future (clock skew) is fresh, not negative.
	if got := (BeatPolicy{}).Status([]Heartbeat{{Channel: BeatDNS, LastAt: now.Add(time.Minute)}}, now); got[0].AgeSeconds != 0 || got[0].State != BeatOK {
		t.Fatalf("skew: %+v", got)
	}
}
