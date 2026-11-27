package store

import (
	"testing"
	"time"
)

// docs/M17-tool-integrity.md §3: an integrity_signal touch is a warning at ingest/steered,
// is never queued, and makes a later decoy touch in the session Critical.
func TestIntegrityIsASteeredWarning(t *testing.T) {
	h := newHitter(t)
	v := h.s.Tenant(DefaultTenant)
	if err := v.CreateToken(h.ctx, Token{ID: "int", Kind: KindIntegrity, Label: "gateway integrity"}); err != nil {
		t.Fatal(err)
	}
	sess := "s0123456789ab"
	_, w, _, queued, err := h.s.RecordHit(h.ctx, Event{TokenID: "int", Channel: "http", SourceIP: "198.51.100.1",
		Session: sess, At: h.t0}, true)
	if err != nil || queued || !w.Warning || w.Layer != LayerIngest || w.Stage != StageSteered {
		t.Fatalf("integrity warning: %+v queued %v err %v", w, queued, err)
	}
	_, d, _, queued, err := h.s.RecordHit(h.ctx, Event{TokenID: "decoy", Channel: "http", SourceIP: "198.51.100.1",
		Session: sess, At: h.t0.Add(time.Minute)}, true)
	if err != nil || !queued || d.IncidentID != w.IncidentID {
		t.Fatalf("decoy: %+v queued %v err %v", d, queued, err)
	}
	c, _ := h.s.Outbox().Related(h.ctx, d, time.Hour, 10)
	if crit, why := c.Critical(d.Stage); !crit {
		t.Fatalf("decoy after a tool change not Critical: %+v %s", c, why)
	}
	for kind, want := range map[string]bool{KindExposure: true, KindIntegrity: true, KindHeartbeat: false, "decoy_tool": false, "honey_credential": false} {
		if IsWarningKind(kind) != want {
			t.Errorf("IsWarningKind(%s) = %v", kind, !want)
		}
	}
}
