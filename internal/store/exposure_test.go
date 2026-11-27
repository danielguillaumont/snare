package store

import (
	"testing"
	"time"
)

// docs/M16-early-warning.md §4: an exposure_signal touch is a warning. It is stored and
// joins the session's incident, is never queued, and makes the next tripwire touch in that
// session Critical.
func TestExposureIsAWarningThatEscalates(t *testing.T) {
	h := newHitter(t)
	v := h.s.Tenant(DefaultTenant)
	if err := v.CreateToken(h.ctx, Token{ID: "exp", Kind: KindExposure, Label: "gateway exposure"}); err != nil {
		t.Fatal(err)
	}
	sess := "s0123456789ab"
	_, w, found, queued, err := h.s.RecordHit(h.ctx, Event{TokenID: "exp", Channel: "http", SourceIP: "198.51.100.1",
		Session: sess, At: h.t0}, true)
	if err != nil || !found || queued || !w.Warning || w.Muted || w.Layer != LayerData || w.Stage != StageCollection {
		t.Fatalf("warning: %+v found %v queued %v err %v", w, found, queued, err)
	}
	if due, _ := h.s.Outbox().Due(h.ctx, h.t0.Add(24*time.Hour), 100); len(due) != 0 {
		t.Fatalf("a warning was queued: %+v", due)
	}

	_, d, _, queued, err := h.s.RecordHit(h.ctx, Event{TokenID: "decoy", Channel: "http", SourceIP: "198.51.100.1",
		Session: sess, At: h.t0.Add(time.Minute)}, true)
	if err != nil || !queued || d.Warning || d.IncidentID != w.IncidentID {
		t.Fatalf("decoy touch: %+v queued %v err %v (warning incident %d)", d, queued, err, w.IncidentID)
	}
	c, err := h.s.Outbox().Related(h.ctx, d, time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	if crit, _ := c.Critical(d.Stage); !crit || len(c.Related) != 1 || c.Related[0].TokenID != "exp" {
		t.Fatalf("decoy after a warning: critical %v, %+v", crit, c)
	}
	evs, _ := v.ListEvents(h.ctx, "exp", 0)
	if len(evs) != 1 || !evs[0].Warning {
		t.Fatalf("warning not read back: %+v", evs)
	}
}

// Only the token's kind makes a warning: a honey value's touch is never one, whatever the
// callback carried (§2, the downgrade attack).
func TestHoneyTouchIsNeverAWarning(t *testing.T) {
	h := newHitter(t)
	for _, via := range []string{"", "use", "egress"} {
		_, ev, _, queued, err := h.s.RecordHit(h.ctx, Event{TokenID: "honey", Channel: "http", SourceIP: "203.0.113.9",
			Via: via, At: h.t0}, true)
		if err != nil || ev.Warning || !queued {
			t.Fatalf("via %q: %+v queued %v err %v", via, ev, queued, err)
		}
	}
}
