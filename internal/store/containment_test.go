package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReleaseSessionIsAudited(t *testing.T) {
	ctx := WithActor(context.Background(), "key_admin1")
	h := newHitter(t)
	v := h.s.Tenant(DefaultTenant)
	// A session with touches but no containment can't be released: nothing was contained.
	h.hit("decoy", "198.51.100.1", "s0123456789ab", "", 0)
	if _, err := v.ReleaseSession(ctx, "s0123456789ab", "why"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("uncontained session: %v", err)
	}
	_, ev, _, _, err := h.s.RecordHit(ctx, Event{TokenID: "honey", Channel: "http", SourceIP: "198.51.100.1",
		Session: "s0123456789ab", Via: "egress", Containment: ContainBlocked, At: h.t0.Add(time.Minute)}, false)
	if err != nil || ev.Containment != ContainBlocked {
		t.Fatalf("contained touch: %+v %v", ev, err)
	}
	if evs, _ := v.ListEvents(ctx, "honey", 1); evs[0].Containment != ContainBlocked {
		t.Fatalf("read back: %+v", evs[0])
	}
	for _, bad := range []struct{ s, note string }{{"", "n"}, {"s0123456789ab", ""}, {"s0123456789ab", strings.Repeat("x", MaxTriageNote+1)}} {
		if _, err := v.ReleaseSession(ctx, bad.s, bad.note); !errors.Is(err, ErrInvalid) {
			t.Errorf("release(%q, %d-byte note): %v", bad.s, len(bad.note), err)
		}
	}
	n, err := v.ReleaseSession(ctx, "s0123456789ab", "INC-142: ticket removed")
	if err != nil || n != 1 {
		t.Fatalf("release: %d %v", n, err)
	}
	aud, _ := v.ListAudit(ctx, 1)
	if len(aud) != 1 || aud[0].Action != ActSessionRelease || aud[0].Target != "s0123456789ab" ||
		!strings.Contains(aud[0].Detail, "INC-142") || aud[0].Actor != "key_admin1" {
		t.Fatalf("audit: %+v", aud)
	}
}

func TestUnknownContainmentIsDropped(t *testing.T) {
	h := newHitter(t)
	_, ev, _, _, _ := h.s.RecordHit(h.ctx, Event{TokenID: "decoy", Channel: "http", SourceIP: "198.51.100.1", Containment: "killed", At: h.t0}, false)
	if ev.Containment != "" {
		t.Fatalf("containment %q stored", ev.Containment)
	}
}
