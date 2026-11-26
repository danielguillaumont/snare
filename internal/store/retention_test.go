package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func hitAt(t *testing.T, s *Store, tok string, at time.Time) Event {
	t.Helper()
	_, ev, _, _, err := s.RecordHit(context.Background(), Event{TokenID: tok, Channel: "http", SourceIP: "192.0.2.1", At: at}, true)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestPurgeEvents(t *testing.T) {
	ctx := WithActor(context.Background(), "key_admin1")
	s := open(t)
	v := s.Tenant(DefaultTenant)
	_ = v.CreateToken(ctx, Token{ID: "tok_1", Kind: "canary_url", Label: "l"})
	_ = v.CreateToken(ctx, Token{ID: "tok_m", Kind: "canary_url", Label: "muted"})
	_ = v.SetTokenDisabled(ctx, "tok_m", true)

	now := time.Now()
	old, recent := now.Add(-40*24*time.Hour), now.Add(-time.Hour)
	oldOpen := hitAt(t, s, "tok_1", old)
	oldResolved := hitAt(t, s, "tok_1", old.Add(time.Second))
	oldFP := hitAt(t, s, "tok_1", old.Add(2*time.Second))
	oldMuted := hitAt(t, s, "tok_m", old)
	recentResolved := hitAt(t, s, "tok_1", recent)
	_ = v.TriageEvent(ctx, oldResolved.ID, StatusResolved, "")
	_ = v.TriageEvent(ctx, oldFP.ID, StatusFalsePositive, "")
	_ = v.TriageEvent(ctx, recentResolved.ID, StatusResolved, "")

	// Finish the old deliveries so they are not pending; the recent one stays queued.
	ob := s.Outbox()
	due, _ := ob.Due(ctx, now.Add(time.Hour), 100)
	for _, d := range due {
		if d.EventID != recentResolved.ID {
			if err := ob.MarkDelivered(ctx, d.ID, 1, now); err != nil {
				t.Fatal(err)
			}
		}
	}

	cutoff := now.Add(-30 * 24 * time.Hour)
	if n, _ := s.OpenExpired(ctx, cutoff); n != 1 {
		t.Fatalf("open expired = %d, want 1", n)
	}
	n, err := s.PurgeEvents(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("purged %d, want 3 (resolved, false positive, muted)", n)
	}
	left := map[int64]bool{}
	for _, tok := range []string{"tok_1", "tok_m"} {
		evs, _ := v.ListEvents(ctx, tok, 100)
		for _, e := range evs {
			left[e.ID] = true
		}
	}
	if !left[oldOpen.ID] || !left[recentResolved.ID] || len(left) != 2 {
		t.Fatalf("left after purge: %v (want old open %d and recent %d)", left, oldOpen.ID, recentResolved.ID)
	}
	var orphans int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM deliveries WHERE event_id NOT IN (SELECT id FROM events)`).Scan(&orphans)
	if orphans != 0 {
		t.Fatalf("%d deliveries left for purged events", orphans)
	}
	_ = oldMuted

	audit, _ := v.ListAudit(ctx, 20)
	var got []string
	for _, e := range audit {
		if e.Action == ActEventsPurge {
			got = append(got, e.Actor+" "+e.Detail)
		}
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "system ") || !strings.Contains(got[0], "events=3") {
		t.Fatalf("purge audit: %q", got)
	}

	// Nothing left to delete: no new audit record.
	if n, _ := s.PurgeEvents(ctx, cutoff); n != 0 {
		t.Fatalf("second purge deleted %d", n)
	}
	audit, _ = v.ListAudit(ctx, 20)
	var purges int
	for _, e := range audit {
		if e.Action == ActEventsPurge {
			purges++
		}
	}
	if purges != 1 {
		t.Fatalf("an empty purge was audited (%d records)", purges)
	}
}

func TestPurgeKeepsEventsWithPendingDeliveries(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	v := s.Tenant(DefaultTenant)
	_ = v.CreateToken(ctx, Token{ID: "tok_1", Kind: "canary_url", Label: "l"})
	ev := hitAt(t, s, "tok_1", time.Now().Add(-40*24*time.Hour))
	_ = v.TriageEvent(ctx, ev.ID, StatusResolved, "")
	// The alert never went out: the event is the only copy, so it waits for the outbox.
	if n, _ := s.PurgeEvents(ctx, time.Now()); n != 0 {
		t.Fatalf("purged an event whose alert is still pending (%d)", n)
	}
}

func TestPurgeIsPerTenantAudited(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	op := s.Operator()
	var ids []string
	for i, name := range []string{"acme", "globex"} {
		tn, err := op.CreateTenant(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, tn.ID)
		v := s.Tenant(tn.ID)
		tok := fmt.Sprintf("tok_%d", i)
		_ = v.CreateToken(ctx, Token{ID: tok, Kind: "canary_url", Label: "l"})
		ev := hitAt(t, s, tok, time.Now().Add(-40*24*time.Hour))
		if err := v.TriageEvent(ctx, ev.ID, StatusResolved, ""); err != nil {
			t.Fatal(err)
		}
	}
	ob := s.Outbox()
	due, _ := ob.Due(ctx, time.Now().Add(time.Hour), 100)
	for _, d := range due {
		_ = ob.MarkDelivered(ctx, d.ID, 1, time.Now())
	}
	if n, _ := s.PurgeEvents(ctx, time.Now().Add(-24*time.Hour)); n != 2 {
		t.Fatalf("purged %d, want 2", n)
	}
	for _, id := range ids {
		audit, _ := s.Tenant(id).ListAudit(ctx, 20)
		found := false
		for _, e := range audit {
			found = found || (e.Action == ActEventsPurge && strings.Contains(e.Detail, "events=1"))
		}
		if !found {
			t.Errorf("tenant %s has no purge record of its own", id)
		}
	}
}
