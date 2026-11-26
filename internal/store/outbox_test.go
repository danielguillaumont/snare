package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecordHitQueuesMarkerOnlyWhenAlerting(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_ = s.Tenant(DefaultTenant).CreateToken(ctx, Token{ID: "t1", Kind: "canary_url", Label: "l"})
	ob := s.Outbox()

	_, ev, _, queued, err := s.RecordHit(ctx, Event{TokenID: "t1", Channel: "http", SourceIP: "192.0.2.1", At: time.Now()}, false)
	if err != nil || queued {
		t.Fatalf("suppressed hit queued: %v %v", queued, err)
	}
	if due, _ := ob.Due(ctx, time.Now().Add(time.Minute), 10); len(due) != 0 {
		t.Fatalf("marker for a suppressed hit: %+v", due)
	}
	_, ev2, _, queued, err := s.RecordHit(ctx, Event{TokenID: "t1", Channel: "http", SourceIP: "192.0.2.1", At: time.Now()}, true)
	if err != nil || !queued || ev2.ID == ev.ID {
		t.Fatalf("alerting hit: %v %v", queued, err)
	}
	due, _ := ob.Due(ctx, time.Now().Add(time.Minute), 10)
	if len(due) != 1 || !due[0].IsMarker() || due[0].EventID != ev2.ID || due[0].TenantID != DefaultTenant {
		t.Fatalf("marker: %+v", due)
	}
}

func TestRecordHitShedsWhenOutboxFull(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	old := MaxPendingDeliveries
	MaxPendingDeliveries = 2
	t.Cleanup(func() { MaxPendingDeliveries = old })
	var queued []bool
	for i := 0; i < 3; i++ {
		_, _, _, q, err := s.RecordHit(ctx, Event{TokenID: "x", Channel: "dns", SourceIP: "192.0.2.1", At: time.Now()}, true)
		if err != nil {
			t.Fatal(err)
		}
		queued = append(queued, q)
	}
	if !queued[0] || !queued[1] || queued[2] {
		t.Fatalf("queued %v, want the third shed", queued)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	if n != 3 {
		t.Fatalf("a shed hit must still be stored: %d events", n)
	}
}

func TestExpandIsAtomicAndIdempotent(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	ob := s.Outbox()
	_, _, _, _, _ = s.RecordHit(ctx, Event{TokenID: "x", Channel: "http", SourceIP: "192.0.2.1", At: time.Now()}, true)
	m, _ := ob.Due(ctx, time.Now().Add(time.Minute), 10)
	now := time.Now()
	if err := ob.Expand(ctx, m[0], []string{"op:log", "op:webhook", "sk_1"}, now); err != nil {
		t.Fatal(err)
	}
	if err := ob.Expand(ctx, m[0], []string{"op:log", "sk_2"}, now); err != nil {
		t.Fatal(err)
	}
	rows, _ := ob.Due(ctx, now.Add(time.Minute), 10)
	if len(rows) != 3 {
		t.Fatalf("want 3 rows from the first expansion only, got %+v", rows)
	}
	for _, r := range rows {
		if r.IsMarker() || r.EventID != m[0].EventID || r.State != DeliveryPending {
			t.Fatalf("row %+v", r)
		}
	}
}

func TestDueOrderingAndRetrySchedule(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	ob := s.Outbox()
	_, _, _, _, _ = s.RecordHit(ctx, Event{TokenID: "x", Channel: "http", SourceIP: "192.0.2.1", At: time.Now()}, true)
	m, _ := ob.Due(ctx, time.Now().Add(time.Minute), 10)
	now := time.Now()
	_ = ob.Expand(ctx, m[0], []string{"a", "b"}, now)
	_, _, _, _, _ = s.RecordHit(ctx, Event{TokenID: "y", Channel: "http", SourceIP: "192.0.2.1", At: time.Now()}, true)

	rows, _ := ob.Due(ctx, now.Add(time.Minute), 10)
	if len(rows) != 3 || !rows[0].IsMarker() {
		t.Fatalf("markers must come first: %+v", rows)
	}
	// A failed row is not due until its next attempt.
	a := rows[1]
	_ = ob.MarkFailed(ctx, a.ID, 1, now.Add(30*time.Second), "503", false, now)
	rows, _ = ob.Due(ctx, now.Add(time.Second), 10)
	for _, r := range rows {
		if r.ID == a.ID {
			t.Fatal("row due before its next attempt")
		}
	}
	rows, _ = ob.Due(ctx, now.Add(31*time.Second), 10)
	found := false
	for _, r := range rows {
		if r.ID == a.ID {
			found = r.Attempts == 1 && r.LastError == "503"
		}
	}
	if !found {
		t.Fatal("row not due after its next attempt")
	}
}

func TestStatsPurgeAndRetry(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	ob := s.Outbox()
	_, _, _, _, _ = s.RecordHit(ctx, Event{TokenID: "x", Channel: "http", SourceIP: "192.0.2.1", At: time.Now()}, true)
	m, _ := ob.Due(ctx, time.Now().Add(time.Minute), 10)
	t0 := time.Now()
	_ = ob.Expand(ctx, m[0], []string{"a", "b", "c"}, t0)
	rows, _ := ob.Due(ctx, t0.Add(time.Minute), 10)
	_ = ob.MarkDelivered(ctx, rows[0].ID, 1, t0)
	_ = ob.MarkFailed(ctx, rows[1].ID, 20, t0, "gone", true, t0)

	st, err := ob.Stats(ctx, t0.Add(10*time.Second))
	if err != nil || st.Pending != 1 || st.Dead != 1 || st.OldestPending < 9*time.Second {
		t.Fatalf("stats %+v %v", st, err)
	}
	if n, _ := ob.Purge(ctx, t0.Add(time.Second)); n != 1 {
		t.Fatalf("purged %d, want the delivered row only", n)
	}

	// Retrying requires a dead row, and is audited.
	op := s.Operator()
	if err := op.RetryDelivery(WithActor(ctx, "operator"), rows[2].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retried a pending row: %v", err)
	}
	if err := op.RetryDelivery(WithActor(ctx, "operator"), rows[1].ID); err != nil {
		t.Fatal(err)
	}
	dead, _ := op.ListDeliveries(ctx, DeliveryDead, 10)
	if len(dead) != 0 {
		t.Fatalf("still dead: %+v", dead)
	}
	audit, _ := op.ListAudit(ctx, "", 10)
	if len(audit) == 0 || audit[0].Action != ActDeliveryRetry || audit[0].Actor != "operator" {
		t.Fatalf("retry not audited: %+v", audit)
	}
	if _, _, err := op.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAlertDataSurvivesMissingToken(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_, ev, _, _, _ := s.RecordHit(ctx, Event{TokenID: "ghost", Channel: "dns", SourceIP: "192.0.2.1", Detail: "q", At: time.Now()}, true)
	_, got, found, err := s.Outbox().AlertData(ctx, ev.ID)
	if err != nil || found || got.Detail != "q" {
		t.Fatalf("%+v %v %v", got, found, err)
	}
	if _, _, _, err := s.Outbox().AlertData(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing event: %v", err)
	}
}

func TestTenantDoesNotSeeOperatorDeliveries(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_ = s.Tenant(DefaultTenant).CreateToken(ctx, Token{ID: "t1", Kind: "canary_url", Label: "l"})
	ob := s.Outbox()
	_, _, _, _, _ = s.RecordHit(ctx, Event{TokenID: "t1", Channel: "http", SourceIP: "192.0.2.1", At: time.Now()}, true)
	m, _ := ob.Due(ctx, time.Now().Add(time.Minute), 10)
	_ = ob.Expand(ctx, m[0], []string{"op:webhook", "sk_own"}, time.Now())
	rows, _ := ob.Due(ctx, time.Now().Add(time.Minute), 10)
	for _, r := range rows {
		_ = ob.MarkFailed(ctx, r.ID, 20, time.Now(), "down", true, time.Now())
	}
	v := s.Tenant(DefaultTenant)
	got, _ := v.ListDeliveries(ctx, "", 10)
	if len(got) != 1 || got[0].SinkRef != "sk_own" {
		t.Fatalf("tenant sees %+v", got)
	}
	for _, r := range rows {
		if r.SinkRef == "op:webhook" {
			if err := v.RetryDelivery(ctx, r.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("tenant retried the operator's delivery: %v", err)
			}
		}
	}
	if all, _ := s.Operator().ListDeliveries(ctx, "", 10); len(all) != 2 {
		t.Fatalf("operator sees %d", len(all))
	}
}
