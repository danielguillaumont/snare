package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func hit(t *testing.T, s *Store, tok, ip string) (Event, bool) {
	t.Helper()
	_, ev, _, queued, err := s.RecordHit(context.Background(), Event{TokenID: tok, Channel: "http", SourceIP: ip, At: time.Now()}, true)
	if err != nil {
		t.Fatal(err)
	}
	return ev, queued
}

func TestDisabledTripwireRecordsMutedAndQueuesNothing(t *testing.T) {
	ctx := WithActor(context.Background(), "key_admin1")
	s := open(t)
	v := s.Tenant(DefaultTenant)
	_ = v.CreateToken(ctx, Token{ID: "tok_1", Kind: "canary_url", Label: "old fixture"})

	if err := v.SetTokenDisabled(ctx, "tok_1", true); err != nil {
		t.Fatal(err)
	}
	if tk, _ := v.GetToken(ctx, "tok_1"); !tk.Disabled {
		t.Fatal("token not reported disabled")
	}
	ev, queued := hit(t, s, "tok_1", "192.0.2.1")
	if queued || !ev.Muted {
		t.Fatalf("disabled tripwire: queued=%v muted=%v", queued, ev.Muted)
	}
	if due, _ := s.Outbox().Due(ctx, time.Now().Add(time.Hour), 10); len(due) != 0 {
		t.Fatalf("delivery queued for a muted touch: %+v", due)
	}
	evs, _ := v.ListEvents(ctx, "tok_1", 10)
	if len(evs) != 1 || !evs[0].Muted || evs[0].Status != StatusOpen {
		t.Fatalf("muted touch must still be recorded: %+v", evs)
	}

	// Disabling twice keeps the original time; enabling restores alerts.
	if err := v.SetTokenDisabled(ctx, "tok_1", true); err != nil {
		t.Fatal(err)
	}
	if err := v.SetTokenDisabled(ctx, "tok_1", false); err != nil {
		t.Fatal(err)
	}
	if ev, queued := hit(t, s, "tok_1", "192.0.2.2"); !queued || ev.Muted {
		t.Fatalf("re-enabled tripwire: queued=%v muted=%v", queued, ev.Muted)
	}
	if err := v.SetTokenDisabled(ctx, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing token: %v", err)
	}

	var acts []string
	audit, _ := v.ListAudit(ctx, 10)
	for _, e := range audit {
		if e.Target == "tok_1" {
			acts = append(acts, e.Action+"/"+e.Actor)
		}
	}
	want := "token.enable/key_admin1,token.disable/key_admin1,token.disable/key_admin1"
	if strings.Join(acts, ",") != want {
		t.Fatalf("audit: %v, want %s", acts, want)
	}
}

func TestTriageEvent(t *testing.T) {
	ctx := WithActor(context.Background(), "key_admin1")
	s := open(t)
	v := s.Tenant(DefaultTenant)
	_ = v.CreateToken(ctx, Token{ID: "tok_1", Kind: "canary_url", Label: "l"})
	ev, _ := hit(t, s, "tok_1", "192.0.2.1")
	hit(t, s, "tok_1", "192.0.2.2")

	if err := v.TriageEvent(ctx, ev.ID, "closed", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown status: %v", err)
	}
	if err := v.TriageEvent(ctx, ev.ID, StatusResolved, strings.Repeat("x", MaxTriageNote+1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long note: %v", err)
	}
	if err := v.TriageEvent(ctx, 99999, StatusResolved, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing event: %v", err)
	}
	const note = "red-team exercise, ticket SEC-118"
	if err := v.TriageEvent(ctx, ev.ID, StatusFalsePositive, note); err != nil {
		t.Fatal(err)
	}
	fp, _ := v.ListEventsFiltered(ctx, EventFilter{Status: StatusFalsePositive}, 10)
	if len(fp) != 1 || fp[0].ID != ev.ID || fp[0].TriageNote != note || fp[0].TriagedBy != "key_admin1" || fp[0].TriagedAt == nil {
		t.Fatalf("triaged event: %+v", fp)
	}
	if open, _ := v.ListEventsFiltered(ctx, EventFilter{Status: StatusOpen}, 10); len(open) != 1 || open[0].ID == ev.ID {
		t.Fatalf("open filter: %+v", open)
	}
	// Reopening is allowed.
	if err := v.TriageEvent(ctx, ev.ID, StatusOpen, ""); err != nil {
		t.Fatal(err)
	}

	// The audit log records the status and the note's size, never the note.
	audit, _ := v.ListAudit(ctx, 10)
	var details []string
	for _, e := range audit {
		if e.Action == ActEventTriage {
			details = append(details, e.Detail)
			if strings.Contains(e.Detail, "red-team") {
				t.Fatalf("note text in the audit log: %q", e.Detail)
			}
		}
	}
	if len(details) != 2 || details[1] != "status=false_positive note_bytes=33" {
		t.Fatalf("audit details: %q", details)
	}
}
