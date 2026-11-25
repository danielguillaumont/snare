package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestTokensAndEvents(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "snare.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreateToken(ctx, Token{ID: "abc", Kind: "decoy_tool", Label: "support agent: export_customer_database"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, Token{ID: "abc", Kind: "x", Label: "dup"}); err == nil {
		t.Fatal("duplicate id must fail")
	}
	got, err := s.GetToken(ctx, "abc")
	if err != nil || got.Kind != "decoy_tool" || got.CreatedAt.IsZero() {
		t.Fatalf("GetToken: %+v %v", got, err)
	}
	if _, err := s.GetToken(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("missing: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	for i, ch := range []string{"http", "dns", "dns"} {
		if _, err := s.AddEvent(ctx, Event{TokenID: "abc", Channel: ch, SourceIP: "203.0.113.7", Detail: "d", At: now.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := s.ListEvents(ctx, "abc", 10)
	if err != nil || len(evs) != 3 || evs[0].Channel != "dns" || !evs[2].At.Equal(now) {
		t.Fatalf("ListEvents: %+v %v", evs, err)
	}
	if evs, _ := s.ListEvents(ctx, "other", 10); len(evs) != 0 {
		t.Fatal("filter by token failed")
	}
	toks, err := s.ListTokens(ctx)
	if err != nil || len(toks) != 1 {
		t.Fatalf("ListTokens: %v %v", toks, err)
	}
}

func TestMemory(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CreateToken(context.Background(), Token{ID: "m", Kind: "k", Label: "l"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetToken(context.Background(), "m"); err != nil {
		t.Fatal(err)
	}
}
