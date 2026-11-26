package store

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/seal"
)

func sealer(t *testing.T, b byte) *seal.Sealer {
	t.Helper()
	s, err := seal.New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rawLabel(t *testing.T, s *Store, id string) (label, memo string) {
	t.Helper()
	if err := s.db.QueryRow(`SELECT label, memo FROM tokens WHERE id = ?`, id).Scan(&label, &memo); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSealedLabelsRoundTripAndAreNotStoredInPlaintext(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if n, err := s.SealLabels(ctx, sealer(t, 1)); err != nil || n != 0 {
		t.Fatalf("empty store: %d %v", n, err)
	}
	v := s.Tenant(DefaultTenant)
	const label, memo = "billing-svc/.env: PAYMENTS_API_KEY", "planted by ops, ticket 812"
	if err := v.CreateToken(ctx, Token{ID: "tok_1", Kind: "honey_credential", Label: label, Memo: memo}); err != nil {
		t.Fatal(err)
	}
	_ = v.CreateToken(ctx, Token{ID: "tok_2", Kind: "canary_url", Label: "no memo"})

	rl, rm := rawLabel(t, s, "tok_1")
	if !strings.HasPrefix(rl, sealedPrefix) || !strings.HasPrefix(rm, sealedPrefix) ||
		strings.Contains(rl, "billing") || strings.Contains(rm, "ticket") {
		t.Fatalf("stored in the clear: %q %q", rl, rm)
	}
	if _, rm2 := rawLabel(t, s, "tok_2"); rm2 != "" {
		t.Fatalf("empty memo sealed: %q", rm2)
	}

	got, err := v.GetToken(ctx, "tok_1")
	if err != nil || got.Label != label || got.Memo != memo {
		t.Fatalf("GetToken: %+v %v", got, err)
	}
	list, _ := v.ListTokens(ctx)
	if len(list) != 2 {
		t.Fatalf("ListTokens: %+v", list)
	}
	for _, tk := range list {
		if strings.HasPrefix(tk.Label, sealedPrefix) {
			t.Fatalf("ListTokens returned a sealed label: %+v", tk)
		}
	}
	tok, ev, found, _, err := s.RecordHit(ctx, Event{TokenID: "tok_1", Channel: "http", SourceIP: "192.0.2.7", At: time.Now()}, true)
	if err != nil || !found || tok.Label != label {
		t.Fatalf("RecordHit: %+v %v", tok, err)
	}
	if tok2, _, _, err := s.Outbox().AlertData(ctx, ev.ID); err != nil || tok2.Label != label || tok2.Memo != memo {
		t.Fatalf("AlertData: %+v %v", tok2, err)
	}
	_, ev2, _, _, _ := s.RecordHit(ctx, Event{TokenID: "tok_2", Channel: "http", SourceIP: "192.0.2.7", At: time.Now()}, true)
	c, err := s.Outbox().Related(ctx, ev2, time.Hour, 5)
	if err != nil || c.Tripwires != 2 || len(c.Related) != 1 || c.Related[0].Label != label {
		t.Fatalf("Related: %+v %v", c, err)
	}
}

func TestSealLabelsMigratesPlaintextRowsOnce(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	v := s.Tenant(DefaultTenant)
	_ = v.CreateToken(ctx, Token{ID: "old_1", Kind: "x", Label: "legacy label", Memo: "legacy memo"})
	_ = v.CreateToken(ctx, Token{ID: "old_2", Kind: "x", Label: "legacy two"})
	if l, _ := rawLabel(t, s, "old_1"); l != "legacy label" {
		t.Fatalf("without a sealer labels are stored as written: %q", l)
	}
	sl := sealer(t, 2)
	if n, err := s.SealLabels(ctx, sl); err != nil || n != 2 {
		t.Fatalf("migrated %d, %v", n, err)
	}
	if l, m := rawLabel(t, s, "old_1"); !strings.HasPrefix(l, sealedPrefix) || !strings.HasPrefix(m, sealedPrefix) {
		t.Fatalf("not migrated: %q %q", l, m)
	}
	if n, err := s.SealLabels(ctx, sl); err != nil || n != 0 {
		t.Fatalf("second run sealed %d again, %v", n, err)
	}
	if got, _ := v.GetToken(ctx, "old_1"); got.Label != "legacy label" || got.Memo != "legacy memo" {
		t.Fatalf("after migration: %+v", got)
	}
}

// A sealed label is bound to its tenant and token: copying it onto another row, by a bug or
// by someone with write access, gives the placeholder, not the other tripwire's location.
func TestSealedLabelIsBoundToItsTokenAndTenant(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	if _, err := s.SealLabels(ctx, sealer(t, 3)); err != nil {
		t.Fatal(err)
	}
	op := s.Operator()
	ta, _ := op.CreateTenant(ctx, "A")
	tb, _ := op.CreateTenant(ctx, "B")
	a, b := s.Tenant(ta.ID), s.Tenant(tb.ID)
	_ = a.CreateToken(ctx, Token{ID: "tok_a", Kind: "x", Label: "A's secret placement"})
	_ = a.CreateToken(ctx, Token{ID: "tok_a2", Kind: "x", Label: "A's other"})
	_ = b.CreateToken(ctx, Token{ID: "tok_b", Kind: "x", Label: "B's"})
	sealedA, _ := rawLabel(t, s, "tok_a")
	for _, id := range []string{"tok_a2", "tok_b"} {
		if _, err := s.db.Exec(`UPDATE tokens SET label = ? WHERE id = ?`, sealedA, id); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := a.GetToken(ctx, "tok_a2"); got.Label != LabelUnreadable {
		t.Fatalf("moved within tenant: %q", got.Label)
	}
	if got, _ := b.GetToken(ctx, "tok_b"); got.Label != LabelUnreadable {
		t.Fatalf("moved across tenants: %q", got.Label)
	}
	if got, _ := a.GetToken(ctx, "tok_a"); got.Label != "A's secret placement" {
		t.Fatalf("original: %q", got.Label)
	}
}

// With the wrong key (or none), a touch is still recorded and still alerts; only the
// description is lost.
func TestWrongSealKeyStillRecordsAndAlerts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "s.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s1.SealLabels(ctx, sealer(t, 4))
	_ = s1.Tenant(DefaultTenant).CreateToken(ctx, Token{ID: "tok_1", Kind: "x", Label: "where it is", Memo: "m"})
	s1.Close()

	for name, setup := range map[string]func(*Store){
		"wrong key": func(s *Store) { _, _ = s.SealLabels(ctx, sealer(t, 5)) },
		"no key":    func(*Store) {},
	} {
		s, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		setup(s)
		tok, ev, found, queued, err := s.RecordHit(ctx, Event{TokenID: "tok_1", Channel: "http", SourceIP: "192.0.2.1", At: time.Now()}, true)
		if err != nil || !found || !queued || tok.Label != LabelUnreadable || tok.Memo != MemoUnreadable || tok.Kind != "x" {
			t.Fatalf("%s: %+v found=%v queued=%v %v", name, tok, found, queued, err)
		}
		if tok2, _, ok, err := s.Outbox().AlertData(ctx, ev.ID); err != nil || !ok || tok2.Label != LabelUnreadable {
			t.Fatalf("%s: AlertData %+v %v", name, tok2, err)
		}
		s.Close()
	}
}
