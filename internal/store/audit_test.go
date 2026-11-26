package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Each administrative change writes exactly one record, attributed to the actor in ctx, and
// never a secret value.
func TestAuditRecordsEachAction(t *testing.T) {
	s := open(t)
	op := s.Operator()
	ctx := WithActor(context.Background(), "operator")

	tn, _ := op.CreateTenant(ctx, "Acme")
	plain, k, _ := op.CreateAPIKey(ctx, tn.ID, RoleAdmin)
	_ = op.SetTenantDisabled(ctx, tn.ID, true)
	_ = op.SetTenantDisabled(ctx, tn.ID, false)
	tctx := WithActor(context.Background(), k.ID)
	v := s.Tenant(tn.ID)
	_ = v.CreateSink(tctx, SinkRecord{ID: "sk_1", Type: "splunk_hec", Config: []byte("SEALED-SECRET")})
	_ = v.DeleteSink(tctx, "sk_1")
	_ = s.Audit(tctx, tn.ID, ActSignIn, k.ID, "")
	_ = op.RevokeAPIKey(ctx, k.ID)

	// Failed changes leave no record.
	_ = v.DeleteSink(tctx, "sk_missing")
	_ = op.RevokeAPIKey(ctx, k.ID) // already revoked
	_ = op.SetTenantDisabled(ctx, "tn_missing", true)

	got, err := op.ListAudit(context.Background(), tn.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ action, actor, target string }{ // newest first
		{ActKeyRevoke, "operator", k.ID},
		{ActSignIn, k.ID, k.ID},
		{ActSinkDelete, k.ID, "sk_1"},
		{ActSinkCreate, k.ID, "sk_1"},
		{ActTenantEnable, "operator", tn.ID},
		{ActTenantDisable, "operator", tn.ID},
		{ActKeyIssue, "operator", k.ID},
		{ActTenantCreate, "operator", tn.ID},
	}
	if len(got) != len(want) {
		t.Fatalf("%d records, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		e := got[i]
		if e.Action != w.action || e.Actor != w.actor || e.Target != w.target || e.TenantID != tn.ID {
			t.Errorf("record %d = %+v, want %+v", i, e, w)
		}
		if strings.Contains(e.Detail, plain) || strings.Contains(e.Detail, "SEALED-SECRET") {
			t.Errorf("record %d leaks a secret: %q", i, e.Detail)
		}
	}
	if _, n, err := op.VerifyAudit(context.Background()); err != nil || n < len(want) {
		t.Fatalf("verify: n=%d err=%v", n, err)
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	build := func(t *testing.T) (*Store, *Operator) {
		s := open(t)
		op := s.Operator()
		ctx := WithActor(context.Background(), "operator")
		for _, n := range []string{"A", "B", "C", "D"} {
			if _, err := op.CreateTenant(ctx, n); err != nil {
				t.Fatal(err)
			}
		}
		return s, op
	}
	ctx := context.Background()

	_, op := build(t)
	head, n, err := op.VerifyAudit(ctx)
	if err != nil || n != 4 || len(head) != 64 {
		t.Fatalf("clean chain: head=%q n=%d err=%v", head, n, err)
	}

	tamper := map[string]struct {
		sql     string
		wantSeq int64
	}{
		"edit detail":      {`UPDATE audit_log SET detail = 'name=Evil' WHERE seq = 2`, 2},
		"edit actor":       {`UPDATE audit_log SET actor = 'ak_someone' WHERE seq = 3`, 3},
		"edit time":        {`UPDATE audit_log SET at = at + 1 WHERE seq = 1`, 1},
		"delete a record":  {`DELETE FROM audit_log WHERE seq = 2`, 3},
		"delete the first": {`DELETE FROM audit_log WHERE seq = 1`, 2},
	}
	for name, c := range tamper {
		t.Run(name, func(t *testing.T) {
			s, op := build(t)
			if _, err := s.db.Exec(c.sql); err != nil {
				t.Fatal(err)
			}
			_, _, err := op.VerifyAudit(ctx)
			var be *AuditBrokenError
			if !errors.As(err, &be) || be.Seq != c.wantSeq {
				t.Fatalf("got %v, want break at seq %d", err, c.wantSeq)
			}
		})
	}

	// Appending keeps the old head as a prefix: the new chain extends the recorded head.
	s, op2 := build(t)
	h1, _, _ := op2.VerifyAudit(ctx)
	_, _ = op2.CreateTenant(WithActor(ctx, "operator"), "E")
	var prev string
	_ = s.db.QueryRow(`SELECT prev_hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if prev != h1 {
		t.Fatal("new record does not chain onto the previous head")
	}
}

func TestAuditDefaultsActorToSystem(t *testing.T) {
	s := open(t)
	_, _ = s.Operator().CreateTenant(context.Background(), "X")
	got, _ := s.Operator().ListAudit(context.Background(), "", 10)
	if len(got) != 1 || got[0].Actor != "system" {
		t.Fatalf("%+v", got)
	}
}
