package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "snare.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestTokensAndEvents(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	v := s.Tenant(DefaultTenant)

	if err := v.CreateToken(ctx, Token{ID: "abc", Kind: "decoy_tool", Label: "support agent: export_customer_database"}); err != nil {
		t.Fatal(err)
	}
	if err := v.CreateToken(ctx, Token{ID: "abc", Kind: "x", Label: "dup"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate id must conflict, got %v", err)
	}
	got, err := v.GetToken(ctx, "abc")
	if err != nil || got.Kind != "decoy_tool" || got.CreatedAt.IsZero() || got.TenantID != DefaultTenant {
		t.Fatalf("GetToken: %+v %v", got, err)
	}
	if _, err := v.GetToken(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("missing: %v", err)
	}
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		tok, ev, found, _, err := s.RecordHit(ctx, Event{TokenID: "abc", Channel: "http", SourceIP: "203.0.113.5", Detail: "ua", At: now.Add(time.Duration(i) * time.Second)}, false)
		if err != nil || !found || tok.Label == "" || ev.ID == 0 || ev.TenantID != DefaultTenant {
			t.Fatalf("RecordHit: %+v %+v %v %v", tok, ev, found, err)
		}
	}
	evs, err := v.ListEvents(ctx, "abc", 2)
	if err != nil || len(evs) != 2 || evs[0].ID < evs[1].ID {
		t.Fatalf("ListEvents newest first, limited: %+v %v", evs, err)
	}
	since, err := v.EventsSince(ctx, now.Add(time.Second), 0)
	if err != nil || len(since) != 2 || since[0].At.After(since[1].At) {
		t.Fatalf("EventsSince oldest first: %+v %v", since, err)
	}
}

func TestUnregisteredTokenHitBelongsToNoTenant(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_, ev, found, _, err := s.RecordHit(ctx, Event{TokenID: "ghost", Channel: "dns", SourceIP: "198.51.100.1", At: time.Now()}, false)
	if err != nil || found || ev.TenantID != "" {
		t.Fatalf("got %+v found=%v err=%v", ev, found, err)
	}
	if evs, _ := s.Tenant(DefaultTenant).ListEvents(ctx, "", 0); len(evs) != 0 {
		t.Fatalf("orphan hit visible to default tenant: %+v", evs)
	}
	if evs, _ := s.Tenant("").ListEvents(ctx, "", 0); len(evs) != 1 {
		// Tenant("") is not reachable from any key (ids come from authentication); this only
		// documents where orphan events live.
		t.Fatalf("orphan should be stored under the empty tenant")
	}
}

// fixture: two tenants with one token, one event and one sink each.
type fixture struct {
	s    *Store
	a, b TenantStore
	dead map[string]int64 // tenant id -> one dead delivery
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	s := open(t)
	op := s.Operator()
	ta, _ := op.CreateTenant(ctx, "Acme")
	tb, _ := op.CreateTenant(ctx, "Beta")
	f := fixture{s: s, a: s.Tenant(ta.ID), b: s.Tenant(tb.ID), dead: map[string]int64{}}
	for _, x := range []struct {
		v  TenantStore
		id string
	}{{f.a, "tok_a"}, {f.b, "tok_b"}} {
		if err := x.v.CreateToken(ctx, Token{ID: x.id, Kind: "decoy_tool", Label: "label of " + x.id}); err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, err := s.RecordHit(ctx, Event{TokenID: x.id, Channel: "http", SourceIP: "203.0.113.9", At: time.Now()}, true); err != nil {
			t.Fatal(err)
		}
		if err := x.v.CreateSink(ctx, SinkRecord{ID: "sink_" + x.id, Type: "webhook", Config: []byte("sealed")}); err != nil {
			t.Fatal(err)
		}
	}
	// Each tenant gets one dead delivery to its own sink.
	ob := s.Outbox()
	markers, _ := ob.Due(ctx, time.Now().Add(time.Hour), 10)
	for _, m := range markers {
		_ = ob.Expand(ctx, m, []string{"sink_" + map[string]string{ta.ID: "tok_a", tb.ID: "tok_b"}[m.TenantID]}, time.Now())
	}
	rows, _ := ob.Due(ctx, time.Now().Add(time.Hour), 10)
	for _, d := range rows {
		_ = ob.MarkFailed(ctx, d.ID, 20, time.Now(), "connection refused", true, time.Now())
		f.dead[d.TenantID] = d.ID
	}
	if len(f.dead) != 2 {
		t.Fatalf("fixture deliveries: %+v", f.dead)
	}
	return f
}

// TestTenantIsolationMatrix is the M4 exit test at the store layer. Every TenantStore method
// must have a case; adding a method without one fails this test.
func TestTenantIsolationMatrix(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(t *testing.T, f fixture){
		"TenantID": func(t *testing.T, f fixture) {
			if f.a.TenantID() == f.b.TenantID() {
				t.Fatal("views share a tenant id")
			}
		},
		"CreateToken": func(t *testing.T, f fixture) {
			// Re-using B's token id from A must fail without revealing anything, and must not
			// move or alter B's token.
			if err := f.a.CreateToken(ctx, Token{ID: "tok_b", Kind: "x", Label: "hijack"}); !errors.Is(err, ErrConflict) {
				t.Fatalf("got %v", err)
			}
			if tb, err := f.b.GetToken(ctx, "tok_b"); err != nil || tb.Label != "label of tok_b" {
				t.Fatalf("B's token altered: %+v %v", tb, err)
			}
		},
		"GetToken": func(t *testing.T, f fixture) {
			if _, err := f.a.GetToken(ctx, "tok_b"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("A read B's token: %v", err)
			}
		},
		"ListTokens": func(t *testing.T, f fixture) {
			toks, _ := f.a.ListTokens(ctx)
			if len(toks) != 1 || toks[0].ID != "tok_a" {
				t.Fatalf("A sees %+v", toks)
			}
		},
		"ListEvents": func(t *testing.T, f fixture) {
			all, _ := f.a.ListEvents(ctx, "", 0)
			byB, _ := f.a.ListEvents(ctx, "tok_b", 0)
			if len(all) != 1 || all[0].TokenID != "tok_a" || len(byB) != 0 {
				t.Fatalf("A sees %+v / %+v", all, byB)
			}
		},
		"EventsSince": func(t *testing.T, f fixture) {
			evs, _ := f.a.EventsSince(ctx, time.Time{}, 0)
			if len(evs) != 1 || evs[0].TokenID != "tok_a" {
				t.Fatalf("A exports %+v", evs)
			}
		},
		"CreateSink": func(t *testing.T, f fixture) {
			if err := f.a.CreateSink(ctx, SinkRecord{ID: "sink_tok_b", Type: "webhook", Config: []byte("x")}); !errors.Is(err, ErrConflict) {
				t.Fatalf("got %v", err)
			}
			sb, _ := f.b.ListSinks(ctx)
			if len(sb) != 1 || string(sb[0].Config) != "sealed" {
				t.Fatalf("B's sink altered: %+v", sb)
			}
		},
		"ListSinks": func(t *testing.T, f fixture) {
			sa, _ := f.a.ListSinks(ctx)
			if len(sa) != 1 || sa[0].ID != "sink_tok_a" {
				t.Fatalf("A sees sinks %+v", sa)
			}
		},
		"ListAudit": func(t *testing.T, f fixture) {
			la, err := f.a.ListAudit(ctx, 100)
			if err != nil {
				t.Fatal(err)
			}
			// A's records: tenant create + sink create. None of B's.
			if len(la) != 2 {
				t.Fatalf("A sees %d audit records, want 2: %+v", len(la), la)
			}
			for _, e := range la {
				if e.TenantID != f.a.TenantID() || strings.Contains(e.Target, "tok_b") {
					t.Fatalf("A sees B's record %+v", e)
				}
			}
		},
		"ListDeliveries": func(t *testing.T, f fixture) {
			for _, state := range []string{"", DeliveryDead} {
				da, err := f.a.ListDeliveries(ctx, state, 100)
				if err != nil || len(da) != 1 || da[0].ID != f.dead[f.a.TenantID()] || da[0].TenantID != f.a.TenantID() {
					t.Fatalf("A sees deliveries %+v %v", da, err)
				}
			}
		},
		"RetryDelivery": func(t *testing.T, f fixture) {
			if err := f.a.RetryDelivery(ctx, f.dead[f.b.TenantID()]); !errors.Is(err, ErrNotFound) {
				t.Fatalf("A retried B's delivery: %v", err)
			}
			if db, _ := f.b.ListDeliveries(ctx, DeliveryDead, 10); len(db) != 1 {
				t.Fatal("B's dead delivery changed")
			}
			if err := f.a.RetryDelivery(ctx, f.dead[f.a.TenantID()]); err != nil {
				t.Fatalf("A can't retry its own: %v", err)
			}
		},
		"RelatedTouches": func(t *testing.T, f fixture) {
			// Both fixture events come from 203.0.113.9; each tenant sees only its own.
			eb, _ := f.b.ListEvents(ctx, "", 1)
			if _, err := f.a.RelatedTouches(ctx, eb[0], time.Hour, 10); !errors.Is(err, ErrNotFound) {
				t.Fatalf("A correlated B's event: %v", err)
			}
			forged := eb[0]
			forged.TenantID = f.a.TenantID() // claim B's event is A's
			c, err := f.a.RelatedTouches(ctx, forged, time.Hour, 10)
			for _, r := range c.Related {
				if r.TokenID == "tok_b" || strings.Contains(r.Label, "tok_b") {
					t.Fatalf("forged event exposed B's touch: %+v", r)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			// Another A touch from the same source sees A's earlier one, never B's.
			_ = f.a.CreateToken(ctx, Token{ID: "tok_a2", Kind: "x", Label: "second"})
			_, ev, _, _, _ := f.s.RecordHit(ctx, Event{TokenID: "tok_a2", Channel: "http", SourceIP: "203.0.113.9", At: time.Now()}, false)
			c, err = f.a.RelatedTouches(ctx, ev, time.Hour, 10)
			if err != nil || c.Tripwires != 2 || len(c.Related) != 1 || c.Related[0].TokenID != "tok_a" {
				t.Fatalf("A's own correlation: %+v %v", c, err)
			}
		},
		"ListHeartbeats": func(t *testing.T, f fixture) {
			for _, v := range []TenantStore{f.a, f.b} {
				id := "hb_" + v.TenantID()
				if err := v.CreateToken(ctx, Token{ID: id, Kind: KindHeartbeat, Label: "heartbeat"}); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, _, _, err := f.s.RecordHit(ctx, Event{TokenID: "hb_" + f.b.TenantID(), Channel: "dns", SourceIP: "203.0.113.9", At: time.Now()}, true); err != nil {
				t.Fatal(err)
			}
			if hs, _ := f.a.ListHeartbeats(ctx); len(hs) != 0 {
				t.Fatalf("A sees B's heartbeat: %+v", hs)
			}
			if hs, _ := f.b.ListHeartbeats(ctx); len(hs) != 1 || hs[0].Channel != BeatDNS {
				t.Fatalf("B's own: %+v", hs)
			}
		},
		"ReleaseSession": func(t *testing.T, f fixture) {
			if _, _, _, _, err := f.s.RecordHit(ctx, Event{TokenID: "tok_b", Channel: "http", SourceIP: "203.0.113.9",
				Session: "sb0000000001", Containment: ContainBlocked, At: time.Now()}, false); err != nil {
				t.Fatal(err)
			}
			if _, err := f.a.ReleaseSession(ctx, "sb0000000001", "not mine"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("A released B's session: %v", err)
			}
			if n, err := f.b.ReleaseSession(ctx, "sb0000000001", "INC-1 cleaned up"); err != nil || n != 1 {
				t.Fatalf("B's own release: %d %v", n, err)
			}
			if aud, _ := f.a.ListAudit(ctx, 50); len(aud) > 0 && aud[0].Action == ActSessionRelease {
				t.Fatal("B's release is in A's audit log")
			}
		},
		"ListIncidents": func(t *testing.T, f fixture) {
			// Both tenants' fixture touches share a source IP; each sees one incident, its own.
			ins, err := f.a.ListIncidents(ctx, 10)
			if err != nil || len(ins) != 1 || ins[0].Touches != 1 {
				t.Fatalf("A's incidents: %+v %v", ins, err)
			}
			ea, _ := f.a.ListEvents(ctx, "", 1)
			if ins[0].ID != ea[0].IncidentID {
				t.Fatalf("A listed incident %d, its event is in %d", ins[0].ID, ea[0].IncidentID)
			}
		},
		"GetIncident": func(t *testing.T, f fixture) {
			eb, _ := f.b.ListEvents(ctx, "", 1)
			if _, _, err := f.a.GetIncident(ctx, eb[0].IncidentID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("A read B's incident: %v", err)
			}
			in, evs, err := f.b.GetIncident(ctx, eb[0].IncidentID)
			if err != nil || in.ID != eb[0].IncidentID || len(evs) != 1 || evs[0].TokenID != "tok_b" {
				t.Fatalf("B's own incident: %+v %+v %v", in, evs, err)
			}
		},
		"ListEventsFiltered": func(t *testing.T, f fixture) {
			evs, err := f.a.ListEventsFiltered(ctx, EventFilter{TokenID: "tok_b"}, 10)
			if err != nil || len(evs) != 0 {
				t.Fatalf("A filtered on B's token: %+v %v", evs, err)
			}
			evs, _ = f.a.ListEventsFiltered(ctx, EventFilter{Status: StatusOpen}, 10)
			if len(evs) != 1 || evs[0].TokenID != "tok_a" {
				t.Fatalf("A's open events: %+v", evs)
			}
		},
		"SetTokenDisabled": func(t *testing.T, f fixture) {
			if err := f.a.SetTokenDisabled(ctx, "tok_b", true); !errors.Is(err, ErrNotFound) {
				t.Fatalf("A disabled B's token: %v", err)
			}
			if tb, _ := f.b.GetToken(ctx, "tok_b"); tb.Disabled {
				t.Fatal("B's token was disabled by A")
			}
		},
		"TriageEvent": func(t *testing.T, f fixture) {
			eb, _ := f.b.ListEvents(ctx, "", 1)
			if err := f.a.TriageEvent(ctx, eb[0].ID, StatusFalsePositive, "not mine"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("A triaged B's event: %v", err)
			}
			if eb2, _ := f.b.ListEvents(ctx, "", 1); eb2[0].Status != StatusOpen || eb2[0].TriageNote != "" {
				t.Fatalf("B's event changed: %+v", eb2[0])
			}
		},
		"DeleteSink": func(t *testing.T, f fixture) {
			if err := f.a.DeleteSink(ctx, "sink_tok_b"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("A deleted B's sink: %v", err)
			}
			if sb, _ := f.b.ListSinks(ctx); len(sb) != 1 {
				t.Fatal("B's sink gone")
			}
		},
	}
	it := reflect.TypeOf((*TenantStore)(nil)).Elem()
	for i := 0; i < it.NumMethod(); i++ {
		name := it.Method(i).Name
		c, ok := cases[name]
		if !ok {
			t.Errorf("TenantStore.%s has no cross-tenant case in this test", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c(t, f)
		})
	}
	if len(cases) != it.NumMethod() {
		t.Errorf("cases for methods that no longer exist: %d cases, %d methods", len(cases), it.NumMethod())
	}
}

// Every SQL statement in a tenant-view method must filter on tenant_id. This is a lint over
// the source, a second line of defence behind the behavioural matrix.
func TestTenantViewQueriesFilterOnTenant(t *testing.T) {
	src := readSource(t)
	for _, fn := range strings.Split(src, "\nfunc (v *tenantView) ")[1:] {
		body := fn
		if i := strings.Index(body, "\nfunc "); i >= 0 {
			body = body[:i]
		}
		name := body[:strings.Index(body, "(")]
		hasSQL := strings.Contains(body, "SELECT") || strings.Contains(body, "DELETE") ||
			strings.Contains(body, "UPDATE") || strings.Contains(body, "INSERT")
		if hasSQL && !strings.Contains(body, "tenant_id") {
			t.Errorf("tenantView.%s issues SQL without tenant_id", name)
		}
	}
}

func TestAPIKeys(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	op := s.Operator()
	tn, _ := op.CreateTenant(ctx, "Acme")
	plain, k, err := op.CreateAPIKey(ctx, tn.ID, RoleViewer)
	if err != nil || !strings.HasPrefix(plain, APIKeyPrefix) || len(plain) != len(APIKeyPrefix)+32 {
		t.Fatalf("key %q %v", plain, err)
	}
	if _, _, err := op.CreateAPIKey(ctx, "tn_missing", RoleAdmin); !errors.Is(err, ErrNotFound) {
		t.Fatalf("key for missing tenant: %v", err)
	}
	if _, _, err := op.CreateAPIKey(ctx, tn.ID, "root"); err == nil {
		t.Fatal("unknown role accepted")
	}
	// Only the hash is stored.
	var stored string
	_ = s.db.QueryRow(`SELECT hash FROM api_keys WHERE id = ?`, k.ID).Scan(&stored)
	if stored == plain || stored != HashKey(plain) {
		t.Fatal("plaintext key stored")
	}
	got, err := s.Authenticate(ctx, plain)
	if err != nil || got.TenantID != tn.ID || got.Role != RoleViewer {
		t.Fatalf("auth: %+v %v", got, err)
	}
	for _, bad := range []string{"", "snk_", plain + "x", strings.TrimPrefix(plain, APIKeyPrefix), HashKey(plain)} {
		if _, err := s.Authenticate(ctx, bad); !errors.Is(err, ErrNotFound) {
			t.Fatalf("accepted %q", bad)
		}
	}
	if !s.KeyActive(ctx, k.ID, tn.ID) || s.KeyActive(ctx, k.ID, DefaultTenant) {
		t.Fatal("KeyActive wrong")
	}
	_ = op.SetTenantDisabled(ctx, tn.ID, true)
	if _, err := s.Authenticate(ctx, plain); !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled tenant's key works")
	}
	_ = op.SetTenantDisabled(ctx, tn.ID, false)
	if err := op.RevokeAPIKey(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, plain); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked key works")
	}
	if s.KeyActive(ctx, k.ID, tn.ID) {
		t.Fatal("revoked key active")
	}
	if err := op.RevokeAPIKey(ctx, k.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("double revoke should be not found")
	}
}

// A pre-M4 database (no tenant columns) opens, and its rows land in the default tenant.
func TestMigratesPreM4Database(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE tokens (id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL, memo TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL)`,
		`CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, token_id TEXT NOT NULL, channel TEXT NOT NULL, source_ip TEXT NOT NULL, detail TEXT NOT NULL, at INTEGER NOT NULL)`,
		`INSERT INTO tokens VALUES ('old1', 'canary_url', 'old label', '', 1)`,
		`INSERT INTO events (token_id, channel, source_ip, detail, at) VALUES ('old1', 'http', '192.0.2.1', 'x', 2)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if tok, err := s.Tenant(DefaultTenant).GetToken(ctx, "old1"); err != nil || tok.Label != "old label" {
		t.Fatalf("token not migrated: %+v %v", tok, err)
	}
	if evs, _ := s.Tenant(DefaultTenant).ListEvents(ctx, "", 0); len(evs) != 1 {
		t.Fatalf("event not migrated: %+v", evs)
	}
	// Re-opening is idempotent.
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}

func readSource(t *testing.T) string {
	t.Helper()
	// Every non-test source file in the package, so tenant-view methods can't hide elsewhere.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
		all.WriteString("\n")
	}
	return all.String()
}

func TestFileDatabaseIsDurable(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var mode string
	var sync int
	_ = s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode)
	_ = s.db.QueryRow(`PRAGMA synchronous`).Scan(&sync)
	if mode != "wal" || sync != 2 { // 2 = FULL
		t.Fatalf("journal_mode=%s synchronous=%d, want wal and 2 (FULL)", mode, sync)
	}
}
