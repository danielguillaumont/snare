package alert

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
	"github.com/danielguillaumont/snare/internal/token"
)

// correlationEnv: tenants A and B, each with tokens; one operator sink that records alerts.
type correlationEnv struct {
	st   *store.Store
	p    *Pipeline
	ob   *Outbox
	sink *memSink
	a, b string
	t0   time.Time
	now  time.Time
}

func newCorrelationEnv(t *testing.T) *correlationEnv {
	t.Helper()
	ctx := context.Background()
	st := memStore(t)
	op := store.WithActor(ctx, "operator")
	ta, _ := st.Operator().CreateTenant(op, "A")
	tb, _ := st.Operator().CreateTenant(op, "B")
	for _, x := range []struct{ tn, id, label string }{
		{ta.ID, "a1", "payments .env"}, {ta.ID, "a2", "decoy export_customers"}, {ta.ID, "a3", "wiki canary"},
		{tb.ID, "b1", "B's honey key"},
	} {
		if err := st.Tenant(x.tn).CreateToken(ctx, store.Token{ID: x.id, Kind: "canary_url", Label: x.label}); err != nil {
			t.Fatal(err)
		}
	}
	e := &correlationEnv{st: st, sink: &memSink{}, a: ta.ID, b: tb.ID, t0: time.Unix(1_800_000_000, 0)}
	e.now = e.t0
	e.ob = fastOutbox(st, e.sink)
	e.p = &Pipeline{Store: st, Outbox: e.ob, Dedup: NewDedup(time.Minute), Log: quiet, Now: func() time.Time { return e.now }}
	return e
}

func (e *correlationEnv) touch(t *testing.T, after time.Duration, tok, channel, ip string) Alert {
	t.Helper()
	e.now = e.t0.Add(after)
	before := len(e.sink.alerts())
	if err := e.p.Hit(context.Background(), token.Match{ID: tok}, channel, ip, ""); err != nil {
		t.Fatal(err)
	}
	drain(t, e.ob)
	got := e.sink.alerts()
	if len(got) != before+1 {
		t.Fatalf("touch of %s produced %d alerts", tok, len(got)-before)
	}
	return got[len(got)-1]
}

func TestSecondTripwireFromSameSourceIsCritical(t *testing.T) {
	e := newCorrelationEnv(t)
	first := e.touch(t, 0, "a1", "http", "198.51.100.7")
	if first.SeverityID != 4 || first.Unmapped.CorrelatedTripwires != 1 || len(first.FindingInfo.RelatedEvents) != 0 {
		t.Fatalf("isolated touch: severity %d, correlated %d", first.SeverityID, first.Unmapped.CorrelatedTripwires)
	}
	second := e.touch(t, 10*time.Minute, "a2", "http", "198.51.100.7")
	if second.SeverityID != 5 || second.Severity != "Critical" || second.Unmapped.CorrelatedTripwires != 2 ||
		second.Unmapped.CorrelationWindow != "1h0m0s" {
		t.Fatalf("second tripwire: %+v / %+v", second.Unmapped, second.Severity)
	}
	rel := second.FindingInfo.RelatedEvents
	if len(rel) != 1 || rel[0].UID != first.FindingInfo.UID || rel[0].Title != "Tripwire touched: payments .env" {
		t.Fatalf("related events %+v", rel)
	}
	third := e.touch(t, 20*time.Minute, "a3", "dns", "198.51.100.7")
	if third.Unmapped.CorrelatedTripwires != 3 || len(third.FindingInfo.RelatedEvents) != 2 ||
		third.FindingInfo.RelatedEvents[0].UID != second.FindingInfo.UID { // newest first
		t.Fatalf("third: %+v %+v", third.Unmapped, third.FindingInfo.RelatedEvents)
	}
}

func TestCorrelationDoesNotEscalate(t *testing.T) {
	cases := map[string]func(t *testing.T, e *correlationEnv) Alert{
		"same tripwire twice": func(t *testing.T, e *correlationEnv) Alert {
			e.touch(t, 0, "a1", "http", "198.51.100.7")
			return e.touch(t, time.Minute, "a1", "dns", "198.51.100.7") // other channel, so not deduped
		},
		"different source": func(t *testing.T, e *correlationEnv) Alert {
			e.touch(t, 0, "a1", "http", "198.51.100.7")
			return e.touch(t, time.Minute, "a2", "http", "198.51.100.8")
		},
		"outside the window": func(t *testing.T, e *correlationEnv) Alert {
			e.touch(t, 0, "a1", "http", "198.51.100.7")
			return e.touch(t, 61*time.Minute, "a2", "http", "198.51.100.7")
		},
		"another tenant's touch from the same IP": func(t *testing.T, e *correlationEnv) Alert {
			e.touch(t, 0, "b1", "http", "198.51.100.7")
			return e.touch(t, time.Minute, "a1", "http", "198.51.100.7")
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newCorrelationEnv(t)
			a := c(t, e)
			if a.SeverityID != 4 || a.Unmapped.CorrelatedTripwires != 1 || len(a.FindingInfo.RelatedEvents) != 0 {
				t.Fatalf("escalated: severity %d, correlated %d, related %+v", a.SeverityID,
					a.Unmapped.CorrelatedTripwires, a.FindingInfo.RelatedEvents)
			}
			raw, _ := json.Marshal(a)
			if a.Metadata.TenantUID == e.a && strings.Contains(string(raw), "B's honey key") {
				t.Fatal("A's alert mentions B's tripwire")
			}
		})
	}
}

// A retry rebuilds the alert from the store. Touches recorded after the event must not
// change it, so every attempt sends the same body.
func TestCorrelationIsStableAcrossRetries(t *testing.T) {
	ctx := context.Background()
	e := newCorrelationEnv(t)
	e.touch(t, 0, "a1", "http", "198.51.100.7")
	e.touch(t, time.Minute, "a2", "http", "198.51.100.7")
	evs, _ := e.st.Tenant(e.a).ListEvents(ctx, "a2", 1)
	tok, _ := e.st.Tenant(e.a).GetToken(ctx, "a2")
	before, _ := Build(ctx, e.st, tok, evs[0], time.Hour)
	e.touch(t, 2*time.Minute, "a3", "http", "198.51.100.7")
	after, _ := Build(ctx, e.st, tok, evs[0], time.Hour)
	b1, _ := json.Marshal(before)
	b2, _ := json.Marshal(after)
	if string(b1) != string(b2) {
		t.Fatalf("rebuilt alert changed:\n%s\n%s", b1, b2)
	}
}

func TestCorrelatedAlertIsStillOCSF(t *testing.T) {
	a := sampleAlert()
	a.Correlate([]store.RelatedTouch{{EventID: 3, TokenID: "other", Label: "x", At: time.UnixMilli(1)}}, 2, time.Hour)
	raw, _ := json.Marshal(a)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if doc["severity_id"].(float64) != 5 || doc["severity"] != ocsfEnums["severity_id"][5] {
		t.Fatalf("severity %v %v", doc["severity_id"], doc["severity"])
	}
	rel := doc["finding_info"].(map[string]any)["related_events"].([]any)
	if uid, _ := rel[0].(map[string]any)["uid"].(string); uid != "snare-other-3" {
		t.Fatalf("related_event.uid (required by OCSF) = %q", uid)
	}
}
