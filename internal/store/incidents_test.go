package store

import (
	"context"
	"slices"
	"testing"
	"time"
)

// Every row of M7 §1, plus via overriding the kind and an unknown via being ignored.
func TestClassify(t *testing.T) {
	cases := []struct {
		kind, via, layer, stage string
	}{
		{"canary_instruction", "", LayerIngest, StageSteered},
		{"decoy_tool", "", LayerTool, StageRecon},
		{"honey_credential", "", LayerData, StageCollection},
		{"canary_doc", "", LayerData, StageCollection},
		{"canary_url", "", LayerData, StageCollection},
		{"other", "", LayerData, StageCollection},
		{"", "", LayerData, StageCollection}, // unregistered token
		{"honey_credential", "egress", LayerEgress, StageExfiltration},
		{"decoy_tool", "egress", LayerEgress, StageExfiltration},
		{"honey_credential", "use", LayerUse, StageUse},
		{"canary_url", "use", LayerUse, StageUse},
		{"decoy_tool", "tool", LayerTool, StageRecon},
		{"canary_doc", "exfiltration", LayerData, StageCollection}, // not a via: ignored
	}
	for _, c := range cases {
		l, s := Classify(c.kind, c.via)
		if l != c.layer || s != c.stage {
			t.Errorf("Classify(%q, %q) = %s, %s; want %s, %s", c.kind, c.via, l, s, c.layer, c.stage)
		}
	}
	for i, s := range Stages {
		if StageRank(s) != i {
			t.Errorf("rank of %s", s)
		}
	}
	if StageRank("") != -1 || StageRank("bogus") != -1 {
		t.Error("unknown stages must rank -1")
	}
}

type hitter struct {
	t   *testing.T
	s   *Store
	ctx context.Context
	t0  time.Time
}

func newHitter(t *testing.T) hitter {
	s := open(t)
	v := s.Tenant(DefaultTenant)
	for id, kind := range map[string]string{"decoy": "decoy_tool", "honey": "honey_credential", "doc": "canary_doc"} {
		if err := v.CreateToken(context.Background(), Token{ID: id, Kind: kind, Label: id}); err != nil {
			t.Fatal(err)
		}
	}
	return hitter{t: t, s: s, ctx: context.Background(), t0: time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)}
}

func (h hitter) hit(tok, ip, session, via string, after time.Duration) Event {
	h.t.Helper()
	_, ev, _, _, err := h.s.RecordHit(h.ctx, Event{TokenID: tok, Channel: "http", SourceIP: ip, Session: session, Via: via, At: h.t0.Add(after)}, false)
	if err != nil {
		h.t.Fatal(err)
	}
	return ev
}

func TestIncidentGroupsBySessionThenIP(t *testing.T) {
	h := newHitter(t)
	a := h.hit("decoy", "198.51.100.1", "s0123456789ab", "", 0)
	if a.IncidentID != a.ID || a.Layer != LayerTool || a.Stage != StageRecon || a.Session != "s0123456789ab" {
		t.Fatalf("first touch: %+v", a)
	}
	// Same session from another IP joins; the session is the key.
	b := h.hit("honey", "203.0.113.7", "s0123456789ab", "egress", 5*time.Minute)
	if b.IncidentID != a.ID || b.Stage != StageExfiltration {
		t.Fatalf("same session, other IP: %+v", b)
	}
	// No session: keyed by IP, so a touch from the first IP without a session is apart.
	c := h.hit("doc", "198.51.100.1", "", "", 6*time.Minute)
	if c.IncidentID == a.ID || c.IncidentID != c.ID {
		t.Fatalf("no session should key on IP, not join the session incident: %+v", c)
	}
	d := h.hit("decoy", "198.51.100.1", "", "", 7*time.Minute)
	if d.IncidentID != c.ID {
		t.Fatalf("same IP, no session: %+v", d)
	}
	// Stored and read back.
	evs, _ := h.s.Tenant(DefaultTenant).ListEvents(h.ctx, "honey", 1)
	if evs[0].IncidentID != a.ID || evs[0].Layer != LayerEgress || evs[0].Session != "s0123456789ab" {
		t.Fatalf("read back: %+v", evs[0])
	}
}

func TestIncidentGapRule(t *testing.T) {
	h := newHitter(t)
	a := h.hit("decoy", "198.51.100.1", "", "", 0)
	b := h.hit("doc", "198.51.100.1", "", "", 59*time.Minute)
	if b.IncidentID != a.ID {
		t.Fatalf("59 minutes later should join: %+v", b)
	}
	// The gap counts from the previous touch, not the first: 118 minutes in, 59 after b.
	c := h.hit("honey", "198.51.100.1", "", "", 118*time.Minute)
	if c.IncidentID != a.ID {
		t.Fatalf("59 minutes after the previous touch should join: %+v", c)
	}
	d := h.hit("decoy", "198.51.100.1", "", "", 179*time.Minute)
	if d.IncidentID == a.ID || d.IncidentID != d.ID {
		t.Fatalf("61 minutes after the previous touch should start a new incident: %+v", d)
	}
}

func TestTwoSessionsFromOneIPStayApart(t *testing.T) {
	h := newHitter(t)
	a := h.hit("decoy", "198.51.100.1", "s000000000001", "", 0)
	b := h.hit("decoy", "198.51.100.1", "s000000000002", "", time.Minute)
	if a.IncidentID == b.IncidentID {
		t.Fatal("two gateway sessions behind one NAT were merged")
	}
}

func TestIncidentsNeverSpanTenants(t *testing.T) {
	f := newFixture(t) // two tenants, one touch each, same IP, seconds apart
	ea, _ := f.a.ListEvents(context.Background(), "", 1)
	eb, _ := f.b.ListEvents(context.Background(), "", 1)
	if ea[0].IncidentID == 0 || ea[0].IncidentID == eb[0].IncidentID {
		t.Fatalf("incidents: A %d, B %d", ea[0].IncidentID, eb[0].IncidentID)
	}
}

func TestCorrelationWithinIncident(t *testing.T) {
	h := newHitter(t)
	sess := "s0123456789ab"
	h.hit("decoy", "198.51.100.1", sess, "", 0)
	h.hit("honey", "198.51.100.1", sess, "", time.Minute) // base URL fetched: collection
	// A touch from another IP without a session is in neither the incident nor the source.
	h.hit("doc", "192.0.2.50", "", "", 2*time.Minute)
	last := h.hit("honey", "203.0.113.7", sess, "egress", 3*time.Minute) // same session, new IP

	c, err := h.s.Outbox().Related(h.ctx, last, time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	if c.Touches != 3 || c.Tripwires != 2 || len(c.Related) != 1 || c.Related[0].TokenID != "decoy" {
		t.Fatalf("correlation: %+v", c)
	}
	if want := []string{StageRecon, StageCollection, StageExfiltration}; !slices.Equal(c.Stages, want) {
		t.Fatalf("stages %v, want %v", c.Stages, want)
	}
	// Retried later, after more touches: the same answer.
	h.hit("doc", "203.0.113.7", sess, "", 4*time.Minute)
	again, _ := h.s.Outbox().Related(h.ctx, last, time.Hour, 10)
	if again.Touches != c.Touches || again.Tripwires != c.Tripwires || !slices.Equal(again.Stages, c.Stages) {
		t.Fatalf("retry differs: %+v vs %+v", again, c)
	}

	ins, err := h.s.Tenant(DefaultTenant).ListIncidents(h.ctx, 10)
	if err != nil || len(ins) != 2 {
		t.Fatalf("incidents: %+v %v", ins, err)
	}
	in := ins[0] // the session's incident was active last
	if in.Session != sess || in.Touches != 4 || in.Tripwires != 3 || in.Open != 4 || in.SourceIP != "198.51.100.1" ||
		!slices.Equal(in.Stages, []string{StageRecon, StageCollection, StageExfiltration}) ||
		!in.FirstSeen.Equal(h.t0) || !in.LastSeen.Equal(h.t0.Add(4*time.Minute)) {
		t.Fatalf("incident summary: %+v", in)
	}
	got, evs, err := h.s.Tenant(DefaultTenant).GetIncident(h.ctx, in.ID)
	if err != nil || got.ID != in.ID || len(evs) != 4 || evs[0].TokenID != "decoy" || evs[2].Stage != StageExfiltration {
		t.Fatalf("GetIncident: %+v %+v %v", got, evs, err)
	}
	if _, _, err := h.s.Tenant(DefaultTenant).GetIncident(h.ctx, 0); err != ErrNotFound {
		t.Fatalf("incident 0 (pre-M7 events) must not be readable as one: %v", err)
	}
}

// The session id arrives in the callback query, so whoever holds a token chooses it. A
// fresh session per touch splits incidents but must not hide the correlation by source.
func TestForgedSessionsCannotHideCorrelation(t *testing.T) {
	h := newHitter(t)
	h.hit("decoy", "198.51.100.1", "s000000000001", "", 0)
	b := h.hit("doc", "198.51.100.1", "s000000000002", "", time.Minute)
	if c, _ := h.s.Outbox().Related(h.ctx, b, time.Hour, 10); c.Tripwires != 2 {
		t.Fatalf("two tripwires from one source, under two sessions: %+v", c)
	}
	c := h.hit("honey", "198.51.100.1", "s000000000003", "", 2*time.Hour)
	if r, _ := h.s.Outbox().Related(h.ctx, c, time.Hour, 10); r.Tripwires != 1 {
		t.Fatalf("outside the window and in no shared incident: %+v", r)
	}
}

// Events recorded before M7 have no incident; their correlation falls back to the source IP
// within the window, as before.
func TestPreM7EventsKeepIPCorrelation(t *testing.T) {
	h := newHitter(t)
	a := h.hit("decoy", "198.51.100.1", "", "", 0)
	b := h.hit("doc", "198.51.100.1", "", "", time.Minute)
	if _, err := h.s.db.Exec(`UPDATE events SET incident_id = 0, incident_key = '', stage = '', layer = ''`); err != nil {
		t.Fatal(err)
	}
	b.IncidentID, b.Stage = 0, ""
	c, err := h.s.Outbox().Related(h.ctx, b, time.Hour, 10)
	if err != nil || c.Tripwires != 2 || len(c.Related) != 1 || c.Related[0].EventID != a.ID || len(c.Stages) != 0 {
		t.Fatalf("fallback: %+v %v", c, err)
	}
	// A new touch after the upgrade starts an incident rather than joining incident 0.
	n := h.hit("honey", "198.51.100.1", "", "", 2*time.Minute)
	if n.IncidentID != n.ID {
		t.Fatalf("post-upgrade touch: %+v", n)
	}
}
