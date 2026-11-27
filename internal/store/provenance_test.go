package store

import (
	"fmt"
	"reflect"
	"testing"
)

// Inputs (docs/M9-provenance.md §2) are stored with the event, at most MaxInputs of them,
// newest kept, and read back unchanged by every event query.
func TestInputsAreStoredWithTheEvent(t *testing.T) {
	h := newHitter(t)
	v := h.s.Tenant(DefaultTenant)
	var ins []Input
	for i := 0; i < MaxInputs+2; i++ {
		ins = append(ins, Input{Tool: "read_file", Fingerprint: fmt.Sprintf("%016x", i), Length: i, AgeSeconds: 10 - i})
	}
	ins[len(ins)-1].Source = "tickets/T-42.md"
	_, ev, _, _, err := h.s.RecordHit(h.ctx, Event{TokenID: "decoy", Channel: "http", SourceIP: "198.51.100.1",
		Session: "s0123456789ab", Inputs: ins, At: h.t0}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := ins[2:]
	if !reflect.DeepEqual(ev.Inputs, want) {
		t.Fatalf("recorded: %+v", ev.Inputs)
	}
	evs, err := v.ListEvents(h.ctx, "decoy", 1)
	if err != nil || len(evs) != 1 || !reflect.DeepEqual(evs[0].Inputs, want) {
		t.Fatalf("read back: %+v %v", evs, err)
	}
	_, tl, err := v.GetIncident(h.ctx, ev.IncidentID)
	if err != nil || len(tl) != 1 || !reflect.DeepEqual(tl[0].Inputs, want) {
		t.Fatalf("timeline: %+v %v", tl, err)
	}
	// A touch without a ledger stores none.
	_, ev, _, _, _ = h.s.RecordHit(h.ctx, Event{TokenID: "decoy", Channel: "dns", SourceIP: "198.51.100.2", At: h.t0}, false)
	if evs, _ := v.ListEvents(h.ctx, "decoy", 1); evs[0].ID != ev.ID || evs[0].Inputs != nil {
		t.Fatalf("no ledger: %+v", evs[0])
	}
}
