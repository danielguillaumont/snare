package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/store"
)

func TestPrintTimeline(t *testing.T) {
	t0 := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	d := admin.IncidentDetail{
		Incident: store.Incident{ID: 7, Session: "s0123456789ab", SourceIP: "198.51.100.1", FirstSeen: t0,
			LastSeen: t0.Add(time.Minute), Touches: 2, Tripwires: 2, Open: 2, Stages: []string{"recon", "exfiltration"}},
		Timeline: []admin.IncidentTouch{
			{Event: store.Event{ID: 7, At: t0, Stage: "recon", Layer: "tool", Status: "open"}, Kind: "decoy_tool", Label: "gateway decoy: export_customer_data"},
			{Event: store.Event{ID: 8, At: t0.Add(time.Minute), Stage: "exfiltration", Layer: "egress", Status: "open"}, Kind: "honey_credential", Label: "payments .env"},
		},
	}
	var b bytes.Buffer
	if err := printTimeline(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"incident 7  session s0123456789ab", "stages: recon > exfiltration", "2 touches of 2 tripwires"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if i, j := strings.Index(out, "export_customer_data"), strings.Index(out, "payments .env"); i < 0 || j < i {
		t.Errorf("timeline not in time order:\n%s", out)
	}
	b.Reset()
	_ = printIncidents(&b, []store.Incident{d.Incident})
	if !strings.Contains(b.String(), "recon > exfiltration") {
		t.Errorf("list:\n%s", b.String())
	}
}
