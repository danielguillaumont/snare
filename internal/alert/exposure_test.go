package alert

import (
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

// An exposure warning is Low and stays Low, whatever came before it (docs/M16-early-warning.md §2).
func TestWarningIsLowAndNeverEscalates(t *testing.T) {
	tok := store.Token{ID: "exp", Kind: store.KindExposure, Label: "gateway exposure: gw.json"}
	ev := store.Event{ID: 3, TokenID: "exp", Channel: "http", At: time.Unix(1_800_000_000, 0), Warning: true,
		Layer: store.LayerData, Stage: store.StageCollection}
	a := New(tok, ev)
	if a.SeverityID != 2 || a.Severity != "Low" || !a.Unmapped.Warning {
		t.Fatalf("warning: %d %s %+v", a.SeverityID, a.Severity, a.Unmapped)
	}
	a.Correlate(store.Correlation{Tripwires: 3, Touches: 3, Stages: []string{store.StageRecon, store.StageCollection}}, ev.Stage, time.Hour)
	if a.SeverityID != 2 || a.Unmapped.CriticalBecause != "" {
		t.Fatalf("warning escalated: %d %q", a.SeverityID, a.Unmapped.CriticalBecause)
	}
	if h := New(store.Token{ID: "h", Kind: "honey_credential"}, store.Event{ID: 4}); h.SeverityID != 4 || h.Unmapped.Warning {
		t.Fatalf("a plain touch changed: %d %+v", h.SeverityID, h.Unmapped)
	}
}

func TestIntegrityWarningSaysWhatChanged(t *testing.T) {
	a := New(store.Token{ID: "i", Kind: store.KindIntegrity, Label: "gateway integrity: gw.json"},
		store.Event{ID: 5, Warning: true, Layer: store.LayerIngest, Stage: store.StageSteered})
	if a.SeverityID != 2 || !strings.Contains(a.FindingInfo.Title, "Tool definition changed") || !strings.Contains(a.FindingInfo.Desc, "pins -accept") {
		t.Fatalf("%d %q %q", a.SeverityID, a.FindingInfo.Title, a.FindingInfo.Desc)
	}
}
