package alert

import (
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

func TestOCSFStatusFollowsTriage(t *testing.T) {
	tok := store.Token{ID: "tok_1", Kind: "canary_url", Label: "l"}
	for _, c := range []struct {
		status string
		muted  bool
		id     int
		name   string
		detail string
	}{
		{store.StatusOpen, false, 1, "New", ""},
		{"", false, 1, "New", ""}, // events stored before M4e
		{store.StatusAcknowledged, false, 2, "In Progress", "acknowledged"},
		{store.StatusResolved, false, 4, "Resolved", "resolved"},
		{store.StatusFalsePositive, false, 4, "Resolved", "false_positive"},
		{store.StatusOpen, true, 3, "Suppressed", "muted"},
		{store.StatusResolved, true, 3, "Suppressed", "muted"},
	} {
		a := New(tok, store.Event{ID: 7, TokenID: "tok_1", At: time.Now(), Status: c.status, Muted: c.muted})
		if a.StatusID != c.id || a.Status != c.name || a.StatusDetail != c.detail {
			t.Errorf("%s muted=%v: got %d %q %q", c.status, c.muted, a.StatusID, a.Status, a.StatusDetail)
		}
		if a.SeverityID != 4 {
			t.Errorf("triage must not change severity: %d", a.SeverityID)
		}
	}
}
