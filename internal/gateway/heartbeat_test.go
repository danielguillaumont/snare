package gateway

import (
	"strings"
	"testing"
)

// The gateway beats once at start with layer=heartbeat and its session, carrying no tool
// and no ledger, and doesn't beat without a heartbeat in its config (docs/M11-heartbeat.md).
func TestHeartbeatAtStart(t *testing.T) {
	cfg, _ := honeyConfig(t)
	cfg.Heartbeat = &Heartbeat{Token: "beattok", Every: "15m"}
	h := newHarness(t, cfg)
	r := h.callback()
	q := r.URL.Query()
	if !strings.HasSuffix(r.URL.Path, "/beattok") || q.Get("layer") != "heartbeat" || q.Get("session") != "stest01" {
		t.Fatalf("beat: %s", r.URL)
	}
	if q.Get("tool") != "" || q.Get("in0") != "" || q.Get("contain") != "" || len(q) != 2 {
		t.Fatalf("beat carries more than layer and session: %s", r.URL)
	}
	if r.UserAgent() != "snare-gateway/1" {
		t.Fatalf("ua %q", r.UserAgent())
	}
	// Traffic after the beat is unaffected, and no second beat arrives within the interval.
	h.listTools(1)
	h.noCallback()

	cfg2, _ := honeyConfig(t)
	newHarness(t, cfg2).noCallback()
}

func TestHeartbeatConfig(t *testing.T) {
	cfg, _ := honeyConfig(t)
	cfg.CallbackURL, cfg.Style = "https://cb.example", "catalog"
	for every, ok := range map[string]bool{"15m": true, "1m": true, "59s": false, "0": false, "soon": false, "": false} {
		cfg.Heartbeat = &Heartbeat{Token: "t", Every: every}
		if err := cfg.Validate(); (err == nil) != ok {
			t.Errorf("every %q: %v", every, err)
		}
	}
	cfg.Heartbeat = &Heartbeat{Every: "15m"}
	if err := cfg.Validate(); err == nil {
		t.Error("a heartbeat without a token was accepted")
	}
}
