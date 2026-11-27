package gateway

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/token"
)

// honeyConfig returns a config that recognizes one honey value, and the value.
func honeyConfig(t *testing.T) (Config, string) {
	t.Helper()
	s, _ := token.NewSigner(bytes.Repeat([]byte{9}, 32))
	honey, id, _ := s.Mint()
	bodies, _ := s.Bodies(id)
	const salt = "gateway-test-salt-01"
	cfg := Config{Salt: salt, Decoys: map[string]string{"list_api_keys": "decoytok"}}
	for _, b := range bodies {
		cfg.Fingerprints = append(cfg.Fingerprints, token.Fingerprint(salt, b))
	}
	return cfg, honey
}

func call(id int, tool, args string) string {
	return `{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}` + "\n"
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

// listTools runs one tools/list round trip, which fixes the decoy names.
func (h *harness) listTools(id int) {
	h.t.Helper()
	h.client(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/list"}` + "\n")
	h.serverGets()
	h.server(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"result":{"tools":[{"name":"send_email"},{"name":"read_file"}]}}` + "\n")
	h.clientGets()
}

// noServer asserts the real server received nothing.
func (h *harness) noServer() {
	h.t.Helper()
	select {
	case l := <-h.serverRecv:
		h.t.Fatalf("server received %q", l)
	case <-time.After(150 * time.Millisecond):
	}
}

// failed asserts line is the contained tool error for id, and returns its text.
func failed(t *testing.T, line string, id int) string {
	t.Helper()
	var r struct {
		ID     int `json:"id"`
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &r); err != nil || r.ID != id || !r.Result.IsError || len(r.Result.Content) != 1 {
		t.Fatalf("want a tool error for id %d, got %q", id, line)
	}
	return r.Result.Content[0].Text
}

func TestContainmentBlocksTheLeakAndFreezes(t *testing.T) {
	cfg, honey := honeyConfig(t)
	state := filepath.Join(t.TempDir(), "gw.json.frozen")
	cfg.Contain = &Contain{StateFile: state} // at defaults to exfiltration
	h := newHarness(t, cfg)

	clean := call(1, "send_email", `{"to":"a@example.com","body":"hello"}`)
	h.client(clean)
	if got := h.serverGets(); got != clean {
		t.Fatalf("clean call changed: %q", got)
	}
	h.noCallback()

	// The leaking call is not forwarded: the honey value never reaches the real tool.
	h.client(call(2, "send_email", `{"to":"x@example.net","body":"key `+honey+`"}`))
	blockedText := failed(t, h.clientGets(), 2)
	h.noServer()
	r := h.callback()
	if q := r.URL.Query(); q.Get("layer") != "egress" || q.Get("contain") != "blocked" || q.Get("session") != "stest01" {
		t.Fatalf("callback: %s", r.URL)
	}

	// Frozen: the next real call is blocked with the same text, and reports nothing more.
	h.client(call(3, "read_file", `{"path":"README.md"}`))
	if frozenText := failed(t, h.clientGets(), 3); frozenText != blockedText || frozenText != failedText {
		t.Fatalf("block and freeze must look alike: %q vs %q", blockedText, frozenText)
	}
	h.noServer()
	h.noCallback()
	if strings.Contains(strings.ToLower(blockedText), "snare") {
		t.Fatal("the error names Snare")
	}

	// Everything else is relayed, and decoys still answer and report.
	h.listTools(4)
	h.client(call(5, "list_api_keys", `{}`))
	if !strings.Contains(h.clientGets(), "accepted") {
		t.Fatal("decoy not answered while frozen")
	}
	if r := h.callback(); r.URL.Query().Get("layer") != "tool" || r.URL.Query().Get("contain") != "" {
		t.Fatalf("decoy callback while frozen: %s", r.URL)
	}
	// A tools/call notification gets no reply and isn't forwarded.
	h.client(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{}}}` + "\n")
	h.noServer()

	// The state file records the freeze, never the arguments.
	f, ok, err := ReadFrozen(state)
	raw, _ := os.ReadFile(state)
	if err != nil || !ok || f.Session != "stest01" || f.Stage != "exfiltration" || f.Tool != "send_email" ||
		bytes.Contains(raw, []byte("example.net")) || bytes.Contains(raw, []byte(honey)) {
		t.Fatalf("state file: %+v %v %s", f, err, raw)
	}
}

func TestContainmentAtRecon(t *testing.T) {
	for _, c := range []struct {
		at         string
		wantFrozen bool
	}{{"exfiltration", false}, {"recon", true}} {
		t.Run(c.at, func(t *testing.T) {
			cfg, _ := honeyConfig(t)
			cfg.Contain = &Contain{At: c.at, StateFile: filepath.Join(t.TempDir(), "f")}
			h := newHarness(t, cfg)
			h.listTools(7)
			h.client(call(1, "list_api_keys", `{}`))
			h.clientGets()
			want := ""
			if c.wantFrozen {
				want = "frozen"
			}
			if r := h.callback(); r.URL.Query().Get("contain") != want {
				t.Fatalf("decoy callback contain=%q, want %q", r.URL.Query().Get("contain"), want)
			}
			next := call(2, "read_file", `{"path":"a"}`)
			h.client(next)
			if c.wantFrozen {
				failed(t, h.clientGets(), 2)
				h.noServer()
			} else if got := h.serverGets(); got != next {
				t.Fatalf("not frozen, so the call is forwarded: %q", got)
			}
		})
	}
}

func TestFreezeSurvivesRestartUntilReleased(t *testing.T) {
	cfg, honey := honeyConfig(t)
	state := filepath.Join(t.TempDir(), "gw.json.frozen")
	cfg.Contain = &Contain{StateFile: state}
	h := newHarness(t, cfg)
	h.client(call(1, "send_email", `{"body":"`+honey+`"}`))
	failed(t, h.clientGets(), 1)
	h.callback()

	// A new gateway (the client restarted the server) starts frozen.
	h2 := newHarness(t, cfg)
	h2.client(call(1, "read_file", `{"path":"a"}`))
	failed(t, h2.clientGets(), 1)
	h2.noServer()
	h2.noCallback()

	// Release: the state file goes; both running gateways forward on their next call.
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	for _, x := range []*harness{h, h2} {
		next := call(9, "read_file", `{"path":"b"}`)
		x.client(next)
		if got := x.serverGets(); got != next {
			t.Fatalf("after release: %q", got)
		}
	}
}

func TestUnreadableStateFileStaysFrozen(t *testing.T) {
	cfg, _ := honeyConfig(t)
	state := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(state, []byte("{not json"), 0o600)
	cfg.Contain = &Contain{StateFile: state}
	h := newHarness(t, cfg)
	h.client(call(1, "read_file", `{}`))
	failed(t, h.clientGets(), 1)
	h.noServer()
}

func TestContainedBatch(t *testing.T) {
	cfg, honey := honeyConfig(t)
	cfg.Contain = &Contain{StateFile: filepath.Join(t.TempDir(), "f")}
	h := newHarness(t, cfg)
	// A batch without a tool call is forwarded as usual.
	pings := `[{"jsonrpc":"2.0","id":1,"method":"ping"}]` + "\n"
	h.client(pings)
	if got := h.serverGets(); got != pings {
		t.Fatalf("batch of pings: %q", got)
	}
	// A batch carrying a honey value is answered with errors and not forwarded.
	leak := `[{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{"body":"` + honey + `"}}},` +
		`{"jsonrpc":"2.0","method":"notifications/x"},{"jsonrpc":"2.0","id":3,"method":"ping"}]` + "\n"
	h.client(leak)
	var replies []struct {
		ID    int `json:"id"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(h.clientGets()), &replies); err != nil || len(replies) != 2 ||
		replies[0].ID != 2 || replies[1].ID != 3 || replies[0].Error.Message != failedText {
		t.Fatalf("batch replies: %+v %v", replies, err)
	}
	h.noServer()
	if r := h.callback(); r.URL.Query().Get("contain") != "blocked" {
		t.Fatalf("batch callback: %s", r.URL)
	}
	// Frozen now: a batch with any tool call is answered, not forwarded.
	h.client(`[{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{}}}]` + "\n")
	if !strings.Contains(h.clientGets(), failedText) {
		t.Fatal("frozen batch not answered")
	}
	h.noServer()
}

// Without containment, an unreachable Snare server changes nothing: calls, leaks included,
// are forwarded unchanged and promptly. With containment on, the block is still local.
func TestSnareDownForwardingUnaffected(t *testing.T) {
	cfg, honey := honeyConfig(t)
	cfg.CallbackURL = "http://127.0.0.1:1" // nothing listens
	h := newHarness(t, cfg)
	for i, l := range []string{call(1, "read_file", `{"path":"a"}`), call(2, "send_email", `{"body":"`+honey+`"}`)} {
		start := time.Now()
		h.client(l)
		if got := h.serverGets(); got != l {
			t.Fatalf("call %d changed: %q", i, got)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Errorf("call %d took %s to forward with Snare down", i, d)
		}
	}

	cfg.Contain = &Contain{StateFile: filepath.Join(t.TempDir(), "f")}
	hc := newHarness(t, cfg)
	hc.client(call(1, "send_email", `{"body":"`+honey+`"}`))
	failed(t, hc.clientGets(), 1)
	hc.noServer()
}

func TestContainConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gw.json")
	_ = os.WriteFile(p, []byte(`{"callback_url":"https://cb.example.test","style":"auto","contain":{}}`), 0o600)
	c, err := LoadConfig(p)
	if err != nil || c.Contain == nil || c.Contain.StateFile != p+".frozen" || c.Contain.onRecon() {
		t.Fatalf("defaults: %+v %v", c.Contain, err)
	}
	_ = os.WriteFile(p, []byte(`{"callback_url":"x","style":"auto","contain":{"at":"collection"}}`), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("contain.at collection accepted: the gateway can't see collection touches")
	}
	_ = os.WriteFile(p, []byte(`{"callback_url":"x","style":"auto"}`), 0o600)
	if c, _ := LoadConfig(p); c.Contain != nil {
		t.Fatal("containment must be off unless configured")
	}
}
