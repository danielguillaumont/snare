package gateway

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a settable clock for the ledger's ages and expiry.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func textResult(id int, text string) string {
	b, _ := json.Marshal(text)
	return `{"jsonrpc":"2.0","id":` + itoa(id) + `,"result":{"content":[{"type":"text","text":` + string(b) + `}]}}` + "\n"
}

// realCall runs one forwarded tool call and its reply through the gateway.
func (h *harness) realCall(id int, tool, args, reply string) {
	h.t.Helper()
	h.client(call(id, tool, args))
	h.serverGets()
	h.server(reply)
	h.clientGets()
}

// touch calls the decoy and returns the callback's query.
func (h *harness) touch(id int) url.Values {
	h.t.Helper()
	h.client(call(id, "list_api_keys", `{}`))
	h.clientGets()
	return h.callback().URL.Query()
}

func entry(tool, text string, age int) string {
	return tool + "~" + InputFingerprint(text) + "~" + strconv.Itoa(len([]rune(text))) + "~" + strconv.Itoa(age)
}

func TestLedgerRecordsRealResultsOnly(t *testing.T) {
	cfg, _ := honeyConfig(t)
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	h := newHarness(t, cfg, func(g *Gateway) { g.now = clk.now })

	h.listTools(1) // a tools/list reply is not an input
	if q := h.touch(2); q.Get("in0") != "" {
		t.Fatalf("ledger not empty before any real call: %v", q)
	}
	h.realCall(3, "read_file", `{"path":"t.md"}`, textResult(3, "ticket text"))
	// An error reply carries no result: not recorded.
	h.realCall(4, "read_file", `{"path":"gone.md"}`, `{"jsonrpc":"2.0","id":4,"error":{"code":-32000,"message":"no such file"}}`+"\n")
	// A reply with an id the gateway never forwarded is not recorded either.
	h.server(textResult(99, "unsolicited"))
	h.clientGets()
	clk.add(4 * time.Second)

	q := h.touch(5)
	if got, want := q.Get("in0"), entry("read_file", "ticket text", 4); got != want {
		t.Fatalf("in0 = %q, want %q", got, want)
	}
	if q.Get("in1") != "" {
		t.Fatalf("more than one input recorded: %v", q)
	}
	// The decoy's own reply (to id 5) is not an input.
	if q := h.touch(6); q.Get("in1") != "" {
		t.Fatalf("decoy reply recorded: %v", q)
	}
}

func TestLedgerCapAndExpiry(t *testing.T) {
	cfg, _ := honeyConfig(t)
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	h := newHarness(t, cfg, func(g *Gateway) { g.now = clk.now })
	h.listTools(1)
	for i := 1; i <= 10; i++ {
		h.realCall(10+i, "read_file", `{}`, textResult(10+i, "doc "+strconv.Itoa(i)))
		clk.add(time.Second)
	}
	q := h.touch(30)
	// The last 8, oldest first: docs 3..10, aged 8 s down to 1 s.
	for k := 0; k < 8; k++ {
		if got, want := q.Get("in"+strconv.Itoa(k)), entry("read_file", "doc "+strconv.Itoa(k+3), 8-k); got != want {
			t.Fatalf("in%d = %q, want %q", k, got, want)
		}
	}
	if q.Get("in8") != "" {
		t.Fatal("more than 8 inputs")
	}

	clk.add(59 * time.Minute)
	h.realCall(40, "search", `{}`, textResult(40, "fresh"))
	clk.add(2 * time.Minute) // docs are now over an hour old; "fresh" is 120 s old
	q = h.touch(41)
	if got, want := q.Get("in0"), entry("search", "fresh", 120); got != want {
		t.Fatalf("after expiry in0 = %q, want %q", got, want)
	}
	if q.Get("in1") != "" {
		t.Fatalf("expired inputs sent: %v", q)
	}
}

func TestLedgerNeverSendsContentOrArguments(t *testing.T) {
	cfg, honey := honeyConfig(t)
	h := newHarness(t, cfg)
	h.listTools(1)
	h.realCall(2, "read_file", `{"path":"argument-marker-7f3.md"}`, textResult(2, "result-marker-c41"))
	h.client(call(3, "send_email", `{"to":"x@example.net","body":"`+honey+`"}`)) // an egress touch
	h.serverGets()
	r := h.callback()
	raw := r.URL.String() // the path is the token (M6); the query must carry no content
	for _, s := range []string{"argument-marker", "result-marker", honey, "x@example.net"} {
		if s == honey {
			if strings.Contains(r.URL.RawQuery, s) {
				t.Fatalf("query carries the honey value: %s", raw)
			}
			continue
		}
		if strings.Contains(raw, s) {
			t.Fatalf("callback carries %q: %s", s, raw)
		}
	}
	if q := r.URL.Query(); q.Get("in0") == "" || q.Get("src0") != "" {
		t.Fatalf("egress touch: want an input and no name: %s", raw)
	}
}

func TestLedgerNamesOnlyWhenOptedIn(t *testing.T) {
	cfg, _ := honeyConfig(t)
	cfg.Provenance = &Provenance{Names: true}
	h := newHarness(t, cfg)
	h.listTools(1)
	h.realCall(2, "read_file", `{"name":"ignored","path":"tickets/T-42 poisoned.md"}`, textResult(2, "x"))
	h.realCall(3, "list_dir", `{"recursive":true}`, textResult(3, "y")) // no name argument
	q := h.touch(4)
	if q.Get("src0") != "tickets/T-42_poisoned.md" || q.Get("src1") != "" || q.Get("in1") == "" {
		t.Fatalf("names: %v", q)
	}
}

func TestResultText(t *testing.T) {
	r := `{"content":[{"type":"text","text":"a\n"},{"type":"image","data":"zz"},{"type":"resource","resource":{"uri":"f","text":"b"}}]}`
	if got, ok := resultText(json.RawMessage(r)); !ok || got != "a\nb" {
		t.Fatalf("resultText = %q %v", got, ok)
	}
	if _, ok := resultText(json.RawMessage(`{"tools":[]}`)); ok {
		t.Fatal("a result without content is not an input")
	}
}

func TestSourceName(t *testing.T) {
	for args, want := range map[string]string{
		`{"url":"https://kb.example/a b","id":"7"}`: "https://kb.example/a_b",
		`{"id":7,"name":"n"}`:                       "n", // non-strings are skipped
		`{"q":"x"}`:                                 "",
		`not json`:                                  "",
	} {
		if got := sourceName(json.RawMessage(args)); got != want {
			t.Errorf("sourceName(%s) = %q, want %q", args, got, want)
		}
	}
	long := strings.Repeat("d/", 100) + "file.md"
	if got := sanitizeSource(long); len(got) != maxSource || !strings.HasSuffix(got, "file.md") {
		t.Fatalf("long source: %q", got)
	}
}
