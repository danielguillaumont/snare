package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/decoys"
	"github.com/danielguillaumont/snare/internal/token"
)

// harness runs a Gateway between a test "client" and a scripted "server", in process.
type harness struct {
	t          *testing.T
	toGateway  *io.PipeWriter // client -> gateway
	fromGW     *bufio.Reader  // gateway -> client
	serverRecv chan []byte    // lines the server received, verbatim
	serverSend *io.PipeWriter // server -> gateway
	calls      chan *http.Request
	done       chan error
}

func newHarness(t *testing.T, cfg Config, opts ...func(*Gateway)) *harness {
	t.Helper()
	h := &harness{t: t, serverRecv: make(chan []byte, 64), calls: make(chan *http.Request, 16), done: make(chan error, 1)}
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.calls <- r }))
	t.Cleanup(cb.Close)
	if cfg.CallbackURL == "" {
		cfg.CallbackURL = cb.URL
	}
	if cfg.Style == "" {
		cfg.Style = "catalog"
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cIn, cInW := io.Pipe()
	cOutR, cOut := io.Pipe()
	sInR, sIn := io.Pipe()
	sOut, sOutW := io.Pipe()
	h.toGateway, h.fromGW, h.serverSend = cInW, bufio.NewReader(cOutR), sOutW
	go func() {
		_ = eachLine(sInR, func(l []byte) error { h.serverRecv <- append([]byte(nil), l...); return nil })
		close(h.serverRecv)
	}()
	g := &Gateway{Cfg: cfg, Session: "stest01"}
	for _, o := range opts {
		o(g)
	}
	go func() { h.done <- g.Run(context.Background(), cIn, cOut, sIn, sOut) }()
	t.Cleanup(func() { cInW.Close(); sOutW.Close() })
	return h
}

func (h *harness) client(line string) { h.t.Helper(); _, _ = io.WriteString(h.toGateway, line) }
func (h *harness) server(line string) { h.t.Helper(); _, _ = io.WriteString(h.serverSend, line) }

func (h *harness) clientGets() string {
	h.t.Helper()
	ch := make(chan string, 1)
	go func() { l, _ := h.fromGW.ReadString('\n'); ch <- l }()
	select {
	case l := <-ch:
		return l
	case <-time.After(3 * time.Second):
		h.t.Fatal("client got nothing")
		return ""
	}
}

func (h *harness) serverGets() string {
	h.t.Helper()
	select {
	case l := <-h.serverRecv:
		return string(l)
	case <-time.After(3 * time.Second):
		h.t.Fatal("server got nothing")
		return ""
	}
}

func (h *harness) callback() *http.Request {
	h.t.Helper()
	select {
	case r := <-h.calls:
		return r
	case <-time.After(3 * time.Second):
		h.t.Fatal("no callback")
		return nil
	}
}

func (h *harness) noCallback() {
	h.t.Helper()
	select {
	case r := <-h.calls:
		h.t.Fatalf("unexpected callback %s", r.URL)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestRelayIsByteForByte(t *testing.T) {
	h := newHarness(t, Config{Decoys: map[string]string{"list_api_keys": "tok"}})
	for _, l := range []string{
		`{ "jsonrpc":"2.0", "method":"initialize","id":0,"params":{"protocolVersion":"2025-06-18"}}` + "\n",
		`{"method":"notifications/initialized","jsonrpc":"2.0"}` + "\n",
		`[{"jsonrpc":"2.0","id":5,"method":"ping"},{"jsonrpc":"2.0","id":6,"method":"ping"}]` + "\n",
		"not json at all\n",
		`{"jsonrpc":"2.0","id":7,"result":{"roots":[]}}` + "\r\n", // reply to a server request
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"a b"}}}` + "\n",
	} {
		h.client(l)
		if got := h.serverGets(); got != l {
			t.Errorf("client->server changed:\n got %q\nwant %q", got, l)
		}
	}
	for _, l := range []string{
		`{"jsonrpc":"2.0","id":0,"result":{"capabilities":{"tools":{}},"serverInfo":{"name":"real","version":"1"}}}` + "\n",
		`{"jsonrpc":"2.0","id":7,"method":"roots/list"}` + "\n",
		`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}` + "\n",
		"garbage {\n",
	} {
		h.server(l)
		if got := h.clientGets(); got != l {
			t.Errorf("server->client changed:\n got %q\nwant %q", got, l)
		}
	}
	h.noCallback()
}

func toolNames(t *testing.T, line string) []string {
	t.Helper()
	var m struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("%v: %s", err, line)
	}
	var out []string
	for _, x := range m.Result.Tools {
		out = append(out, x.Name)
	}
	return out
}

func TestDecoysOnFinalPageOnlyAndRealToolsWin(t *testing.T) {
	h := newHarness(t, Config{Decoys: map[string]string{"list_api_keys": "tokA", "query_vault_v2": "tokB"}})
	// The server also sees this request, and a server request that reuses id 1 is not a reply.
	h.client(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	h.serverGets()
	srvReq := `{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}` + "\n"
	h.server(srvReq)
	if got := h.clientGets(); got != srvReq {
		t.Fatalf("server request altered: %q", got)
	}
	page1 := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file"}],"nextCursor":"p2"}}` + "\n"
	h.server(page1)
	if got := h.clientGets(); got != page1 {
		t.Fatalf("non-final page altered: %q", got)
	}
	h.client(`{"jsonrpc":"2.0","id":"two","method":"tools/list","params":{"cursor":"p2"}}` + "\n")
	h.serverGets()
	h.server(`{"jsonrpc":"2.0","id":"two","result":{"tools":[{"name":"send_email","inputSchema":{"type":"object"}},{"name":"list_api_keys"}]}}` + "\n")
	got := toolNames(t, h.clientGets())
	if strings.Join(got, ",") != "send_email,list_api_keys,query_vault_v2" {
		t.Fatalf("final page tools: %v", got)
	}

	// list_api_keys is a real tool here: its call goes to the server, no callback.
	call := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_api_keys","arguments":{}}}` + "\n"
	h.client(call)
	if s := h.serverGets(); s != call {
		t.Fatalf("real tool call altered: %q", s)
	}
	h.noCallback()
}

func TestDecoyCallIsAnsweredLocallyWithSessionContext(t *testing.T) {
	h := newHarness(t, Config{Decoys: map[string]string{"query_vault_v2": "decoytoken123"}})
	h.client(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	h.serverGets()
	h.server(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"send_email"}]}}` + "\n")
	h.clientGets()

	h.client(`{"jsonrpc":"2.0","id":"c9","method":"tools/call","params":{"name":"query_vault_v2","arguments":{"path":"prod/db"}}}` + "\n")
	reply := h.clientGets()
	if !strings.Contains(reply, `"id":"c9"`) || !strings.Contains(reply, "accepted") {
		t.Fatalf("decoy reply: %s", reply)
	}
	r := h.callback()
	if !strings.HasSuffix(r.URL.Path, "/decoytoken123") || r.URL.Query().Get("layer") != "tool" ||
		r.URL.Query().Get("session") != "stest01" || r.URL.Query().Get("tool") != "query_vault_v2" {
		t.Fatalf("callback: %s", r.URL)
	}
	if strings.Contains(r.URL.String(), "prod") {
		t.Fatalf("arguments leaked into the callback: %s", r.URL)
	}
	select {
	case l := <-h.serverRecv:
		t.Fatalf("decoy call reached the real server: %s", l)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHoneyValueInArgumentsIsReported(t *testing.T) {
	s, _ := token.NewSigner(bytes.Repeat([]byte{9}, 32))
	honey, id, _ := s.Mint()
	bodies, _ := s.Bodies(id)
	const salt = "gateway-test-salt-01"
	var fps []string
	for _, b := range bodies {
		fps = append(fps, token.Fingerprint(salt, b))
	}
	h := newHarness(t, Config{Salt: salt, Fingerprints: fps})

	clean := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@example.com","body":"hello"}}}` + "\n"
	h.client(clean)
	h.serverGets()
	h.noCallback()

	leak := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"x@example.net","body":"the key is ` + honey + `"}}}` + "\n"
	h.client(leak)
	if got := h.serverGets(); got != leak {
		t.Fatalf("observe mode must relay the call unchanged: %q", got)
	}
	r := h.callback()
	q := r.URL.Query()
	if !strings.Contains(r.URL.Path, honey) || q.Get("layer") != "egress" || q.Get("tool") != "send_email" || q.Get("session") != "stest01" {
		t.Fatalf("egress callback: %s", r.URL)
	}
	if strings.Contains(r.URL.String(), "example.net") {
		t.Fatalf("arguments leaked into the callback: %s", r.URL)
	}
}

func TestDecoyNamesFollowTheServersStyle(t *testing.T) {
	h := newHarness(t, Config{Style: "auto", Seed: 42, Decoys: map[string]string{"list_api_keys": "t1", "read_env_secrets": "t2"}})
	h.client(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	h.serverGets()
	h.server(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"searchIssues"},{"name":"createPullRequest"},{"name":"getFile"}]}}` + "\n")
	got := toolNames(t, h.clientGets())
	if len(got) != 5 {
		t.Fatalf("tools: %v", got)
	}
	picks, _ := decoys.Pick(42, "camel", nil)
	want := map[string]bool{}
	for _, p := range picks {
		if p.Canonical == "list_api_keys" || p.Canonical == "read_env_secrets" {
			want[p.Name] = true
		}
	}
	for _, n := range got[3:] {
		if strings.ContainsAny(n, "_-") || !want[n] {
			t.Errorf("decoy %q is not a camelCase name from the generator (%v)", n, want)
		}
	}
}

func TestDetectStyle(t *testing.T) {
	for _, c := range []struct {
		names []string
		want  string
	}{
		{[]string{"read_file", "write_file", "getX"}, "snake"},
		{[]string{"searchIssues", "getFile", "list"}, "camel"},
		{[]string{"browser-navigate", "browser-click"}, "kebab"},
		{[]string{"search", "fetch"}, "snake"},
		{nil, "snake"},
	} {
		if got := DetectStyle(c.names); got != c.want {
			t.Errorf("%v: %s, want %s", c.names, got, c.want)
		}
	}
}

func TestConfigHoldsNoHoneyValueOrKey(t *testing.T) {
	s, _ := token.NewSigner(bytes.Repeat([]byte{5}, 32))
	honey, id, _ := s.Mint()
	bodies, _ := s.Bodies(id)
	cfg := Config{CallbackURL: "https://cb.example.com", Style: "auto", Salt: "0123456789abcdef", Decoys: map[string]string{"list_api_keys": "decoy"}}
	for _, b := range bodies {
		cfg.Fingerprints = append(cfg.Fingerprints, token.Fingerprint(cfg.Salt, b))
	}
	raw, _ := json.Marshal(cfg)
	for _, b := range append(bodies, honey, id) {
		if bytes.Contains(raw, []byte(b)) {
			t.Fatalf("config contains %q", b)
		}
	}
	if err := (Config{CallbackURL: "x", Style: "auto", Fingerprints: []string{"a"}}).Validate(); err == nil {
		t.Error("fingerprints without a salt accepted")
	}
	if err := (Config{CallbackURL: "x", Style: "auto", Decoys: map[string]string{"nope": "t"}}).Validate(); err == nil {
		t.Error("decoy outside the catalog accepted")
	}
}

// Lines larger than bufio's default buffer are relayed intact.
func TestLargeMessages(t *testing.T) {
	h := newHarness(t, Config{})
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write","arguments":{"data":"` + strings.Repeat("x", 300_000) + `"}}}` + "\n"
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); h.client(big) }()
	if got := h.serverGets(); got != big {
		t.Fatalf("large line altered (len %d vs %d)", len(got), len(big))
	}
	wg.Wait()
}

// A server-to-client request that reuses the id of a pending tools/list must not consume
// it: the real reply that follows still gets the decoys.
func TestServerRequestWithSameIDIsNotTheReply(t *testing.T) {
	h := newHarness(t, Config{Decoys: map[string]string{"list_api_keys": "tokA"}})
	h.client(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	h.serverGets()
	h.server(`{"jsonrpc":"2.0","id":1,"method":"elicitation/create","params":{}}` + "\n")
	h.clientGets()
	h.server(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"send_email"}]}}` + "\n")
	if got := toolNames(t, h.clientGets()); strings.Join(got, ",") != "send_email,list_api_keys" {
		t.Fatalf("tools after a same-id server request: %v", got)
	}
}

// Style adapt (docs/M12-adaptive-deception.md §1): decoys take the server's namespace, verbs,
// argument style and punctuation, are answered as decoys, and never shadow a real tool.
func TestAdaptStyleSpeaksTheServersVocabulary(t *testing.T) {
	h := newHarness(t, Config{Style: "adapt", Seed: 9, Decoys: map[string]string{"read_env_secrets": "envtok01", "list_api_keys": "keytok01"}})
	h.client(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	h.serverGets()
	h.server(`{"jsonrpc":"2.0","id":1,"result":{"tools":[` +
		`{"name":"jiraFetchIssue","description":"Fetch one issue","inputSchema":{"type":"object","properties":{"issueKey":{"type":"string"}}}},` +
		`{"name":"jiraShowBoards","description":"Show boards","inputSchema":{"type":"object","properties":{"projectKey":{"type":"string"}}}},` +
		`{"name":"jiraSearch","description":"Search with JQL"}]}}` + "\n")
	var m struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				Description string         `json:"description"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(h.clientGets()), &m); err != nil || len(m.Result.Tools) != 5 {
		t.Fatalf("tools: %+v %v", m, err)
	}
	vocab := decoys.Learn([]decoys.RealTool{
		{Name: "jiraFetchIssue", Description: "Fetch one issue", Params: []string{"issueKey"}},
		{Name: "jiraShowBoards", Description: "Show boards", Params: []string{"projectKey"}},
		{Name: "jiraSearch", Description: "Search with JQL"},
	})
	want, _ := decoys.Adapt(vocab, 9, nil, nil)
	shown := map[string]decoys.Choice{}
	for _, c := range want {
		shown[c.Name] = c
	}
	var envName string
	for _, d := range m.Result.Tools[3:] {
		c, ok := shown[d.Name]
		if !ok || !strings.HasPrefix(d.Name, "jira") || d.Description != c.Description || strings.HasSuffix(d.Description, ".") {
			t.Errorf("decoy %+v is not the adapted choice", d)
		}
		props, _ := d.InputSchema["properties"].(map[string]any)
		for _, p := range c.Params {
			if _, ok := props[p.Name]; !ok {
				t.Errorf("%s: argument %q missing from %v", d.Name, p.Name, props)
			}
		}
		if c.Canonical == "read_env_secrets" {
			envName = d.Name
		}
	}
	if !strings.HasPrefix(envName, "jiraFetch") {
		t.Fatalf("read_env_secrets shown as %q, want the server's verb", envName)
	}
	h.client(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + envName + `","arguments":{}}}` + "\n")
	if reply := h.clientGets(); !strings.Contains(reply, "accepted") {
		t.Fatalf("decoy reply: %s", reply)
	}
	if r := h.callback(); !strings.HasSuffix(r.URL.Path, "/envtok01") || r.URL.Query().Get("tool") != envName {
		t.Fatalf("callback: %s", r.URL)
	}
}

func TestAdaptStyleNeverShadowsARealTool(t *testing.T) {
	// The server already has a tool with the name adaptation would produce: it stays real.
	vocab := decoys.Learn([]decoys.RealTool{{Name: "get_ticket"}, {Name: "get_user"}})
	picks, _ := decoys.Adapt(vocab, 4, nil, nil)
	var clash string
	for _, c := range picks {
		if c.Canonical == "get_admin_credentials" {
			clash = c.Name
		}
	}
	h := newHarness(t, Config{Style: "adapt", Seed: 4, Decoys: map[string]string{"get_admin_credentials": "admtok01"}})
	h.client(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	h.serverGets()
	h.server(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_ticket"},{"name":"get_user"},{"name":"` + clash + `"}]}}` + "\n")
	got := toolNames(t, h.clientGets())
	if n := strings.Count(","+strings.Join(got, ",")+",", ","+clash+","); n != 1 || got[2] != clash {
		t.Fatalf("tools: %v (real %q must appear once, as the server's)", got, clash)
	}
	call := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + clash + `","arguments":{}}}` + "\n"
	h.client(call)
	if s := h.serverGets(); s != call {
		t.Fatalf("real tool call altered: %q", s)
	}
	h.noCallback()
}
