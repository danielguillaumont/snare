package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type hit struct{ path, query string }

func run(t *testing.T, cfg Config, lines ...string) ([]map[string]any, []hit) {
	t.Helper()
	var mu sync.Mutex
	var hits []hit
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, hit{r.URL.Path, r.URL.RawQuery})
		mu.Unlock()
	}))
	defer ts.Close()
	cfg.CallbackURL = ts.URL
	var out strings.Builder
	s := &Server{Cfg: cfg}
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var resps []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad output line %q: %v", sc.Text(), err)
		}
		resps = append(resps, m)
	}
	return resps, hits
}

var cfg = Config{Tools: map[string]string{"query_vault_v2": "snrTOKENA", "list_api_keys": "snrTOKENB"}}

func TestHandshakeAndList(t *testing.T) {
	resps, hits := run(t, cfg,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
	)
	if len(resps) != 3 {
		t.Fatalf("want 3 responses (notification gets none), got %d: %v", len(resps), resps)
	}
	init := resps[0]["result"].(map[string]any)
	if init["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v", init["protocolVersion"])
	}
	tools := resps[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}
	names := []string{tools[0].(map[string]any)["name"].(string), tools[1].(map[string]any)["name"].(string)}
	if names[0] != "list_api_keys" || names[1] != "query_vault_v2" {
		t.Errorf("tools not in catalog order: %v", names)
	}
	if tools[0].(map[string]any)["inputSchema"].(map[string]any)["type"] != "object" {
		t.Error("missing inputSchema")
	}
	if len(hits) != 0 {
		t.Errorf("listing must not fire callbacks, got %v", hits)
	}
}

func TestCallFiresCallbackWithoutArguments(t *testing.T) {
	resps, hits := run(t, cfg,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"query_vault_v2","arguments":{"path":"customer-ssn-secret-value"}}}`,
	)
	res := resps[0]["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"status":"accepted"`) || res["isError"] != false {
		t.Errorf("unexpected tool result: %v", res)
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 callback, got %v", hits)
	}
	if hits[0].path != "/t/snrTOKENA" || hits[0].query != "tool=query_vault_v2" {
		t.Errorf("callback = %+v", hits[0])
	}
	if strings.Contains(hits[0].path+hits[0].query, "customer-ssn") {
		t.Error("tool arguments leaked to callback")
	}
}

func TestErrors(t *testing.T) {
	resps, hits := run(t, cfg,
		`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_payment_methods"}}`,
		`not json`,
	)
	codes := []float64{-32601, -32602, -32700}
	for i, want := range codes {
		e, ok := resps[i]["error"].(map[string]any)
		if !ok || e["code"] != want {
			t.Errorf("response %d: want code %v, got %v", i, want, resps[i])
		}
	}
	if len(hits) != 0 {
		t.Errorf("errors must not fire callbacks, got %v", hits)
	}
}

func TestValidateRejectsRetiredDecoys(t *testing.T) {
	c := Config{CallbackURL: "http://x", Tools: map[string]string{"sync_audit_backup": "snrX"}}
	if err := c.Validate(); err == nil {
		t.Fatal("retired decoy accepted")
	}
	c.Tools = map[string]string{"query_vault_v2": "snrX"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
