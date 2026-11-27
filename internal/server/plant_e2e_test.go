package server

// End-to-end test for the M2 exit criterion: `snare plant` works on a sample repo and a
// RAG corpus, plus the decoy MCP server, and every planted tripwire fires through the
// callback server. A simulated "hijacked agent" uses each planted value the way a real
// one would: calls the honey base URL, resolves the honey DB host, renders the corpus
// image, and calls a decoy tool.

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/mcp"
	"github.com/danielguillaumont/snare/internal/plant"
	"github.com/danielguillaumont/snare/internal/store"
)

// field returns the token ID planted for one honey field (each field has its own token).
func field(es []plant.Entry, name string) string {
	for _, e := range es {
		if strings.HasSuffix(e.Label, " "+name) {
			return e.TokenID
		}
	}
	return "missing-" + name
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), filepath.Base(src))
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestEndToEndPlantedTripwiresFire(t *testing.T) {
	cfg := Config{
		Key:       bytes.Repeat([]byte{7}, 32),
		AdminKey:  []byte("test-admin-key-0123456789abcdef"),
		HTTPAddr:  "127.0.0.1:0",
		AdminAddr: "127.0.0.1:0",
		DNSAddr:   "127.0.0.1:0",
		Zone:      "cb.test.",
		AnswerIP:  net.ParseIP("127.0.0.1"),
		PublicURL: "http://cb.test",
		DBPath:    filepath.Join(t.TempDir(), "snare.db"),
	}
	s, err := Start(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	c := &admin.Client{BaseURL: "http://" + s.AdminAddr, Key: string(cfg.AdminKey)}

	// Plant into copies so the checked-in examples stay clean.
	repo := copyDir(t, filepath.Join("..", "..", "examples", "sample-repo"))
	corpus := copyDir(t, filepath.Join("..", "..", "examples", "sample-corpus"))
	repoE, err := plant.Repo(c, repo, plant.Options{})
	if err != nil {
		t.Fatal(err)
	}
	corpusE, err := plant.Corpus(c, corpus, false, plant.Options{})
	if err != nil {
		t.Fatal(err)
	}
	mcpPath := filepath.Join(t.TempDir(), "decoy-mcp.json")
	mcpE, _, err := plant.MCP(c, plant.MCPOptions{ConfigPath: mcpPath})
	if err != nil {
		t.Fatal(err)
	}

	// Public URLs point at cb.test; route them to the bound listener, keeping the Host header.
	get := func(raw string, auth ...string) {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", "http://"+s.HTTPAddr+u.RequestURI(), nil)
		req.Host = u.Host
		if len(auth) > 0 {
			req.Header.Set("Authorization", "Bearer "+auth[0])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	// 1. Repo: agent calls the honey API and resolves the honey DB host.
	env, _ := os.ReadFile(filepath.Join(repo, plant.RepoFile))
	vals := map[string]string{}
	for _, line := range strings.Split(string(env), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			vals[k] = v
		}
	}
	get(vals["PAYMENTS_API_BASE_URL"]+"/v1/payouts", vals["PAYMENTS_API_KEY"])
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(vals["PAYMENTS_DB_HOST"]), dns.TypeA)
	if _, _, err := new(dns.Client).Exchange(m, s.DNSAddr); err != nil {
		t.Fatal(err)
	}

	// 2. Corpus: a RAG pipeline / chat UI renders the runbook's status image.
	doc, _ := os.ReadFile(filepath.Join(corpus, plant.CorpusFile))
	img := regexp.MustCompile(`!\[[^\]]*\]\(([^)]+)\)`).FindStringSubmatch(string(doc))
	if img == nil {
		t.Fatal("no image in planted runbook")
	}
	get(img[1])

	// 3. MCP: agent calls a decoy tool.
	mc, err := mcp.LoadConfig(mcpPath)
	if err != nil {
		t.Fatal(err)
	}
	mc.CallbackURL = "http://" + s.HTTPAddr
	ms := &mcp.Server{Cfg: mc}
	var out bytes.Buffer
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_vault_v2","arguments":{"path":"prod/db"}}}` + "\n"
	if err := ms.Serve(context.Background(), strings.NewReader(call), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "accepted") {
		t.Fatalf("decoy response: %s", out.String())
	}
	var vaultID string
	for _, e := range mcpE {
		if strings.HasSuffix(e.Label, ": query_vault_v2") {
			vaultID = e.TokenID
		}
	}

	// Every tripwire must show up as an event, with the right channel.
	want := []struct {
		id, channel, what string
	}{
		{field(repoE, "base_url"), "http", "repo honey base URL"},
		{field(repoE, "api_key"), "http", "repo honey API key (sent as a bearer token)"},
		{field(repoE, "db_host"), "dns", "repo honey DB host"},
		{field(corpusE, "base_url"), "http", "corpus runbook image"},
		{vaultID, "http", "decoy MCP tool"},
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, w := range want {
		for {
			evs, err := c.Events(w.id, 10)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range evs {
				if e.Channel == w.channel {
					found = true
				}
			}
			if found {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: no %s event for token %s", w.what, w.channel, w.id)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Untouched decoys stay silent: no false alarms from planting itself.
	for _, e := range mcpE {
		if e.TokenID == vaultID {
			continue
		}
		evs, _ := c.Events(e.TokenID, 1)
		if len(evs) != 0 {
			t.Errorf("%s fired without being called", e.Label)
		}
	}
	if _, err := os.Stat(filepath.Join(repo, "snare-planted.json")); err == nil {
		t.Error("manifest written into planted repo")
	}
}

// The key layout (docs/M12-adaptive-deception.md §2): the base URL carries no token, so opening
// it is silent, and the planted key still fires when it is used against that URL.
func TestEndToEndKeyLayout(t *testing.T) {
	cfg := Config{
		Key:       bytes.Repeat([]byte{12}, 32),
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
	repo := t.TempDir()
	es, err := plant.Repo(c, repo, plant.Options{Layout: plant.LayoutKey})
	if err != nil {
		t.Fatal(err)
	}
	env, _ := os.ReadFile(filepath.Join(repo, plant.RepoFile))
	vals := map[string]string{}
	for _, line := range strings.Split(string(env), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(k, "#") {
			vals[k] = v
		}
	}
	base, key := vals["PAYMENTS_API_BASE_URL"], vals["PAYMENTS_API_KEY"]
	if base != "http://cb.test/v1" || key == "" {
		t.Fatalf("planted: %v", vals)
	}
	get := func(auth string) {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://"+s.HTTPAddr+"/v1/payouts", nil)
		req.Host = "cb.test"
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	get("") // opening the URL alone: silent
	time.Sleep(200 * time.Millisecond)
	if evs, _ := c.EventsFiltered(store.EventFilter{}, 10); len(evs) != 0 {
		t.Fatalf("the tokenless URL fired: %+v", evs)
	}
	get(key)
	id := field(es, "api_key")
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		evs, _ := c.Events(id, 10)
		if len(evs) == 1 && evs[0].Channel == "http" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the key used against the base URL did not fire: %+v", evs)
		}
	}
}
