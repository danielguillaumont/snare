package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/clientcfg"
	"github.com/danielguillaumont/snare/internal/gateway"
	"github.com/danielguillaumont/snare/internal/server"
)

const initClient = `{
  "theme": "dark",
  "mcpServers": {
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "placeholder"}},
    "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/docs"]},
    "remote": {"url": "https://mcp.example.test/sse"},
    "clock": {"command": "uvx", "args": ["mcp-server-time"]}
  },
  "x-extra": {"keep": [1, 2]}
}`

func startSnare(t *testing.T) *admin.Client {
	t.Helper()
	httpAddr := freeAddr(t)
	adminKey := "init-test-admin-key-0123456789ab"
	s, err := server.Start(server.Config{
		Key: bytes.Repeat([]byte{7}, 32), AdminKey: []byte(adminKey), SealKey: bytes.Repeat([]byte{9}, 32),
		HTTPAddr: httpAddr, AdminAddr: "127.0.0.1:0", PublicURL: "http://" + httpAddr,
		DBPath: filepath.Join(t.TempDir(), "snare.db"),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	return &admin.Client{BaseURL: "http://" + s.AdminAddr, Key: adminKey}
}

func TestInitEndToEnd(t *testing.T) {
	c := startSnare(t)
	work := t.TempDir()
	cfgPath := filepath.Join(work, "claude_desktop_config.json")
	if err := os.WriteFile(cfgPath, []byte(initClient), 0o644); err != nil {
		t.Fatal(err)
	}
	commented := filepath.Join(work, "mcp.json")
	withComments := "{\n  // mine\n  \"servers\": {\"gh\": {\"command\": \"gh-mcp\"}}\n}"
	if err := os.WriteFile(commented, []byte(withComments), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, ".snare")
	o := initOptions{
		Clients: []clientcfg.Candidate{{Client: "claude-desktop", Path: cfgPath}, {Client: "vscode", Path: commented}},
		Dir:     dir, Profile: "all", Snare: "/usr/local/bin/snare", Admin: c, BeatWait: 5 * time.Second,
	}
	run := func(o initOptions) (string, error) {
		var out bytes.Buffer
		err := runInit(context.Background(), o, &out)
		return out.String(), err
	}

	// Dry run: a plan, and nothing written or minted.
	out, err := run(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"wrap   github", "wrap   files", "skip   remote", "skip   clock", "not plain JSON", "Dry run", "snare plant repo"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("dry run created %s", dir)
	}
	if toks, _ := c.Tokens(); len(toks) != 0 {
		t.Errorf("dry run minted %d tokens", len(toks))
	}

	// Apply: two gateways, a backup, a rewritten config, two verified heartbeats, coverage.
	o.Apply = true
	out, err = run(o)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Count(out, "verified     ") != 2 || !strings.Contains(out, "Layers armed:") || !strings.Contains(out, "Restart your MCP client") {
		t.Errorf("apply output:\n%s", out)
	}
	f, err := clientcfg.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := map[string]string{}
	for _, s := range f.Servers() {
		if gw, ok := s.GatewayConfig(); ok {
			wrapped[s.Name] = gw
		}
	}
	if len(wrapped) != 2 || wrapped["github"] != clientcfg.GatewayPath(dir, "claude-desktop", "github") {
		t.Fatalf("wrapped: %v", wrapped)
	}
	for _, gw := range wrapped {
		cfg, err := gateway.LoadConfig(gw)
		if err != nil || len(cfg.Decoys) != 17 || cfg.Heartbeat == nil {
			t.Errorf("%s: %v %+v", gw, err, cfg)
		}
	}
	after, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(after), `"x-extra"`) || !strings.Contains(string(after), `"GITHUB_TOKEN": "placeholder"`) {
		t.Errorf("lost fields:\n%s", after)
	}
	if b, _ := os.ReadFile(commented); string(b) != withComments {
		t.Error("a file with comments was changed")
	}
	backups, _ := filepath.Glob(cfgPath + ".snare-backup-*")
	if len(backups) != 1 {
		t.Fatalf("backups: %v", backups)
	}
	if b, _ := os.ReadFile(backups[0]); string(b) != initClient {
		t.Error("backup is not the original")
	}
	toks, _ := c.Tokens()

	// A second apply wraps nothing new and mints nothing.
	out, err = run(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "armed  github") || !strings.Contains(out, "Nothing to wrap") {
		t.Errorf("second apply:\n%s", out)
	}
	if again, _ := os.ReadFile(cfgPath); !bytes.Equal(again, after) {
		t.Error("second apply changed the config")
	}
	if t2, _ := c.Tokens(); len(t2) != len(toks) {
		t.Errorf("second apply minted: %d -> %d", len(toks), len(t2))
	}

	// Undo restores the original commands; everything else stays.
	o.Undo = true
	out, err = run(o)
	if err != nil || !strings.Contains(out, "restored github, files") {
		t.Fatalf("undo: %v\n%s", err, out)
	}
	orig, _ := clientcfg.Parse("orig", []byte(initClient))
	back, _ := clientcfg.Load(cfgPath)
	for i, s := range orig.Servers() {
		b := back.Servers()[i]
		if b.Command != s.Command || strings.Join(b.Args, " ") != strings.Join(s.Args, " ") {
			t.Errorf("undo %s: %+v", s.Name, b)
		}
	}
}

func TestInitLivenessFailureIsReported(t *testing.T) {
	c := startSnare(t)
	gw := filepath.Join(t.TempDir(), "gw.json")
	cfg := gateway.Config{CallbackURL: "http://" + freeAddr(t), Style: "auto", Decoys: map[string]string{"list_api_keys": "y"},
		Heartbeat: &gateway.Heartbeat{Token: "t", Every: "15m"}}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(gw, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := verify(context.Background(), initOptions{Admin: c, BeatWait: time.Second}, gw)
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("want unreachable, got %v", err)
	}
}
