package clientcfg

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCandidatesPerOS(t *testing.T) {
	win := Candidates("windows", `C:\Users\u`, `C:\Users\u\AppData\Roaming`, `C:\work`)
	if win[0].Client != "claude-desktop" || !strings.HasSuffix(win[0].Path, filepath.Join("Roaming", "Claude", "claude_desktop_config.json")) {
		t.Errorf("windows: %+v", win[0])
	}
	mac := Candidates("darwin", "/Users/u", "", "/w")
	if !strings.Contains(mac[0].Path, filepath.Join("Library", "Application Support", "Claude")) {
		t.Errorf("darwin: %+v", mac[0])
	}
	lin := Candidates("linux", "/home/u", "", "/w")
	var clients []string
	for _, c := range lin {
		clients = append(clients, c.Client)
	}
	if strings.Join(clients, ",") != "claude-desktop,claude-code,vscode,cursor,cursor-project,windsurf" {
		t.Errorf("linux: %v", clients)
	}
	// No APPDATA: the Desktop location is skipped, not guessed.
	if c := Candidates("windows", `C:\Users\u`, "", `C:\w`); c[0].Client == "claude-desktop" {
		t.Errorf("guessed %+v", c[0])
	}
}

const mixed = `{"mcpServers": {
  "github":   {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
  "files":    {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/docs"]},
  "remote":   {"url": "https://mcp.example.test/sse"},
  "decoys":   {"command": "snare", "args": ["decoy-mcp", "-config", "d.json"]},
  "wrapped":  {"command": "/opt/snare", "args": ["gateway", "-config", "g.json", "--", "slack-mcp"]},
  "clock":    {"command": "uvx", "args": ["mcp-server-time"]}
}}`

func TestPlan(t *testing.T) {
	f := load(t, mixed)
	acts, _, err := Plan(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range acts {
		got[a.Server] = a.Do
		if a.Why == "" {
			t.Errorf("%s: no reason", a.Server)
		}
	}
	want := map[string]string{"github": Wrap, "files": Wrap, "remote": Skip, "decoys": Armed, "wrapped": Armed, "clock": Skip}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
	if acts[0].Server != "github" || acts[5].Server != "clock" {
		t.Error("not in file order")
	}

	// -servers wraps exactly what it names, if it can.
	acts, _, err = Plan(f, []string{"clock", "remote"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acts {
		w := map[string]string{"clock": Wrap, "remote": Skip, "github": Skip, "decoys": Armed}[a.Server]
		if w != "" && a.Do != w {
			t.Errorf("-servers: %s %s, want %s", a.Server, a.Do, w)
		}
	}
	if _, _, err := Plan(f, []string{"nope"}); err == nil {
		t.Error("unknown -servers name accepted")
	}
}

func TestGatewayPath(t *testing.T) {
	if p := GatewayPath("/d", "claude-desktop", "My Server/v2"); p != filepath.Join("/d", "gw-claude-desktop-my-server-v2.json") {
		t.Errorf("%s", p)
	}
	if p := GatewayPath("/d", "x", "!!"); p != filepath.Join("/d", "gw-x-server.json") {
		t.Errorf("%s", p)
	}
}
