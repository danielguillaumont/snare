package clientcfg

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const desktop = `{
  "globalShortcut": "Ctrl+Space",
  "mcpServers": {
    "zeta-files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"], "env": {"A": "1"}, "x-note": "keep me"},
    "alpha-web": {"url": "https://mcp.example.test/sse", "type": "sse"},
    "mail": {"args": ["--q", "a&b"], "command": "mail-mcp"}
  },
  "zz-unknown": [1, 2, {"deep": true}]
}`

func load(t *testing.T, s string) *File {
	t.Helper()
	f, err := Parse("cfg.json", []byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func keysInOrder(t *testing.T, b []byte, path ...string) []string {
	t.Helper()
	raw := json.RawMessage(b)
	for _, p := range path {
		ms, err := members(raw)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, m := range ms {
			if m.key == p {
				raw, found = m.raw, true
			}
		}
		if !found {
			t.Fatalf("no key %q", p)
		}
	}
	ms, err := members(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ks []string
	for _, m := range ms {
		ks = append(ks, m.key)
	}
	return ks
}

func TestServersInFileOrder(t *testing.T) {
	f := load(t, desktop)
	ss := f.Servers()
	if f.Key != "mcpServers" || len(ss) != 3 || ss[0].Name != "zeta-files" || ss[2].Name != "mail" {
		t.Fatalf("%s %+v", f.Key, ss)
	}
	if !ss[1].Remote() || ss[0].Remote() {
		t.Error("remote detection")
	}
	vs := load(t, `{"servers": {"gh": {"command": "gh-mcp"}}}`)
	if vs.Key != "servers" || vs.Servers()[0].Command != "gh-mcp" {
		t.Errorf("VS Code shape: %+v", vs.Servers())
	}
}

func TestWrapKeepsEverythingElse(t *testing.T) {
	f := load(t, desktop)
	if err := f.Wrap("zeta-files", "/usr/local/bin/snare", "/home/u/.snare/gw.json"); err != nil {
		t.Fatal(err)
	}
	if err := f.Wrap("mail", "/usr/local/bin/snare", "/home/u/.snare/gw-mail.json"); err != nil {
		t.Fatal(err)
	}
	out := f.Bytes()
	if got := strings.Join(keysInOrder(t, out), ","); got != "globalShortcut,mcpServers,zz-unknown" {
		t.Errorf("top order: %s", got)
	}
	if got := strings.Join(keysInOrder(t, out, "mcpServers"), ","); got != "zeta-files,alpha-web,mail" {
		t.Errorf("server order: %s", got)
	}
	if got := strings.Join(keysInOrder(t, out, "mcpServers", "zeta-files"), ","); got != "command,args,env,x-note" {
		t.Errorf("entry fields: %s", got)
	}
	if !strings.Contains(string(out), `"a&b"`) || !strings.Contains(string(out), `"deep": true`) || !strings.Contains(string(out), `"keep me"`) {
		t.Errorf("content lost or escaped:\n%s", out)
	}
	g := load(t, string(out))
	s := g.Servers()[0]
	if gw, ok := s.GatewayConfig(); !ok || gw != "/home/u/.snare/gw.json" || s.Command != "/usr/local/bin/snare" {
		t.Fatalf("wrapped: %+v", s)
	}
	want := []string{"gateway", "-config", "/home/u/.snare/gw.json", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/data"}
	if strings.Join(s.Args, " ") != strings.Join(want, " ") || s.Env["A"] != "1" {
		t.Errorf("args %v env %v", s.Args, s.Env)
	}

	// Remote servers and Snare itself are refused.
	if err := g.Wrap("alpha-web", "snare", "x"); err == nil {
		t.Error("wrapped a remote server")
	}
	if err := g.Wrap("zeta-files", "snare", "x"); err == nil {
		t.Error("wrapped a gateway twice")
	}

	// Unwrap restores the original command and args exactly.
	for _, n := range []string{"zeta-files", "mail"} {
		if ok, err := g.Unwrap(n); !ok || err != nil {
			t.Fatalf("unwrap %s: %v %v", n, ok, err)
		}
	}
	if ok, _ := g.Unwrap("alpha-web"); ok {
		t.Error("unwrapped a server that wasn't wrapped")
	}
	back := load(t, string(g.Bytes())).Servers()
	orig := load(t, desktop).Servers()
	for i := range orig {
		if back[i].Command != orig[i].Command || strings.Join(back[i].Args, "\x00") != strings.Join(orig[i].Args, "\x00") {
			t.Errorf("%s: %+v, want %+v", orig[i].Name, back[i], orig[i])
		}
	}
}

func TestRefusesWhatItCannotRewriteSafely(t *testing.T) {
	for name, s := range map[string]string{
		"comments":  "{\n  // my servers\n  \"mcpServers\": {}\n}",
		"trailing":  `{"mcpServers": {}} {}`,
		"array":     `[]`,
		"duplicate": `{"mcpServers": {"a": {"command": "x"}, "a": {"command": "y"}}}`,
	} {
		if _, err := Parse("c.json", []byte(s)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := Parse("c.json", []byte(`{"theme": "dark"}`)); !errors.Is(err, ErrNoServers) {
		t.Errorf("no servers: %v", err)
	}
}

func TestGatewayConfigDetection(t *testing.T) {
	for _, c := range []struct {
		s  Server
		ok bool
	}{
		{Server{Command: `C:\tools\snare.exe`, Args: []string{"gateway", "-config", "g.json", "--", "npx", "x"}}, true},
		{Server{Command: "snare", Args: []string{"decoy-mcp", "-config", "d.json"}}, false},
		{Server{Command: "snare", Args: []string{"gateway", "-config", "g.json", "--"}}, false},
		{Server{Command: "npx", Args: []string{"gateway", "-config", "g.json", "--", "x"}}, false},
	} {
		if _, ok := c.s.GatewayConfig(); ok != c.ok {
			t.Errorf("%+v: %v", c.s, ok)
		}
	}
	if !(Server{Command: "/opt/snare"}).IsSnare() || (Server{Command: "snarey"}).IsSnare() {
		t.Error("IsSnare")
	}
}
