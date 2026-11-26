package advise

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func caps(cs ...Capability) []Capability {
	if cs == nil {
		return []Capability{}
	}
	return cs
}

func TestClassifyServers(t *testing.T) {
	cases := []struct {
		name string
		s    Server
		kind string
		want []Capability
	}{
		{"github", Server{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github"}}, "code host", caps(UntrustedInput, PrivateData, Exfiltration)},
		{"files", Server{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/home/me/docs"}}, "filesystem", caps(PrivateData)},
		{"pg", Server{Command: "uvx", Args: []string{"mcp-server-postgres"}}, "database", caps(PrivateData)},
		{"web", Server{Command: "uvx", Args: []string{"mcp-server-fetch"}}, "web access", caps(UntrustedInput, Exfiltration)},
		{"inbox", Server{Command: "npx", Args: []string{"@gongrzhe/server-gmail-autoauth-mcp"}}, "email", caps(UntrustedInput, Exfiltration)},
		{"kb", Server{Type: "http", URL: "https://mcp.notion.com/mcp"}, "documents / knowledge base", caps(UntrustedInput, PrivateData)},
		{"memory", Server{Command: "npx", Args: []string{"@modelcontextprotocol/server-memory"}}, "local utility", caps()},
		{"snare", Server{Command: "snare", Args: []string{"decoy-mcp", "-config", "decoy-mcp.json"}}, "snare decoy server", caps()},
		{"acme-internal", Server{Command: "./bin/acme"}, "unknown", caps()},
		// Token matching, not substrings: "offset" must not read as "fs", "dbx" not as "db".
		{"offsetter", Server{Command: "dbx-tool"}, "unknown", caps()},
	}
	for _, c := range cases {
		r := classifyServer(c.name, c.s, nil)
		if r.Kind != c.kind || !reflect.DeepEqual(r.Capabilities, c.want) {
			t.Errorf("%s: kind %q caps %v, want %q %v (evidence %v)", c.name, r.Kind, r.Capabilities, c.kind, c.want, r.Evidence)
		}
	}
}

// A directory argument is data. A filesystem root called "docs" or "mail" must not make the
// server look like a knowledge base or an inbox.
func TestPathArgumentsDoNotClassify(t *testing.T) {
	r := classifyServer("files", Server{Command: "npx", Args: []string{"@modelcontextprotocol/server-filesystem", "/home/me/mail", "C:\\Users\\me\\docs"}}, nil)
	if !reflect.DeepEqual(r.Capabilities, caps(PrivateData)) {
		t.Fatalf("caps %v from path names", r.Capabilities)
	}
	if !reflect.DeepEqual(r.Paths, []string{"/home/me/mail", "C:\\Users\\me\\docs"}) {
		t.Fatalf("paths %v", r.Paths)
	}
}

func TestTrifectaAgent(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "..", "examples", "agent-configs", "support-agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep := Analyze(cfg, nil)
	if !rep.Trifecta || rep.Risk != "high" {
		t.Fatalf("risk %s trifecta %v legs %v", rep.Risk, rep.Trifecta, rep.Legs)
	}
	text := recText(rep)
	for _, want := range []string{
		"snare plant mcp", // decoys on the private-data path
		"snare plant repo /srv/support/shared-docs", // honey creds in the exposed root
		"canary record",  // customer-db
		"SNARE_ZONE",     // fetch can make outbound requests
		"seeded item in", // canary in an untrusted source
	} {
		if !strings.Contains(text, want) {
			t.Errorf("recommendations lack %q:\n%s", want, text)
		}
	}
}

func TestLowRiskAgent(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "..", "examples", "agent-configs", "notes-assistant.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep := Analyze(cfg, nil)
	if rep.Trifecta || rep.Risk != "low" {
		t.Fatalf("risk %s legs %v", rep.Risk, rep.Legs)
	}
	if strings.Contains(recText(rep), "snare plant mcp") {
		t.Fatal("recommends decoys for a low-risk agent")
	}
}

// Without tools the internal server is unknown; with a tools/list dump it is classified, and
// the dump replaces any name-based guess.
func TestToolsDumpClassifiesAndOverrides(t *testing.T) {
	dir := filepath.Join("..", "..", "examples", "agent-configs")
	cfg, err := LoadConfig(filepath.Join(dir, "internal-tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep := Analyze(cfg, nil)
	if !rep.Servers[0].Unknown || !strings.Contains(recText(rep), "-tools") {
		t.Fatalf("unknown server not flagged: %+v", rep.Servers[0])
	}
	tools, err := LoadTools(filepath.Join(dir, "internal-tools.tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep = Analyze(cfg, tools)
	s := rep.Servers[0]
	if s.From != "tools" || !reflect.DeepEqual(s.Capabilities, caps(UntrustedInput, PrivateData, Exfiltration)) || !rep.Trifecta {
		t.Fatalf("with tools: %+v", s)
	}

	// Name says "github" (all three), tools say read-only issue listing: tools win.
	gh := classifyServer("github", Server{Command: "npx", Args: []string{"@modelcontextprotocol/server-github"}},
		[]Tool{{Name: "list_issues", Description: "List issues in a repository"}})
	if !reflect.DeepEqual(gh.Capabilities, caps(UntrustedInput, PrivateData)) {
		t.Fatalf("tools did not override the name: %v", gh.Capabilities)
	}
}

func TestDecoyServerIsNotACapability(t *testing.T) {
	cfg := Config{MCPServers: map[string]Server{
		"files": {Command: "npx", Args: []string{"@modelcontextprotocol/server-filesystem", "/data"}},
		"tools": {Command: "snare", Args: []string{"decoy-mcp", "-config", "d.json"}},
	}}
	rep := Analyze(cfg, map[string][]Tool{"tools": {{Name: "send_email", Description: "Send an email"}}})
	if !rep.HasDecoys || len(rep.Legs[Exfiltration]) != 0 {
		t.Fatalf("decoy tools counted as capabilities: %v", rep.Legs)
	}
}

func TestVSCodeServersKeyAndBadInput(t *testing.T) {
	if _, err := LoadConfig(filepath.Join("..", "..", "examples", "agent-configs", "internal-tools.json")); err != nil {
		t.Fatalf("VS Code 'servers' key: %v", err)
	}
	if _, err := LoadConfig(filepath.Join("..", "..", "go.mod")); err == nil {
		t.Fatal("accepted a non-JSON file")
	}
}

func recText(r Report) string {
	var b strings.Builder
	for _, x := range r.Recommendations {
		b.WriteString(x.Why + " | " + x.Action + " | " + x.Command + "\n")
	}
	return b.String()
}
