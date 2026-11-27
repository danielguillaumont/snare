package clientcfg

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/danielguillaumont/snare/internal/advise"
)

// Candidate is a client config location snare init checks (docs/M14-first-run.md §1).
type Candidate struct {
	Client string
	Path   string
}

// Candidates lists the known MCP client config locations for one machine and working
// directory. appData is %APPDATA% on Windows.
func Candidates(goos, home, appData, cwd string) []Candidate {
	var out []Candidate
	add := func(client string, parts ...string) {
		if parts[0] == "" {
			return
		}
		out = append(out, Candidate{client, filepath.Join(parts...)})
	}
	switch goos {
	case "windows":
		add("claude-desktop", appData, "Claude", "claude_desktop_config.json")
	case "darwin":
		add("claude-desktop", home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	default:
		add("claude-desktop", home, ".config", "Claude", "claude_desktop_config.json")
	}
	add("claude-code", cwd, ".mcp.json")
	add("vscode", cwd, ".vscode", "mcp.json")
	add("cursor", home, ".cursor", "mcp.json")
	add("cursor-project", cwd, ".cursor", "mcp.json")
	add("windsurf", home, ".codeium", "windsurf", "mcp_config.json")
	return out
}

// Actions for one server.
const (
	Wrap  = "wrap"
	Armed = "armed"
	Skip  = "skip"
)

// Action is what snare init will do with one server, and why.
type Action struct {
	Server string
	Do     string
	Why    string
}

var capWords = map[advise.Capability]string{
	advise.UntrustedInput: "untrusted input",
	advise.PrivateData:    "private data",
	advise.Exfiltration:   "a way out",
}

// Plan decides an action per server, in file order. With only set, exactly those servers
// are wrapped (when they can be); otherwise every local server advise gives a capability.
func Plan(f *File, only []string) ([]Action, advise.Report, error) {
	servers := f.Servers()
	cfg := advise.Config{MCPServers: map[string]advise.Server{}}
	names := map[string]bool{}
	for _, s := range servers {
		names[s.Name] = true
		cfg.MCPServers[s.Name] = advise.Server{Command: s.Command, Args: s.Args, URL: s.URL, Type: s.Type, Env: s.Env}
	}
	for _, n := range only {
		if !names[n] {
			return nil, advise.Report{}, fmt.Errorf("-servers %q: no such server in %s", n, f.Path)
		}
	}
	rep := advise.Analyze(cfg, nil)
	byName := map[string]advise.ServerReport{}
	for _, sr := range rep.Servers {
		byName[sr.Name] = sr
	}
	var out []Action
	for _, s := range servers {
		sr := byName[s.Name]
		a := Action{Server: s.Name}
		var caps []string
		for _, c := range sr.Capabilities {
			caps = append(caps, capWords[c])
		}
		switch {
		case s.IsSnare():
			a.Do = Armed
			if gw, ok := s.GatewayConfig(); ok {
				a.Why = "already behind snare gateway (" + gw + ")"
			} else {
				a.Why = "Snare's own decoy server"
			}
		case s.Remote():
			a.Do, a.Why = Skip, "remote server: the gateway wraps local servers only (snare plant mcp adds decoys beside it)"
		case len(only) > 0 && slices.Contains(only, s.Name):
			a.Do, a.Why = Wrap, "named in -servers"
		case len(only) > 0:
			a.Do, a.Why = Skip, "not in -servers"
		case len(caps) > 0:
			a.Do, a.Why = Wrap, strings.Join(caps, ", ")
		case sr.Unknown:
			a.Do, a.Why = Skip, "could not be classified: name it in -servers to wrap it anyway"
		default:
			a.Do, a.Why = Skip, "no untrusted input, private data or way out found"
		}
		out = append(out, a)
	}
	return out, rep, nil
}

// GatewayPath is where snare init writes the gateway config for one server.
func GatewayPath(dir, client, server string) string {
	return filepath.Join(dir, "gw-"+slug(client)+"-"+slug(server)+".json")
}

func slug(s string) string {
	b := []byte(strings.ToLower(s))
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			b[i] = '-'
		}
	}
	out := strings.Trim(string(b), "-")
	if out == "" {
		return "server"
	}
	return out
}
