// Package clientcfg reads and rewrites MCP client config files (claude_desktop_config.json,
// .mcp.json, .vscode/mcp.json and the like) for snare init (docs/M14-first-run.md §1).
//
// It changes only the server entries it is asked to change. Key order and unknown fields
// survive at every level; whitespace is normalised to two-space indentation.
package clientcfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Server is the part of a server entry snare reads. Raw keeps the entry as written.
type Server struct {
	Name    string
	Command string
	Args    []string
	URL     string
	Env     map[string]string
	Type    string
}

// Remote reports a server reached over the network rather than started locally.
func (s Server) Remote() bool { return s.Command == "" }

// GatewayConfig returns the gateway config path when the entry already runs behind
// snare gateway.
func (s Server) GatewayConfig() (string, bool) {
	if !isSnare(s.Command) || len(s.Args) < 4 || s.Args[0] != "gateway" {
		return "", false
	}
	cfg := ""
	for i := 1; i < len(s.Args); i++ {
		switch s.Args[i] {
		case "-config", "--config":
			if i+1 < len(s.Args) {
				cfg = s.Args[i+1]
			}
		case "--":
			return cfg, cfg != "" && i+1 < len(s.Args)
		}
	}
	return "", false
}

// IsSnare reports a server that is Snare itself (the decoy server or a gateway).
func (s Server) IsSnare() bool { return isSnare(s.Command) }

func isSnare(cmd string) bool {
	b := strings.ToLower(filepath.Base(strings.ReplaceAll(cmd, `\`, "/")))
	return b == "snare" || b == "snare.exe"
}

type member struct {
	key string
	raw json.RawMessage
}

// File is a parsed client config.
type File struct {
	Path    string
	Key     string // "mcpServers" or "servers" (VS Code)
	top     []member
	servers []member
}

// ErrNoServers is returned for a JSON file with no mcpServers or servers object.
var ErrNoServers = errors.New("no mcpServers or servers entries")

// Load reads path. A file that isn't plain JSON (VS Code allows comments) is an error, and
// the caller must leave it alone.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, b)
}

// Parse parses b as the config at path.
func Parse(path string, b []byte) (*File, error) {
	top, err := members(b)
	if err != nil {
		return nil, fmt.Errorf("%s: not plain JSON (%v); edit it by hand", path, err)
	}
	f := &File{Path: path, top: top}
	for _, k := range []string{"mcpServers", "servers"} {
		for _, m := range top {
			if m.key != k {
				continue
			}
			if f.servers, err = members(m.raw); err != nil {
				return nil, fmt.Errorf("%s: %s: %v", path, k, err)
			}
			f.Key = k
			return f, nil
		}
	}
	return nil, fmt.Errorf("%s: %w", path, ErrNoServers)
}

// members splits a JSON object into its members, in order.
func members(b []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	var out []member
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if seen[k] {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		seen[k] = true
		out = append(out, member{k, raw})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	var rest json.RawMessage
	if err := dec.Decode(&rest); err == nil {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

// Servers returns the server entries in file order. An entry that isn't an object is skipped.
func (f *File) Servers() []Server {
	var out []Server
	for _, m := range f.servers {
		var s struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			URL     string            `json:"url"`
			Env     map[string]string `json:"env"`
			Type    string            `json:"type"`
		}
		if json.Unmarshal(m.raw, &s) != nil {
			continue
		}
		out = append(out, Server{Name: m.key, Command: s.Command, Args: s.Args, URL: s.URL, Env: s.Env, Type: s.Type})
	}
	return out
}

func (f *File) index(name string) int {
	for i, m := range f.servers {
		if m.key == name {
			return i
		}
	}
	return -1
}

// setCommand replaces command and args of one entry, keeping its other fields and their order.
func (f *File) setCommand(name, command string, args []string) error {
	i := f.index(name)
	if i < 0 {
		return fmt.Errorf("no server %q", name)
	}
	fields, err := members(f.servers[i].raw)
	if err != nil {
		return fmt.Errorf("server %q: %v", name, err)
	}
	cb, ab := marshal(command), marshal(args)
	put := func(k string, v []byte) {
		for j := range fields {
			if fields[j].key == k {
				fields[j].raw = v
				return
			}
		}
		fields = append(fields, member{k, v})
	}
	put("command", cb)
	put("args", ab)
	f.servers[i].raw = object(fields)
	return nil
}

// Wrap puts server name behind snare gateway: snare gateway -config gw -- <old command>.
func (f *File) Wrap(name, snare, gwConfig string) error {
	for _, s := range f.Servers() {
		if s.Name != name {
			continue
		}
		if s.Remote() {
			return fmt.Errorf("server %q is remote; the gateway wraps local servers only", name)
		}
		if s.IsSnare() {
			return fmt.Errorf("server %q is already Snare", name)
		}
		args := append([]string{"gateway", "-config", gwConfig, "--", s.Command}, s.Args...)
		return f.setCommand(name, snare, args)
	}
	return fmt.Errorf("no server %q", name)
}

// Unwrap restores a wrapped server's original command. It reports whether name was wrapped.
func (f *File) Unwrap(name string) (bool, error) {
	for _, s := range f.Servers() {
		if s.Name != name {
			continue
		}
		if _, ok := s.GatewayConfig(); !ok {
			return false, nil
		}
		for i, a := range s.Args {
			if a == "--" {
				return true, f.setCommand(name, s.Args[i+1], append([]string{}, s.Args[i+2:]...))
			}
		}
	}
	return false, nil
}

// Bytes renders the file: the original members in order, with the server object updated.
func (f *File) Bytes() []byte {
	top := make([]member, len(f.top))
	copy(top, f.top)
	for i := range top {
		if top[i].key == f.Key {
			top[i].raw = object(f.servers)
		}
	}
	var out bytes.Buffer
	if err := json.Indent(&out, object(top), "", "  "); err != nil {
		panic(err) // object() only joins values that already parsed
	}
	out.WriteByte('\n')
	return out.Bytes()
}

// marshal encodes v without HTML escaping, so "&" in an argument stays "&".
func marshal(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err) // strings and string slices always encode
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}

func object(ms []member) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(marshal(m.key))
		b.WriteByte(':')
		b.Write(m.raw)
	}
	b.WriteByte('}')
	return b.Bytes()
}
