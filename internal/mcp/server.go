// Package mcp implements the decoy MCP server: a stdio JSON-RPC 2.0 server that exposes
// decoy tools from the screened catalog and fires a Snare callback when one is called.
//
// Tool arguments are never forwarded anywhere: they may contain the victim's data.
package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/danielguillaumont/snare/internal/decoys"
)

const ProtocolVersion = "2025-06-18"

// Config is the file written by `snare plant mcp` and read by `snare decoy-mcp`.
type Config struct {
	ServerName  string `json:"server_name"`  // name advertised in initialize
	CallbackURL string `json:"callback_url"` // e.g. https://cb.example.com
	// URLPath is the path before the token, matching the server's SNARE_URL_PATH so decoy
	// callbacks look like the install's other honey URLs. Empty means DefaultURLPath.
	URLPath string            `json:"url_path,omitempty"`
	Tools   map[string]string `json:"tools"` // catalog decoy name -> token
	// Names is what agents see for each catalog decoy (per-install names, M3a-fix). A decoy
	// without an entry is shown under its catalog name.
	Names map[string]decoys.Override `json:"names,omitempty"`
}

// Shown returns the name and description agents see for a catalog decoy.
func (c Config) Shown(canonical string) (name, description string) {
	t, _ := decoys.Get(canonical)
	name, description = t.Name, t.Description
	if o, ok := c.Names[canonical]; ok {
		name = o.Name
		if o.Description != "" {
			description = o.Description
		}
	}
	return name, description
}

// resolve maps a name an agent called back to its catalog decoy.
func (c Config) resolve(shown string) (string, bool) {
	for canon := range c.Tools {
		if n, _ := c.Shown(canon); n == shown {
			return canon, true
		}
	}
	return "", false
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.CallbackURL == "" {
		return fmt.Errorf("callback_url is required")
	}
	if len(c.Tools) == 0 {
		return fmt.Errorf("no tools configured")
	}
	for name, tok := range c.Tools {
		if _, ok := decoys.Get(name); !ok {
			return fmt.Errorf("tool %q is not in the screened decoy catalog", name)
		}
		if tok == "" {
			return fmt.Errorf("tool %q has no token", name)
		}
	}
	seen := map[string]string{}
	for canon := range c.Names {
		if _, ok := c.Tools[canon]; !ok {
			return fmt.Errorf("names: %q is not a configured tool", canon)
		}
	}
	for canon := range c.Tools {
		n, _ := c.Shown(canon)
		if !decoys.ValidName(n) {
			return fmt.Errorf("names: invalid tool name %q for %s", n, canon)
		}
		if prev, dup := seen[n]; dup {
			return fmt.Errorf("names: %q shown for both %s and %s", n, prev, canon)
		}
		seen[n] = canon
	}
	return nil
}

type Server struct {
	Cfg  Config
	HTTP *http.Client
	Log  *slog.Logger

	wg sync.WaitGroup
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve reads requests from r and writes responses to w until r is exhausted, then waits
// for in-flight callbacks.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	if s.Log == nil {
		s.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if s.HTTP == nil {
		s.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	defer s.wg.Wait()
	enc := json.NewEncoder(w) // Encode appends '\n': newline-delimited framing
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			if err := enc.Encode(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}}); err != nil {
				return err
			}
			continue
		}
		res, rerr := s.handle(ctx, req)
		if len(req.ID) == 0 { // notification: no response
			continue
		}
		if err := enc.Encode(response{JSONRPC: "2.0", ID: req.ID, Result: res, Error: rerr}); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		name := s.Cfg.ServerName
		if name == "" {
			name = "internal-ops"
		}
		return map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": name, "version": "1.4.2"},
		}, nil
	case "notifications/initialized", "notifications/cancelled":
		return nil, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		var tools []map[string]any
		for _, t := range decoys.Catalog { // catalog order is stable
			if _, ok := s.Cfg.Tools[t.Name]; ok {
				name, desc := s.Cfg.Shown(t.Name)
				tools = append(tools, map[string]any{"name": name, "description": desc, "inputSchema": t.InputSchema()})
			}
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		canon, ok := s.Cfg.resolve(p.Name)
		if !ok {
			return nil, &rpcError{-32602, "unknown tool: " + p.Name}
		}
		tok := s.Cfg.Tools[canon]
		s.fire(ctx, p.Name, tok)
		body, _ := json.Marshal(map[string]string{"status": "accepted", "request_id": randID()})
		return map[string]any{"content": []map[string]any{{"type": "text", "text": string(body)}}, "isError": false}, nil
	default:
		return nil, &rpcError{-32601, "method not found"}
	}
}

// DefaultURLPath matches the callback server's default (admin.DefaultURLPath).
const DefaultURLPath = "/v1/"

// fire sends the callback in the background. Only the tool name is sent, never arguments.
// The listener finds the token anywhere in the URL, so the path is cosmetic, not routing.
func (s *Server) fire(ctx context.Context, tool, tok string) {
	p := s.Cfg.URLPath
	if p == "" {
		p = DefaultURLPath
	}
	p = "/" + strings.Trim(p, "/") + "/"
	if p == "//" {
		p = "/"
	}
	u := strings.TrimRight(s.Cfg.CallbackURL, "/") + p + url.PathEscape(tok) + "?tool=" + url.QueryEscape(tool)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for attempt := 0; attempt < 3; attempt++ {
			req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), "GET", u, nil)
			if err != nil {
				s.Log.Error("callback", "err", err)
				return
			}
			req.Header.Set("User-Agent", "snare-decoy-mcp/1")
			resp, err := s.HTTP.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 500 {
					s.Log.Info("decoy tool called", "tool", tool)
					return
				}
			}
			s.Log.Warn("callback failed, retrying", "tool", tool, "attempt", attempt+1, "err", err)
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
		s.Log.Error("callback gave up", "tool", tool)
	}()
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}
