// Package gateway is the Snare gateway: a stdio MCP proxy between a client and a real MCP
// server (docs/M6-gateway.md). It relays every message it doesn't own byte for byte, adds
// decoys to the real server's tool list, answers calls to them, and reports honey values
// it sees in the arguments of real tool calls.
//
// Tool arguments are scanned in memory and never logged, stored or sent. The only thing it
// reports is a matched honey token, which the agent already holds.
package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danielguillaumont/snare/internal/decoys"
	"github.com/danielguillaumont/snare/internal/token"
)

// Config is the file written by `snare plant gateway`. It holds decoy tokens (as the
// decoy-mcp config does) and salted fingerprints of honey values, never a signing key and
// never a honey value.
type Config struct {
	CallbackURL string `json:"callback_url"`
	URLPath     string `json:"url_path,omitempty"`
	// Style is how decoy names are written: "auto" (match the real server's tools), "adapt"
	// (the real server's namespace, verbs and conventions; docs/M12-adaptive-deception.md),
	// "snake", "camel", "kebab", or "catalog" (the public catalog names; easy to fingerprint).
	Style  string                     `json:"style"`
	Seed   uint64                     `json:"seed"`
	Decoys map[string]string          `json:"decoys"` // catalog name -> token
	Names  map[string]decoys.Override `json:"names,omitempty"`

	Salt         string   `json:"salt,omitempty"`
	Fingerprints []string `json:"fingerprints,omitempty"`

	// Contain turns on containment (docs/M8-containment.md). Nil is off, the default.
	Contain *Contain `json:"contain,omitempty"`
	// Provenance configures the input ledger (docs/M9-provenance.md).
	Provenance *Provenance `json:"provenance,omitempty"`
	// Heartbeat sends a synthetic touch at start and on an interval (docs/M11-heartbeat.md).
	// Nil is off.
	Heartbeat *Heartbeat `json:"heartbeat,omitempty"`
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
	if c.Contain != nil && c.Contain.StateFile == "" {
		c.Contain.StateFile = path + ".frozen"
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.CallbackURL == "" {
		return errors.New("callback_url is required")
	}
	switch c.Style {
	case "auto", "adapt", "snake", "camel", "kebab", "catalog":
	default:
		return fmt.Errorf("style %q: want auto, adapt, snake, camel, kebab or catalog", c.Style)
	}
	for name, tok := range c.Decoys {
		if _, ok := decoys.Get(name); !ok {
			return fmt.Errorf("decoy %q is not in the screened catalog", name)
		}
		if tok == "" {
			return fmt.Errorf("decoy %q has no token", name)
		}
	}
	for canon := range c.Names {
		if _, ok := c.Decoys[canon]; !ok {
			return fmt.Errorf("names: %q is not a configured decoy", canon)
		}
	}
	if len(c.Fingerprints) > 0 && len(c.Salt) < 16 {
		return errors.New("fingerprints need a salt of at least 16 characters")
	}
	if c.Heartbeat != nil {
		if _, err := c.Heartbeat.interval(); err != nil {
			return err
		}
	}
	if c.Contain != nil {
		return c.Contain.validate()
	}
	return nil
}

// Gateway relays one client session to one server.
type Gateway struct {
	Cfg     Config
	HTTP    *http.Client
	Log     *slog.Logger
	Session string // random per process when empty

	matcher *token.Matcher

	mu      sync.Mutex
	pending map[string]bool           // ids of the client's tools/list requests awaiting a reply
	real    map[string]bool           // real tool names seen so far
	style   string                    // resolved decoy style, fixed at the first tools/list reply
	byName  map[string]string         // shown decoy name -> catalog name
	descs   map[string]string         // catalog name -> description shown
	params  map[string][]decoys.Param // catalog name -> arguments shown, when adapted (M12)
	tools   []decoys.RealTool         // real tools seen so far, for style adapt
	frozen  bool                      // contained (M8)
	// persisted: the freeze is in the state file, so removing the file releases it.
	persisted bool
	calls     map[string]callInfo // forwarded real tool calls awaiting a result (M9)
	ledger    []input             // the last results, oldest first (M9)
	now       func() time.Time    // tests

	outMu sync.Mutex // serializes writes to the client
	wg    sync.WaitGroup
}

func (g *Gateway) init() {
	if g.Log == nil {
		g.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if g.HTTP == nil {
		g.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if g.Session == "" {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		g.Session = "s" + hex.EncodeToString(b)
	}
	g.pending, g.real, g.calls = map[string]bool{}, map[string]bool{}, map[string]callInfo{}
	if len(g.Cfg.Fingerprints) > 0 {
		set := token.FingerprintSet{}
		for _, fp := range g.Cfg.Fingerprints {
			set.Add(fp)
		}
		g.matcher = token.NewMatcher(g.Cfg.Salt, set)
	}
	g.loadFreeze()
}

// Run relays until the server closes its output, then waits briefly for callbacks in flight.
// When the client closes its input, the server's input is closed.
func (g *Gateway) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer, serverIn io.WriteCloser, serverOut io.Reader) error {
	g.init()
	stop := make(chan struct{})
	if hb := g.Cfg.Heartbeat; hb != nil {
		if every, err := hb.interval(); err == nil {
			go g.heartbeat(ctx, every, stop)
		}
	}
	go func() {
		err := eachLine(clientIn, func(line []byte) error { return g.fromClient(ctx, line, clientOut, serverIn) })
		if err != nil {
			g.Log.Error("client side", "err", err)
		}
		_ = serverIn.Close()
	}()
	err := eachLine(serverOut, func(line []byte) error { return g.write(clientOut, g.fromServer(line)) })
	close(stop)
	done := make(chan struct{})
	go func() { g.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return err
}

// eachLine calls fn with every newline-terminated line of r, newline included, and with a
// final unterminated line if there is one.
func eachLine(r io.Reader, fn func([]byte) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if ferr := fn(line); ferr != nil {
				return ferr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (g *Gateway) write(w io.Writer, b []byte) error {
	g.outMu.Lock()
	defer g.outMu.Unlock()
	_, err := w.Write(b)
	return err
}

type message struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
	Result json.RawMessage `json:"result,omitempty"`
}

func idKey(id json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, id) != nil {
		return string(id)
	}
	return b.String()
}

// fromClient handles one client line: answers a decoy call, or inspects and forwards.
func (g *Gateway) fromClient(ctx context.Context, line []byte, clientOut io.Writer, serverIn io.Writer) error {
	t := bytes.TrimSpace(line)
	contain := g.Cfg.Contain
	if len(t) > 0 && t[0] == '{' {
		var m message
		if json.Unmarshal(t, &m) == nil {
			switch m.Method {
			case "tools/list":
				if len(m.ID) > 0 {
					g.mu.Lock()
					g.pending[idKey(m.ID)] = true
					g.mu.Unlock()
				}
			case "tools/call":
				if canon, ok := g.decoyFor(m.Params.Name); ok && len(m.ID) > 0 {
					action := ""
					if contain.onRecon() && g.freeze("recon", m.Params.Name) {
						action = "frozen"
					}
					g.fire(ctx, g.Cfg.Decoys[canon], "tool", m.Params.Name, action)
					return g.write(clientOut, decoyReply(m.ID))
				}
				if contain != nil {
					return g.containCall(ctx, m, clientOut, serverIn, line)
				}
				g.inspect(ctx, m.Params.Arguments, m.Params.Name)
				g.track(m)
			}
		}
	} else if bytes.Contains(t, []byte(`"tools/call"`)) {
		if contain != nil && len(t) > 0 && t[0] == '[' {
			if reply, handled := g.containBatch(ctx, t); handled {
				if reply == nil {
					return nil
				}
				return g.write(clientOut, reply)
			}
		}
		g.inspect(ctx, t, "batch") // a batch is relayed whole; still look for honey values
	}
	_, err := serverIn.Write(line)
	return err
}

// containCall handles a real tool call with containment on: blocked while frozen, and
// blocked (then frozen) when it carries a honey value. Otherwise it is forwarded unchanged.
func (g *Gateway) containCall(ctx context.Context, m message, clientOut, serverIn io.Writer, line []byte) error {
	block := func() error {
		if len(m.ID) == 0 {
			return nil // a notification gets no reply
		}
		return g.write(clientOut, failedReply(m.ID))
	}
	if g.isFrozen() {
		return block()
	}
	if body, ok := g.find(m.Params.Arguments); ok {
		g.freeze("exfiltration", m.Params.Name)
		g.fire(ctx, body, "egress", m.Params.Name, "blocked")
		return block()
	}
	g.track(m)
	_, err := serverIn.Write(line)
	return err
}

// fromServer returns the line to send to the client: unchanged, except the final page of a
// reply to the client's own tools/list, which gets the decoys.
func (g *Gateway) fromServer(line []byte) []byte {
	t := bytes.TrimSpace(line)
	if len(t) == 0 || t[0] != '{' {
		return line
	}
	var m message
	if json.Unmarshal(t, &m) != nil || len(m.ID) == 0 || m.Method != "" {
		return line
	}
	key := idKey(m.ID)
	g.mu.Lock()
	defer g.mu.Unlock()
	if ci, ok := g.calls[key]; ok { // a real tool's result: into the ledger, line unchanged
		delete(g.calls, key)
		if len(m.Result) > 0 {
			g.record(ci, m.Result)
		}
		return line
	}
	if len(m.Result) == 0 || !g.pending[key] {
		return line
	}
	delete(g.pending, key)
	out, err := g.inject(t)
	if err != nil {
		g.Log.Warn("tools/list reply left unchanged", "err", err)
		return line
	}
	return append(out, '\n')
}

// inject adds decoys to a tools/list response. Called with g.mu held.
func (g *Gateway) inject(msg []byte) ([]byte, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(msg, &env); err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(env["result"], &result); err != nil {
		return nil, err
	}
	var tools []json.RawMessage
	if raw, ok := result["tools"]; ok {
		if err := json.Unmarshal(raw, &tools); err != nil {
			return nil, err
		}
	}
	for _, raw := range tools {
		var t struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			InputSchema struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"inputSchema"`
		}
		if json.Unmarshal(raw, &t) == nil && t.Name != "" {
			if !g.real[t.Name] {
				rt := decoys.RealTool{Name: t.Name, Description: t.Description}
				for p := range t.InputSchema.Properties {
					rt.Params = append(rt.Params, p)
				}
				sort.Strings(rt.Params)
				g.tools = append(g.tools, rt)
			}
			g.real[t.Name] = true
		}
	}
	var cursor string
	_ = json.Unmarshal(result["nextCursor"], &cursor)
	if cursor != "" {
		return msg, nil // not the final page: decoys go on the last one
	}
	if g.byName == nil {
		if err := g.chooseNames(); err != nil {
			return nil, err
		}
	}
	for _, t := range decoys.Catalog { // catalog order is stable
		if _, ok := g.Cfg.Decoys[t.Name]; !ok {
			continue
		}
		shown := g.shownName(t.Name)
		if shown == "" || g.real[shown] {
			continue // real tools always win
		}
		schema := t.InputSchema()
		if ps, ok := g.params[t.Name]; ok {
			schema = decoys.Tool{Params: ps}.InputSchema()
		}
		entry, _ := json.Marshal(map[string]any{"name": shown, "description": g.descs[t.Name], "inputSchema": schema})
		tools = append(tools, entry)
	}
	if result["tools"], _ = json.Marshal(tools); result["tools"] == nil {
		return nil, errors.New("encode tools")
	}
	if env["result"], _ = json.Marshal(result); env["result"] == nil {
		return nil, errors.New("encode result")
	}
	return json.Marshal(env)
}

func (g *Gateway) shownName(canon string) string {
	for n, c := range g.byName {
		if c == canon {
			return n
		}
	}
	return ""
}

// chooseNames fixes the decoy names, matching the real tools' style when Style is auto, or
// their whole vocabulary when it is adapt.
// Called with g.mu held, after the first final tools/list page.
func (g *Gateway) chooseNames() error {
	style := g.Cfg.Style
	if style == "auto" {
		names := make([]string, 0, len(g.real))
		for n := range g.real {
			names = append(names, n)
		}
		style = DetectStyle(names)
	}
	g.style = style
	g.byName, g.descs = map[string]string{}, map[string]string{}
	if style == "catalog" {
		for _, t := range decoys.Catalog {
			name, desc := t.Name, t.Description
			if o, ok := g.Cfg.Names[t.Name]; ok {
				name = o.Name
				if o.Description != "" {
					desc = o.Description
				}
			}
			g.byName[name], g.descs[t.Name] = t.Name, desc
		}
		return nil
	}
	var picks []decoys.Choice
	var err error
	if style == "adapt" {
		picks, err = decoys.Adapt(decoys.Learn(g.tools), g.Cfg.Seed, g.Cfg.Names, g.real)
	} else {
		picks, err = decoys.Pick(g.Cfg.Seed, style, g.Cfg.Names)
	}
	if err != nil {
		return err
	}
	g.params = map[string][]decoys.Param{}
	for _, c := range picks {
		g.byName[c.Name], g.descs[c.Canonical] = c.Canonical, c.Description
		if style == "adapt" {
			g.params[c.Canonical] = c.Params
		}
	}
	return nil
}

// decoyFor reports whether a called name is one of this session's decoys.
func (g *Gateway) decoyFor(name string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if name == "" || g.real[name] || g.byName == nil {
		return "", false
	}
	canon, ok := g.byName[name]
	if !ok {
		return "", false
	}
	_, configured := g.Cfg.Decoys[canon]
	return canon, configured
}

// DetectStyle returns the most common naming style among tool names: snake, camel or kebab
// (snake when there is no signal).
func DetectStyle(names []string) string { return decoys.DetectStyle(names) }

func decoyReply(id json.RawMessage) []byte {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	text, _ := json.Marshal(map[string]string{"status": "accepted", "request_id": "req_" + hex.EncodeToString(b)})
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(text)}}, "isError": false,
	}})
	return append(out, '\n')
}

// inspect looks for honey values in a real tool call's arguments. It never blocks the call,
// and a failure here never affects relaying.
func (g *Gateway) inspect(ctx context.Context, args []byte, tool string) {
	if body, ok := g.find(args); ok {
		g.fire(ctx, body, "egress", tool, "")
	}
}

// find returns the honey value in args, if any. A failure is treated as no match.
func (g *Gateway) find(args []byte) (body string, ok bool) {
	if g.matcher == nil || len(args) == 0 {
		return "", false
	}
	defer func() {
		if r := recover(); r != nil {
			g.Log.Error("inspection failed; call relayed", "panic", r)
			body, ok = "", false
		}
	}()
	return g.matcher.Find(string(args))
}

// DefaultURLPath matches the callback server's default (admin.DefaultURLPath).
const DefaultURLPath = "/v1/"

// fire sends a callback carrying tok and the session context, in the background. action
// is the containment taken ("blocked", "frozen") or empty.
// touchURL is the callback URL that touches tok, with query q.
func touchURL(cfg Config, tok string, q url.Values) string {
	p := cfg.URLPath
	if p == "" {
		p = DefaultURLPath
	}
	p = "/" + strings.Trim(p, "/") + "/"
	if p == "//" {
		p = "/"
	}
	return strings.TrimRight(cfg.CallbackURL, "/") + p + url.PathEscape(tok) + "?" + q.Encode()
}

func (g *Gateway) fire(ctx context.Context, tok, layer, tool, action string) {
	q := url.Values{"layer": {layer}, "session": {g.Session}}
	if layer != layerHeartbeat { // a heartbeat is about the path, not the agent: no tool, no ledger
		q.Set("tool", contextSafe(tool))
		if action != "" {
			q.Set("contain", action)
		}
		g.ledgerParams(q)
	}
	u := touchURL(g.Cfg, tok, q)
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for attempt := 0; attempt < 3; attempt++ {
			req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), "GET", u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "snare-gateway/1")
			resp, err := g.HTTP.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 500 {
					return
				}
			}
			time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
		}
		g.Log.Error("callback gave up", "layer", layer)
	}()
}

// contextSafe maps a tool name onto the listener's context charset ([A-Za-z0-9._-], ≤ 64).
func contextSafe(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			b[i] = '_'
		}
	}
	if len(b) > 64 {
		b = b[:64]
	}
	if len(b) == 0 {
		return "unknown"
	}
	return string(b)
}
