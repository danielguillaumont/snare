package gateway

// The input ledger (docs/M9-provenance.md): what the real server returned to the agent,
// as fingerprints, so a touch can say what the agent read just before.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Provenance configures the ledger. The ledger itself is always on; Names is opt-in.
type Provenance struct {
	// Names sends the call's first identifier-like argument (path, url, …) with each
	// entry. Off by default: it sends argument values to the Snare server.
	Names bool `json:"names,omitempty"`
}

const (
	ledgerSize      = 8
	ledgerTTL       = time.Hour
	maxPendingCalls = 1024
	maxSource       = 128
)

// nameKeys are the arguments a source name is taken from, in order.
var nameKeys = []string{"path", "file", "filename", "uri", "url", "id", "name"}

type input struct {
	tool, fp, src string
	n             int
	at            time.Time
}

type callInfo struct{ tool, src string }

// InputFingerprint is the ledger's fingerprint of a tool result's text: the first 16 hex
// characters of its SHA-256. snare provenance find uses it to name a file.
func InputFingerprint(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:8])
}

// resultText joins a tool result's text content in order (§1).
func resultText(result json.RawMessage) (string, bool) {
	var r struct {
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Resource struct {
				Text string `json:"text"`
			} `json:"resource"`
		} `json:"content"`
	}
	if json.Unmarshal(result, &r) != nil || r.Content == nil {
		return "", false
	}
	var b strings.Builder
	for _, c := range r.Content {
		b.WriteString(c.Text)
		b.WriteString(c.Resource.Text)
	}
	return b.String(), true
}

// sourceName picks the source name from a call's arguments, sanitized; "" if none.
func sourceName(args json.RawMessage) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(args, &m) != nil {
		return ""
	}
	for _, k := range nameKeys {
		var s string
		if json.Unmarshal(m[k], &s) == nil && s != "" {
			return sanitizeSource(s)
		}
	}
	return ""
}

func sanitizeSource(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '/' || c == ':') {
			b[i] = '_'
		}
	}
	if len(b) > maxSource {
		b = b[len(b)-maxSource:] // keep the end: the file name is the useful part
	}
	return string(b)
}

// track remembers a forwarded real tool call so its result can be recorded.
func (g *Gateway) track(m message) {
	if len(m.ID) == 0 {
		return
	}
	ci := callInfo{tool: m.Params.Name}
	if p := g.Cfg.Provenance; p != nil && p.Names {
		ci.src = sourceName(m.Params.Arguments)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.calls) < maxPendingCalls {
		g.calls[idKey(m.ID)] = ci
	}
}

// record adds a result to the ledger. Called with g.mu held.
func (g *Gateway) record(ci callInfo, result json.RawMessage) {
	text, ok := resultText(result)
	if !ok {
		return
	}
	g.ledger = append(g.ledger, input{tool: ci.tool, src: ci.src, fp: InputFingerprint(text),
		n: utf8.RuneCountInString(text), at: g.clock()})
	if len(g.ledger) > ledgerSize {
		g.ledger = append(g.ledger[:0], g.ledger[len(g.ledger)-ledgerSize:]...)
	}
}

func (g *Gateway) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// ledgerParams adds the live ledger to a callback's query, oldest first (§2).
func (g *Gateway) ledgerParams(q url.Values) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.clock()
	i := 0
	for _, in := range g.ledger {
		age := now.Sub(in.at)
		if age > ledgerTTL {
			continue
		}
		if age < 0 {
			age = 0
		}
		k := strconv.Itoa(i)
		q.Set("in"+k, contextSafe(in.tool)+"~"+in.fp+"~"+strconv.Itoa(in.n)+"~"+strconv.Itoa(int(age/time.Second)))
		if in.src != "" {
			q.Set("src"+k, in.src)
		}
		i++
	}
}

// ResultFingerprint is the fingerprint the ledger records for a tools/call result, and
// whether the result has content at all.
func ResultFingerprint(result json.RawMessage) (string, bool) {
	text, ok := resultText(result)
	if !ok {
		return "", false
	}
	return InputFingerprint(text), true
}
