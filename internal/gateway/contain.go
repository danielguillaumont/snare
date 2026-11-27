package gateway

// Containment (docs/M8-containment.md): opt-in, off unless the config has a contain block.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Contain turns containment on. A nil *Contain is off.
type Contain struct {
	// At is the earliest stage that contains: "exfiltration" (default) or "recon".
	At string `json:"at,omitempty"`
	// StateFile holds the freeze across restarts. LoadConfig defaults it to the config path
	// plus ".frozen".
	StateFile string `json:"state_file,omitempty"`
}

func (c *Contain) validate() error {
	switch c.At {
	case "", "exfiltration", "recon":
		return nil
	}
	return fmt.Errorf("contain.at %q: want exfiltration or recon", c.At)
}

// onRecon reports whether a decoy call contains.
func (c *Contain) onRecon() bool { return c != nil && c.At == "recon" }

// Frozen is what the state file records. Never arguments.
type Frozen struct {
	At      time.Time `json:"frozen_at"`
	Session string    `json:"session"`
	Stage   string    `json:"stage"`
	Tool    string    `json:"tool"`
}

// ReadFrozen reads a state file. A missing file is (Frozen{}, false, nil).
func ReadFrozen(path string) (Frozen, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Frozen{}, false, nil
	}
	if err != nil {
		return Frozen{}, false, err
	}
	var f Frozen
	if err := json.Unmarshal(b, &f); err != nil {
		// A state file we can't parse still means frozen: fail closed, as containment must.
		return Frozen{Stage: "unknown"}, true, nil
	}
	return f, true, nil
}

func writeFrozen(path string, f Frozen) error {
	b, _ := json.MarshalIndent(f, "", "  ")
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snare-frozen-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmp.Name(), 0o600)
	return os.Rename(tmp.Name(), path)
}

// failedText is the one error a contained agent sees, for a blocked leak and a frozen call
// alike. It names nothing.
const failedText = "The tool call failed. Try again later."

func failedReply(id json.RawMessage) []byte {
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
		"content": []map[string]any{{"type": "text", "text": failedText}}, "isError": true,
	}})
	return append(out, '\n')
}

// failedBatch answers every request in a batch with an error and forwards none of it.
func failedBatch(batch []json.RawMessage) []byte {
	var out []json.RawMessage
	for _, raw := range batch {
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(raw, &m) != nil || len(m.ID) == 0 {
			continue // a notification gets no reply
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID,
			"error": map[string]any{"code": -32603, "message": failedText}})
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil
	}
	b, _ := json.Marshal(out)
	return append(b, '\n')
}

// loadFreeze starts the gateway frozen if the state file says so.
func (g *Gateway) loadFreeze() {
	c := g.Cfg.Contain
	if c == nil || c.StateFile == "" {
		return
	}
	f, ok, err := ReadFrozen(c.StateFile)
	if err != nil {
		g.Log.Error("reading containment state; starting frozen", "err", err)
		ok = true
	}
	if ok {
		g.frozen, g.persisted = true, err == nil
		g.Log.Warn("session starts frozen: an earlier touch contained it; release with snare gateway release",
			"frozen_at", f.At, "stage", f.Stage)
	}
}

// isFrozen reports the freeze. A freeze written to the state file ends when the file is
// removed (snare gateway release), checked on each call while frozen.
func (g *Gateway) isFrozen() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.frozen {
		return false
	}
	if g.persisted {
		if _, ok, err := ReadFrozen(g.Cfg.Contain.StateFile); err == nil && !ok {
			g.frozen, g.persisted = false, false
			g.Log.Warn("containment released")
		}
	}
	return g.frozen
}

// freeze contains the session. It reports false if it already was.
func (g *Gateway) freeze(stage, tool string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.frozen {
		return false
	}
	g.frozen = true
	if p := g.Cfg.Contain.StateFile; p != "" {
		err := writeFrozen(p, Frozen{At: time.Now().UTC(), Session: g.Session, Stage: stage, Tool: contextSafe(tool)})
		g.persisted = err == nil
		if err != nil {
			g.Log.Error("containment state not written; frozen for this process only", "err", err)
		}
	}
	g.Log.Warn("session frozen", "stage", stage)
	return true
}

// containBatch handles a batch line when containment is on. It returns the reply to send
// instead of forwarding, or nil to forward the batch as usual.
func (g *Gateway) containBatch(ctx context.Context, t []byte) ([]byte, bool) {
	if !bytes.Contains(t, []byte(`"tools/call"`)) {
		return nil, false
	}
	var batch []json.RawMessage
	if json.Unmarshal(t, &batch) != nil {
		return nil, false
	}
	if g.isFrozen() {
		return failedBatch(batch), true
	}
	if body, ok := g.find(t); ok {
		g.freeze("exfiltration", "batch")
		g.fire(ctx, body, "egress", "batch", "blocked")
		return failedBatch(batch), true
	}
	return nil, false
}
