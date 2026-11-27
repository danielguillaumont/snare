package gateway

// Tool integrity (docs/M17-tool-integrity.md): pin each real tool's definition on first
// sight and warn when it changes under the same name.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
)

// Integrity configures definition pinning. Token is an integrity_signal token: its touches
// are warnings, never alerts on their own.
type Integrity struct {
	Token string `json:"token"`
	// PinFile holds the pins across restarts. LoadConfig defaults it to the config path
	// plus ".pins".
	PinFile string `json:"pin_file,omitempty"`
}

// layerIntegrity is the layer a gateway reports with an integrity touch.
const layerIntegrity = "integrity"

// Pin is one tool's pinned definition fingerprint and the latest one seen. Fingerprints
// only: the file never holds descriptions or schemas.
type Pin struct {
	Pinned string `json:"pinned"`
	Seen   string `json:"seen"`
}

// Changed reports whether the latest definition differs from the pin.
func (p Pin) Changed() bool { return p.Seen != "" && p.Seen != p.Pinned }

// ReadPins reads a pin file. A missing file is an empty set.
func ReadPins(path string) (map[string]Pin, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Pin{}, nil
	}
	if err != nil {
		return nil, err
	}
	pins := map[string]Pin{}
	if err := json.Unmarshal(b, &pins); err != nil {
		return nil, fmt.Errorf("pin file %s: %w", path, err)
	}
	return pins, nil
}

// WritePins writes a pin file atomically, readable by the owner only.
func WritePins(path string, pins map[string]Pin) error {
	b, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AcceptPin re-pins tool from its latest seen definition. It returns false when the tool has
// no pending change.
func AcceptPin(path, tool string) (bool, error) {
	pins, err := ReadPins(path)
	if err != nil {
		return false, err
	}
	p, ok := pins[tool]
	if !ok || !p.Changed() {
		return false, nil
	}
	p.Pinned = p.Seen
	pins[tool] = p
	return true, WritePins(path, pins)
}

// DefinitionFingerprint is the SHA-256 of a tool's name, description and input schema, in
// canonical JSON (object keys sorted), so formatting and key order never count as a change.
func DefinitionFingerprint(name, description string, schema json.RawMessage) string {
	var s any
	if len(schema) > 0 {
		if json.Unmarshal(schema, &s) != nil {
			s = string(schema) // unparseable: compare the bytes
		}
	}
	b, _ := json.Marshal(map[string]any{"name": name, "description": description, "inputSchema": s})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// checkDefinitions compares a tools/list page's real tools with the pins, records new pins
// and the latest definitions, and queues one warning per changed tool per session. Called
// with g.mu held.
func (g *Gateway) checkDefinitions(defs map[string]string) {
	in := g.Cfg.Integrity
	if in == nil || in.Token == "" || len(defs) == 0 {
		return
	}
	if g.pins == nil {
		pins, err := ReadPins(in.PinFile)
		if err != nil {
			g.Log.Error("tool pins unreadable; integrity checks off for this session", "err", err)
			g.pins = map[string]Pin{}
			g.pinsBroken = true
			return
		}
		g.pins = pins
	}
	if g.pinsBroken {
		return
	}
	dirty := false
	names := make([]string, 0, len(defs))
	for n := range defs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		fp := defs[name]
		p, ok := g.pins[name]
		switch {
		case !ok:
			g.pins[name] = Pin{Pinned: fp, Seen: fp}
			dirty = true
		case p.Seen != fp:
			p.Seen = fp
			g.pins[name] = p
			dirty = true
		}
		if g.pins[name].Changed() && !g.drifted[name] {
			g.drifted[name] = true
			g.queue = append(g.queue, signal{tok: in.Token, layer: layerIntegrity, tool: name})
		}
	}
	if dirty && in.PinFile != "" {
		if err := WritePins(in.PinFile, g.pins); err != nil {
			g.Log.Error("write tool pins", "err", err)
		}
	}
}
