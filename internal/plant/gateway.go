package plant

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/decoys"
	"github.com/danielguillaumont/snare/internal/gateway"
	"github.com/danielguillaumont/snare/internal/store"
)

// Fingerprinter fetches the tenant's token fingerprints (docs/M6-gateway.md §3).
type Fingerprinter interface {
	Fingerprints(salt string) (admin.FingerprintResponse, error)
}

// GatewayClient is what planting a gateway needs from the admin API.
type GatewayClient interface {
	Minter
	Fingerprinter
}

type GatewayOptions struct {
	Options
	ConfigPath string
	Exclude    []string
	Profiles   []string // decoy profiles (docs/M13b-default-decoy-set.md); empty or "all": every decoy
	Style      string   // auto (default), adapt, snake, camel, kebab or catalog
	Seed       uint64
	Overrides  map[string]decoys.Override
	Command    string // snare binary for the client snippet (default "snare")
	Contain    string // "", "exfiltration" or "recon" (docs/M8-containment.md); "" is off
	// ProvenanceNames sends each input's source name with touches (docs/M9-provenance.md §3).
	ProvenanceNames bool
	// Heartbeat is the gateway's heartbeat interval (docs/M11-heartbeat.md): "" for the
	// default 15m, "0" for none.
	Heartbeat string
	// NoExposure turns off early warnings (docs/M16-early-warning.md): no exposure_signal
	// token is minted and the gateway doesn't scan tool results.
	NoExposure bool
	// NoIntegrity turns off tool-definition pinning (docs/M17-tool-integrity.md).
	NoIntegrity bool
}

// Gateway mints one decoy token per catalog decoy, fetches fingerprints of every tripwire in
// the tenant under a fresh salt, and writes the gateway config. It returns the entries and
// the client-config snippet.
func Gateway(c GatewayClient, o GatewayOptions) ([]Entry, string, error) {
	if o.ConfigPath == "" {
		return nil, "", errors.New("config path required")
	}
	if _, err := os.Stat(o.ConfigPath); err == nil {
		return nil, "", fmt.Errorf("%w: %s", ErrExists, o.ConfigPath)
	}
	selected, err := decoys.Select(o.Profiles, o.Exclude)
	if err != nil {
		return nil, "", err
	}
	if o.Style == "" {
		o.Style = "auto"
	}
	cfg := gateway.Config{Style: o.Style, Seed: o.Seed, Decoys: map[string]string{}, Names: o.Overrides}
	if o.ProvenanceNames {
		cfg.Provenance = &gateway.Provenance{Names: true}
	}
	if o.Contain != "" {
		cfg.Contain = &gateway.Contain{At: o.Contain}
		if err := cfg.Validate(); err != nil && err.Error() != "callback_url is required" {
			return nil, "", fmt.Errorf("-contain: %w", err)
		}
	}
	mt := minter(c, o.Options)
	var entries []Entry
	for _, t := range selected {
		label := "gateway decoy: " + t.Name
		r, err := mt.Mint("decoy_tool", label, "planted by snare plant gateway; shown inside the wrapped server's tool list")
		if err != nil {
			return nil, "", err
		}
		cfg.Decoys[t.Name] = r.Token
		if cfg.CallbackURL == "" {
			cfg.CallbackURL, cfg.URLPath = r.CallbackURL, urlPathOf(r)
		}
		entries = append(entries, Entry{Type: "gateway", Path: o.ConfigPath, Label: label, Kind: "decoy_tool", TokenID: r.ID, PlantedAt: time.Now().UTC()})
	}
	if every := o.Heartbeat; every != "0" {
		if every == "" {
			every = "15m" // gateway.DefaultHeartbeat
		}
		label := "gateway heartbeat: " + filepath.Base(absOr(o.ConfigPath))
		r, err := mt.Mint(store.KindHeartbeat, label, "planted by snare plant gateway; its touches prove the gateway can reach Snare and never alert")
		if err != nil {
			return nil, "", err
		}
		cfg.Heartbeat = &gateway.Heartbeat{Token: r.Token, Every: every}
		entries = append(entries, Entry{Type: "gateway", Path: o.ConfigPath, Label: label, Kind: store.KindHeartbeat, TokenID: r.ID, PlantedAt: time.Now().UTC()})
	}
	if !o.NoExposure {
		label := "gateway exposure: " + filepath.Base(absOr(o.ConfigPath))
		r, err := mt.Mint(store.KindExposure, label, "planted by snare plant gateway; touched when a honey value reaches the agent in a tool result: a warning, never an alert on its own")
		if err != nil {
			return nil, "", err
		}
		cfg.Exposure = &gateway.Exposure{Token: r.Token}
		entries = append(entries, Entry{Type: "gateway", Path: o.ConfigPath, Label: label, Kind: store.KindExposure, TokenID: r.ID, PlantedAt: time.Now().UTC()})
	}
	if !o.NoIntegrity {
		label := "gateway integrity: " + filepath.Base(absOr(o.ConfigPath))
		r, err := mt.Mint(store.KindIntegrity, label, "planted by snare plant gateway; touched when a real tool's definition changes: a warning, never an alert on its own")
		if err != nil {
			return nil, "", err
		}
		cfg.Integrity = &gateway.Integrity{Token: r.Token}
		entries = append(entries, Entry{Type: "gateway", Path: o.ConfigPath, Label: label, Kind: store.KindIntegrity, TokenID: r.ID, PlantedAt: time.Now().UTC()})
	}
	if !o.DryRun {
		if _, err := fetch(c, &cfg); err != nil {
			return nil, "", err
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, "", fmt.Errorf("gateway config: %w (is SNARE_PUBLIC_URL set on the server?)", err)
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if o.DryRun {
		fmt.Fprintf(o.out(), "--- would write %s (%d decoys; fingerprints are fetched when planting for real) ---\n", o.ConfigPath, len(cfg.Decoys))
	} else if err := writePrivate(o.ConfigPath, b, false); err != nil {
		return nil, "", err
	}
	cmd := o.Command
	if cmd == "" {
		cmd = "snare"
	}
	snippet, _ := json.MarshalIndent(map[string]any{"mcpServers": map[string]any{
		"<server name>": map[string]any{"command": cmd, "args": []string{"gateway", "-config", absOr(o.ConfigPath), "--", "<real server command>", "<its args>"}},
	}}, "", "  ")
	return entries, string(snippet), nil
}

// RefreshGateway re-fetches fingerprints for an existing gateway config under a new salt, so
// tripwires planted since are recognized. It returns how many tripwires are covered.
func RefreshGateway(f Fingerprinter, path string) (int, error) {
	cfg, err := gateway.LoadConfig(path)
	if err != nil {
		return 0, err
	}
	n, err := fetch(f, &cfg)
	if err != nil {
		return 0, err
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return n, writePrivate(path, b, true)
}

func fetch(f Fingerprinter, cfg *gateway.Config) (int, error) {
	salt := make([]byte, 24)
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}
	cfg.Salt = base64.RawURLEncoding.EncodeToString(salt)
	r, err := f.Fingerprints(cfg.Salt)
	if err != nil {
		return 0, fmt.Errorf("fetching fingerprints: %w", err)
	}
	cfg.Fingerprints = r.Fingerprints
	return r.Tokens, nil
}

// writePrivate writes a 0600 file, because the config holds decoy tokens. With replace it
// swaps the file in atomically; otherwise it refuses to overwrite.
func writePrivate(path string, b []byte, replace bool) error {
	b = append(b, '\n')
	if !replace {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(b); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snare-gateway-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmp.Name(), 0o600)
	return os.Rename(tmp.Name(), path)
}
