package plant

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/decoys"
	"github.com/danielguillaumont/snare/internal/gateway"
)

type fakeGW struct {
	fakeMinter
	salts []string
}

func (f *fakeGW) Fingerprints(salt string) (admin.FingerprintResponse, error) {
	f.salts = append(f.salts, salt)
	return admin.FingerprintResponse{Fingerprints: []string{"fp-" + salt[:4]}, Tokens: len(f.calls)}, nil
}

func TestGatewayConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gw.json")
	f := &fakeGW{}
	entries, snippet, err := Gateway(f, GatewayOptions{ConfigPath: path, Exclude: []string{"list_api_keys"}, Seed: 7})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// One entry per decoy, plus the heartbeat token (docs/M11-heartbeat.md), minted as a
	// heartbeat so its touches are never alerts.
	if len(entries) != len(decoys.Catalog) || len(cfg.Decoys) != len(entries)-1 {
		t.Fatalf("entries %d, decoys %d", len(entries), len(cfg.Decoys))
	}
	last := entries[len(entries)-1]
	if hb := cfg.Heartbeat; hb == nil || hb.Every != "15m" || hb.Token == "" || last.Kind != "heartbeat" || f.calls[len(f.calls)-1].Kind != "heartbeat" {
		t.Fatalf("heartbeat: %+v, entry %+v, kinds %v", cfg.Heartbeat, last, f.calls)
	}
	// -heartbeat 0 plants none; a bad interval is refused.
	if es, _, err := Gateway(&fakeGW{}, GatewayOptions{ConfigPath: filepath.Join(t.TempDir(), "gw.json"), Heartbeat: "0"}); err != nil || len(es) != len(decoys.Catalog) {
		t.Fatalf("heartbeat 0: %d entries, %v", len(es), err)
	}
	if _, _, err := Gateway(&fakeGW{}, GatewayOptions{ConfigPath: filepath.Join(t.TempDir(), "gw.json"), Heartbeat: "10s"}); err == nil {
		t.Fatal("a 10s heartbeat was accepted")
	}
	if _, ok := cfg.Decoys["list_api_keys"]; ok {
		t.Error("excluded decoy planted")
	}
	if cfg.Style != "auto" || cfg.Seed != 7 || cfg.CallbackURL != "https://cb.example.test" || cfg.URLPath != "/v1/" {
		t.Errorf("config: %+v", cfg)
	}
	if len(f.salts) != 1 || cfg.Salt != f.salts[0] || len(cfg.Salt) < 16 || len(cfg.Fingerprints) != 1 {
		t.Errorf("fingerprints: salt %q, %v", cfg.Salt, cfg.Fingerprints)
	}
	if !strings.Contains(snippet, `"gateway"`) || !strings.Contains(snippet, `"--"`) {
		t.Errorf("snippet: %s", snippet)
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("config mode %v: it holds decoy tokens and must be private", fi.Mode())
	}
	if _, _, err := Gateway(f, GatewayOptions{ConfigPath: path}); !errors.Is(err, ErrExists) {
		t.Errorf("overwrite: %v", err)
	}

	// Refresh: a new salt; decoys and seed unchanged.
	n, err := RefreshGateway(f, path)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := gateway.LoadConfig(path)
	if n == 0 || after.Salt == cfg.Salt || len(after.Decoys) != len(cfg.Decoys) || after.Seed != cfg.Seed {
		t.Errorf("refresh: n=%d before %+v after %+v", n, cfg, after)
	}
}

func TestGatewayContainIsOptIn(t *testing.T) {
	dir := t.TempDir()
	off := filepath.Join(dir, "off.json")
	if _, _, err := Gateway(&fakeGW{}, GatewayOptions{ConfigPath: off}); err != nil {
		t.Fatal(err)
	}
	if c, _ := gateway.LoadConfig(off); c.Contain != nil {
		t.Fatal("containment on without -contain")
	}
	on := filepath.Join(dir, "on.json")
	if _, _, err := Gateway(&fakeGW{}, GatewayOptions{ConfigPath: on, Contain: "recon"}); err != nil {
		t.Fatal(err)
	}
	if c, _ := gateway.LoadConfig(on); c.Contain == nil || c.Contain.At != "recon" || c.Contain.StateFile != on+".frozen" {
		t.Fatalf("contain: %+v", c.Contain)
	}
	if _, _, err := Gateway(&fakeGW{}, GatewayOptions{ConfigPath: filepath.Join(dir, "bad.json"), Contain: "use"}); err == nil {
		t.Fatal("-contain use accepted")
	}
}

func TestGatewayDryRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gw.json")
	f := &fakeGW{}
	var out bytes.Buffer
	if _, _, err := Gateway(f, GatewayOptions{Options: Options{DryRun: true, Out: &out}, ConfigPath: path}); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 || len(f.salts) != 0 {
		t.Fatal("dry run called the API")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("dry run wrote the config")
	}
}
