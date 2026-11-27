package plant

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/danielguillaumont/snare/internal/decoys"
	"github.com/danielguillaumont/snare/internal/gateway"
	"github.com/danielguillaumont/snare/internal/mcp"
)

// -profile plants only that profile's decoys, -exclude still applies on top, and the
// heartbeat is unaffected (docs/M13b-default-decoy-set.md).
func TestPlantProfiles(t *testing.T) {
	creds := decoys.Profiles["credentials"]

	path := filepath.Join(t.TempDir(), "gw.json")
	es, _, err := Gateway(&fakeGW{}, GatewayOptions{ConfigPath: path, Profiles: []string{"credentials"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Decoys) != len(creds) || len(es) != len(creds)+2 || cfg.Heartbeat == nil || cfg.Exposure == nil {
		t.Fatalf("gateway: %d decoys, %d entries, heartbeat %v", len(cfg.Decoys), len(es), cfg.Heartbeat)
	}
	for name := range cfg.Decoys {
		if !slices.Contains(creds, name) {
			t.Errorf("gateway planted %s outside the credentials profile", name)
		}
	}

	mpath := filepath.Join(t.TempDir(), "decoy-mcp.json")
	if _, _, err := MCP(&fakeMinter{}, MCPOptions{ConfigPath: mpath, Profiles: []string{"credentials", "control"}, Exclude: []string{"list_api_keys"}}); err != nil {
		t.Fatal(err)
	}
	mc, err := mcp.LoadConfig(mpath)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(creds) + len(decoys.Profiles["control"]) - 1; len(mc.Tools) != want {
		t.Fatalf("mcp: %d tools, want %d", len(mc.Tools), want)
	}
	if _, ok := mc.Tools["list_api_keys"]; ok {
		t.Error("excluded decoy planted")
	}

	// "all" (the default) is the whole catalog; an unknown profile is refused.
	if es, _, err := MCP(&fakeMinter{}, MCPOptions{ConfigPath: filepath.Join(t.TempDir(), "a.json"), Profiles: []string{"all"}}); err != nil || len(es) != len(decoys.Catalog) {
		t.Fatalf("all: %d, %v", len(es), err)
	}
	if _, _, err := Gateway(&fakeGW{}, GatewayOptions{ConfigPath: filepath.Join(t.TempDir(), "x.json"), Profiles: []string{"secrets"}}); err == nil {
		t.Error("unknown profile accepted")
	}
}
