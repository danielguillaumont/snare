package advise

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func layerByName(t *testing.T, cov []LayerCoverage, name string) LayerCoverage {
	t.Helper()
	for _, c := range cov {
		if c.Layer == name {
			return c
		}
	}
	t.Fatalf("no layer %s", name)
	return LayerCoverage{}
}

func TestCoverage(t *testing.T) {
	// Nothing planted: every layer unarmed, each with a way to arm it.
	cov := Coverage(nil)
	if len(cov) != 6 || Armed(cov) != 0 {
		t.Fatalf("empty: %+v", cov)
	}
	order := []string{"ingest", "context", "tool", "data", "egress", "use"}
	for i, c := range cov {
		if c.Layer != order[i] || c.ToArm == "" {
			t.Errorf("layer %d: %+v", i, c)
		}
	}

	// A repo plant arms data and use; a gateway arms tool and egress.
	ps := []Planted{
		{Type: "repo", Kind: "honey_credential"}, {Type: "repo", Kind: "honey_credential"},
		{Type: "gateway", Kind: "decoy_tool", Path: "gw.json"}, {Type: "gateway", Kind: "decoy_tool", Path: "gw.json"}, {Type: "gateway", Kind: "decoy_tool", Path: "gw.json"},
	}
	cov = Coverage(ps)
	if Armed(cov) != 4 {
		t.Fatalf("armed %d: %+v", Armed(cov), cov)
	}
	if c := layerByName(t, cov, "data"); !c.Armed || strings.Join(c.By, ",") != "2 honey_credential" {
		t.Errorf("data: %+v", c)
	}
	if c := layerByName(t, cov, "egress"); !c.Armed || c.Note != "" || strings.Join(c.By, ",") != "1 gateway config" {
		t.Errorf("egress: %+v", c)
	}
	if c := layerByName(t, cov, "ingest"); c.Armed || !strings.Contains(c.ToArm, "-with-instruction") {
		t.Errorf("ingest: %+v", c)
	}
	// Context can't be armed until M10, whatever is planted.
	if c := layerByName(t, cov, "context"); c.Armed || !strings.Contains(c.ToArm, "M10") {
		t.Errorf("context: %+v", c)
	}

	// A gateway with nothing to find is armed, with a caveat.
	cov = Coverage([]Planted{{Type: "gateway", Kind: "decoy_tool"}})
	if c := layerByName(t, cov, "egress"); !c.Armed || !strings.Contains(c.Note, "-refresh") {
		t.Errorf("egress without data: %+v", c)
	}
}

func TestLoadManifest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	_ = os.WriteFile(p, []byte(`[{"type":"corpus","path":"d","label":"l","kind":"canary_instruction","token_id":"x","planted_at":"2026-11-26T00:00:00Z"}]`), 0o600)
	ps, err := LoadManifest(p)
	if err != nil || len(ps) != 1 || ps[0].Kind != "canary_instruction" || ps[0].Type != "corpus" {
		t.Fatalf("%+v %v", ps, err)
	}
	if !layerByName(t, Coverage(ps), "ingest").Armed {
		t.Error("canary instruction should arm ingest")
	}
	_ = os.WriteFile(p, []byte(`{`), 0o600)
	if _, err := LoadManifest(p); err == nil {
		t.Error("bad JSON accepted")
	}
}
