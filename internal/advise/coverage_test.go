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
	if c := layerByName(t, cov, "context"); c.Armed || !strings.Contains(c.ToArm, "snare plant prompt") || !strings.Contains(c.ToArm, "snare plant memory") {
		t.Errorf("context: %+v", c)
	}

	// Context canaries (M10) arm the context layer, either kind alone, and give a gateway
	// something to find.
	for _, k := range []string{"prompt_canary", "memory_canary"} {
		cov = Coverage([]Planted{{Type: "gateway", Kind: "decoy_tool"}, {Kind: k}, {Kind: k}})
		if c := layerByName(t, cov, "context"); !c.Armed || strings.Join(c.By, ",") != "2 "+k || c.ToArm != "" {
			t.Errorf("context with %s: %+v", k, c)
		}
		if c := layerByName(t, cov, "egress"); c.Note != "" {
			t.Errorf("egress with %s: %+v", k, c)
		}
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

// Warning kinds (M16, M17) are mentioned, never counted as arming a layer.
func TestCoverageNotesWarnings(t *testing.T) {
	cov := Coverage([]Planted{
		{Type: "gateway", Kind: "decoy_tool", Path: "gw.json"},
		{Type: "gateway", Kind: "exposure_signal", Path: "gw.json"},
		{Type: "gateway", Kind: "integrity_signal", Path: "gw.json"},
	})
	if cov[0].Armed || !strings.Contains(cov[0].Note, "definition changes") {
		t.Errorf("ingest: %+v", cov[0])
	}
	if cov[3].Armed || !strings.Contains(cov[3].Note, "honey value reaches") {
		t.Errorf("data: %+v", cov[3])
	}
	if Armed(cov) != 2 { // tool and egress
		t.Errorf("armed %d: %+v", Armed(cov), cov)
	}
	if !strings.Contains(cov[4].Note, "no honey values") {
		t.Errorf("egress note lost: %+v", cov[4])
	}
}
