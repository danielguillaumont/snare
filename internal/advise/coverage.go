package advise

// Layer coverage (docs/M7-incidents.md §4, docs/DEPTH.md): which layers of the agent kill
// chain have a tripwire, judged from the plant manifest.

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

// Planted is the part of a plant manifest entry coverage needs.
type Planted struct {
	Type string `json:"type"` // repo, corpus, mcp, gateway
	Kind string `json:"kind"`
	Path string `json:"path"`
}

// LoadManifest reads a manifest written by snare plant.
func LoadManifest(path string) ([]Planted, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ps []Planted
	if err := json.Unmarshal(b, &ps); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	return ps, nil
}

// LayerCoverage says whether one layer is armed, by what, and how to arm it.
type LayerCoverage struct {
	Layer string   `json:"layer"`
	Stage string   `json:"stage"` // what a touch here proves
	Armed bool     `json:"armed"`
	By    []string `json:"armed_by,omitempty"`
	Note  string   `json:"note,omitempty"`   // armed, with a caveat
	ToArm string   `json:"to_arm,omitempty"` // when not armed
}

// Coverage reports the six layers in kill-chain order.
func Coverage(ps []Planted) []LayerCoverage {
	count := map[string]int{} // kind -> tripwires; "type:" + type -> distinct config paths
	seen := map[string]bool{}
	for _, p := range ps {
		count[p.Kind]++
		if k := p.Type + "|" + p.Path; !seen[k] {
			seen[k] = true
			count["type:"+p.Type]++
		}
	}
	by := func(keys ...string) []string {
		var out []string
		for _, k := range keys {
			if n := count[k]; n > 0 {
				name := strings.TrimPrefix(k, "type:")
				if strings.HasPrefix(k, "type:") {
					name += " config"
				}
				out = append(out, fmt.Sprintf("%d %s", n, name))
			}
		}
		return out
	}
	layer := func(name, stage, toArm string, keys ...string) LayerCoverage {
		b := by(keys...)
		c := LayerCoverage{Layer: name, Stage: stage, Armed: len(b) > 0, By: b}
		if !c.Armed {
			c.ToArm = toArm
		}
		return c
	}
	out := []LayerCoverage{
		layer("ingest", "steered", "snare plant corpus -with-instruction <docs dir>", "canary_instruction"),
		layer("context", "steered", "snare plant prompt -file <system prompt file>, snare plant memory <dir> (then load the records into the agent's memory)",
			"prompt_canary", "memory_canary"),
		layer("tool", "recon", "snare plant gateway -config gw.json (decoys inside your real MCP servers), or snare plant mcp", "decoy_tool"),
		layer("data", "collection", "snare plant repo <repo dir>, snare plant corpus <docs dir>", "honey_credential", "canary_doc", "canary_url"),
		layer("egress", "exfiltration", "snare plant gateway -config gw.json, then run your MCP servers through snare gateway", "type:gateway"),
		layer("use", "use", "snare plant repo <repo dir> (honey credentials report when they are used)", "honey_credential"),
	}
	if out[4].Armed && count["honey_credential"]+count["canary_doc"]+count["canary_url"]+count["canary_instruction"]+
		count["prompt_canary"]+count["memory_canary"] == 0 {
		out[4].Note = "the gateway has no honey values to look for: plant data tripwires, then snare plant gateway -refresh"
	}
	return out
}

// Armed counts the armed layers.
func Armed(cov []LayerCoverage) int {
	return len(slices.DeleteFunc(slices.Clone(cov), func(c LayerCoverage) bool { return !c.Armed }))
}
