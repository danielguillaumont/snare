package plant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/decoys"
	"github.com/danielguillaumont/snare/internal/mcp"
)

type fakeMinter struct{ calls []admin.MintRequest }

func (f *fakeMinter) Mint(kind, label, memo string) (admin.MintResponse, error) {
	f.calls = append(f.calls, admin.MintRequest{Kind: kind, Label: label, Memo: memo})
	tok := fmt.Sprintf("snrtesttoken%02d", len(f.calls))
	return admin.MintResponse{ID: fmt.Sprintf("id%02d", len(f.calls)), Token: tok, URL: "https://cb.example.test/v1/" + tok, Hostname: tok + ".cb.example.test", CallbackURL: "https://cb.example.test"}, nil
}

func TestRepo(t *testing.T) {
	dir := t.TempDir()
	m := &fakeMinter{}
	es, err := Repo(m, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, RepoFile))
	s := string(b)
	for _, want := range []string{
		"PAYMENTS_API_BASE_URL=https://cb.example.test/v1/snrtesttoken01",
		"PAYMENTS_API_KEY=snrtesttoken02",
		"PAYMENTS_DB_HOST=snrtesttoken03.cb.example.test",
		"PAYMENTS_DB_PASSWORD=snrtesttoken04",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	// One token per field: no value is reused (that reuse was a fingerprint in M3a).
	if len(m.calls) != 4 || len(es) != 4 {
		t.Fatalf("want 4 tokens / entries, got %d / %d", len(m.calls), len(es))
	}
	for i, e := range es {
		if e.TokenID != fmt.Sprintf("id%02d", i+1) || e.Kind != "honey_credential" {
			t.Errorf("entry %d = %+v", i, e)
		}
	}
	for i, f := range []string{"base_url", "api_key", "db_host", "db_password"} {
		if !strings.HasSuffix(m.calls[i].Label, " "+f) || !strings.HasSuffix(es[i].Label, " "+f) {
			t.Errorf("token %d label %q doesn't name field %s", i, m.calls[i].Label, f)
		}
	}
	// Never overwrite.
	if _, err := Repo(m, dir, Options{}); !errors.Is(err, ErrExists) {
		t.Errorf("second plant: want ErrExists, got %v", err)
	}
	if len(m.calls) != 4 {
		t.Error("must not mint when the target exists")
	}
}

func TestRepoWithoutZoneSkipsDBFields(t *testing.T) {
	dir := t.TempDir()
	m := &noZoneMinter{}
	es, err := Repo(m, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, RepoFile))
	if strings.Contains(string(b), "DB_HOST") || len(es) != 2 {
		t.Errorf("without a zone: %d entries\n%s", len(es), b)
	}
}

type noZoneMinter struct{ fakeMinter }

func (n *noZoneMinter) Mint(kind, label, memo string) (admin.MintResponse, error) {
	r, err := n.fakeMinter.Mint(kind, label, memo)
	r.Hostname = ""
	return r, err
}

func TestCorpusInstructionOptIn(t *testing.T) {
	dir := t.TempDir()
	if _, err := Corpus(&fakeMinter{}, dir, false, Options{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, CorpusFile))
	s := string(b)
	if !strings.Contains(s, "](https://cb.example.test/v1/snrtesttoken01/status.png)") || !strings.Contains(s, "`snrtesttoken02`") {
		t.Errorf("image or credential missing:\n%s", s)
	}
	if strings.Contains(s, "automated assistants") {
		t.Error("instruction must be opt-in")
	}
	dir2 := t.TempDir()
	if _, err := Corpus(&fakeMinter{}, dir2, true, Options{}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(dir2, CorpusFile))
	if !strings.Contains(string(b), "automated assistants") {
		t.Error("-with-instruction did not add the instruction")
	}
}

func TestDryRunWritesAndMintsNothing(t *testing.T) {
	dir := t.TempDir()
	m := &fakeMinter{}
	var out bytes.Buffer
	if _, err := Repo(m, dir, Options{DryRun: true, Out: &out}); err != nil {
		t.Fatal(err)
	}
	if len(m.calls) != 0 {
		t.Error("dry run minted a token")
	}
	if _, err := os.Stat(filepath.Join(dir, RepoFile)); err == nil {
		t.Error("dry run wrote a file")
	}
	if !strings.Contains(out.String(), "would write") {
		t.Errorf("dry run output: %q", out.String())
	}
}

func TestMCPConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decoy-mcp.json")
	m := &fakeMinter{}
	es, snippet, err := MCP(m, MCPOptions{ConfigPath: path, Exclude: []string{"list_api_keys"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != len(decoys.Catalog)-1 || len(m.calls) != len(decoys.Catalog)-1 {
		t.Fatalf("want %d tripwires, got %d", len(decoys.Catalog)-1, len(es))
	}
	cfg, err := mcp.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Tools["list_api_keys"]; ok {
		t.Error("excluded decoy planted")
	}
	if cfg.CallbackURL != "https://cb.example.test" {
		t.Errorf("callback url = %q", cfg.CallbackURL)
	}
	seen := map[string]bool{}
	for _, tok := range cfg.Tools {
		if seen[tok] {
			t.Error("tokens must be unique per tool")
		}
		seen[tok] = true
	}
	var sn map[string]any
	if err := json.Unmarshal([]byte(snippet), &sn); err != nil || !strings.Contains(snippet, "decoy-mcp") {
		t.Errorf("bad snippet: %s", snippet)
	}
	if _, _, err := MCP(m, MCPOptions{ConfigPath: filepath.Join(t.TempDir(), "x.json"), Exclude: []string{"sync_audit_backup"}}); err == nil {
		t.Error("unknown/retired -exclude accepted")
	}
}

func TestManifest(t *testing.T) {
	dir := t.TempDir()
	if err := CheckManifestOutside(filepath.Join(dir, "snare-planted.json"), dir); err == nil {
		t.Error("manifest inside planted dir accepted")
	}
	if err := CheckManifestOutside(filepath.Join(dir, "..", "snare-planted.json"), dir); err != nil {
		t.Error(err)
	}
	mf := filepath.Join(t.TempDir(), "m.json")
	for i := 0; i < 2; i++ {
		if err := AppendManifest(mf, []Entry{{Type: "repo", TokenID: fmt.Sprint(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	var all []Entry
	b, _ := os.ReadFile(mf)
	if err := json.Unmarshal(b, &all); err != nil || len(all) != 2 {
		t.Errorf("manifest = %s", b)
	}
}

func TestMCPPerInstallNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decoy-mcp.json")
	_, _, err := MCP(&fakeMinter{}, MCPOptions{ConfigPath: path, Style: "camel", Seed: 42,
		Overrides: map[string]decoys.Override{"query_vault_v2": {Name: "nwSecretLookup"}}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mcp.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := cfg.Shown("query_vault_v2"); n != "nwSecretLookup" {
		t.Errorf("override not applied: %s", n)
	}
	want, _ := decoys.Pick(42, "camel", map[string]decoys.Override{"query_vault_v2": {Name: "nwSecretLookup"}})
	for _, c := range want {
		if n, _ := cfg.Shown(c.Canonical); n != c.Name {
			t.Errorf("%s shown as %s, want %s", c.Canonical, n, c.Name)
		}
		if strings.Contains(c.Name, "_") {
			t.Errorf("camel style gave %s", c.Name)
		}
	}
	// Overrides alone keep the other catalog names.
	path2 := filepath.Join(t.TempDir(), "d2.json")
	if _, _, err := MCP(&fakeMinter{}, MCPOptions{ConfigPath: path2, Overrides: map[string]decoys.Override{"list_api_keys": {Name: "org_keys"}}}); err != nil {
		t.Fatal(err)
	}
	cfg2, _ := mcp.LoadConfig(path2)
	if len(cfg2.Names) != 1 {
		t.Errorf("names: %v", cfg2.Names)
	}
	if _, _, err := MCP(&fakeMinter{}, MCPOptions{ConfigPath: filepath.Join(t.TempDir(), "d3.json"), Style: "loud"}); err == nil {
		t.Error("bad style accepted")
	}
}
