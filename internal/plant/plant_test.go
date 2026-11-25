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
	return admin.MintResponse{ID: fmt.Sprintf("id%02d", len(f.calls)), Token: tok, URL: "https://cb.example.test/t/" + tok, Hostname: tok + ".cb.example.test"}, nil
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
	for _, want := range []string{"PAYMENTS_API_BASE_URL=https://cb.example.test/t/snrtesttoken01", "PAYMENTS_API_KEY=snrtesttoken01", "PAYMENTS_DB_HOST=snrtesttoken01.cb.example.test"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if len(m.calls) != 1 || m.calls[0].Kind != "honey_credential" || len(es) != 1 || es[0].TokenID != "id01" {
		t.Errorf("calls=%v entries=%v", m.calls, es)
	}
	// Never overwrite.
	if _, err := Repo(m, dir, Options{}); !errors.Is(err, ErrExists) {
		t.Errorf("second plant: want ErrExists, got %v", err)
	}
	if len(m.calls) != 1 {
		t.Error("must not mint when the target exists")
	}
}

func TestCorpusInstructionOptIn(t *testing.T) {
	dir := t.TempDir()
	if _, err := Corpus(&fakeMinter{}, dir, false, Options{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, CorpusFile))
	s := string(b)
	if !strings.Contains(s, "](https://cb.example.test/t/snrtesttoken01/status.png)") || !strings.Contains(s, "`snrtesttoken01`") {
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
