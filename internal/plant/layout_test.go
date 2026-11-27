package plant

// Honey layouts (docs/M12-adaptive-deception.md §2): no minted value is reused across fields
// in anything a plant command writes, the key layout leaves the URL tokenless, and -adapt
// follows the repo's dotenv conventions.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/gateway"
	"github.com/danielguillaumont/snare/internal/mcp"
)

func (f *fakeMinter) tokens() []string {
	var out []string
	for i := range f.calls {
		out = append(out, tokenN(i+1))
	}
	return out
}

func tokenN(n int) string { return fmt.Sprintf("snrtesttoken%02d", n) } // as fakeMinter mints

// distinctPerField fails if a field holds two tokens, or one token sits in two fields. It
// returns how many fields hold a token.
func distinctPerField(t *testing.T, what string, fields map[string]string, tokens []string) int {
	t.Helper()
	owner, n := map[string]string{}, 0
	for name, v := range fields {
		var in []string
		for _, tok := range tokens {
			if strings.Contains(v, tok) {
				in = append(in, tok)
			}
		}
		if len(in) > 1 {
			t.Errorf("%s: field %s holds %d tokens: %q", what, name, len(in), v)
		}
		for _, tok := range in {
			if prev, ok := owner[tok]; ok {
				t.Errorf("%s: token reused in %s and %s", what, prev, name)
			}
			owner[tok] = name
			n++
		}
	}
	return n
}

func dotenvFields(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(ln, "="); ok && !strings.HasPrefix(ln, "#") {
			out[k] = v
		}
	}
	return out
}

func TestNoValueIsReusedByAnyPlantCommand(t *testing.T) {
	for _, layout := range []string{LayoutPath, LayoutKey} {
		dir, m := t.TempDir(), &fakeMinter{}
		if _, err := Repo(m, dir, Options{Layout: layout}); err != nil {
			t.Fatal(err)
		}
		if n := distinctPerField(t, "repo "+layout, dotenvFields(t, filepath.Join(dir, RepoFile)), m.tokens()); n != len(m.calls) {
			t.Errorf("repo %s: %d of %d tokens planted", layout, n, len(m.calls))
		}
	}

	dir, m := t.TempDir(), &fakeMinter{}
	if _, err := Corpus(m, dir, true, Options{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, CorpusFile))
	rows := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		if cells := strings.Split(ln, "|"); len(cells) == 4 && strings.TrimSpace(cells[1]) != "Setting" {
			rows[strings.TrimSpace(cells[1])] = cells[2]
		}
	}
	if n := distinctPerField(t, "corpus", rows, m.tokens()); n != len(m.calls) {
		t.Errorf("corpus table: %d of %d tokens", n, len(m.calls))
	}

	m = &fakeMinter{}
	path := filepath.Join(t.TempDir(), "decoy-mcp.json")
	if _, _, err := MCP(m, MCPOptions{ConfigPath: path}); err != nil {
		t.Fatal(err)
	}
	mc, err := mcp.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for k, v := range mc.Tools {
		fields[k] = v
	}
	if n := distinctPerField(t, "mcp", fields, m.tokens()); n != len(m.calls) {
		t.Errorf("mcp: %d of %d tokens", n, len(m.calls))
	}

	g := &fakeGW{}
	path = filepath.Join(t.TempDir(), "gw.json")
	if _, _, err := Gateway(g, GatewayOptions{ConfigPath: path}); err != nil {
		t.Fatal(err)
	}
	gc, err := gateway.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	fields = map[string]string{"heartbeat": gc.Heartbeat.Token, "exposure": gc.Exposure.Token}
	for k, v := range gc.Decoys {
		fields[k] = v
	}
	if n := distinctPerField(t, "gateway", fields, g.tokens()); n != len(g.calls) {
		t.Errorf("gateway: %d of %d tokens", n, len(g.calls))
	}

	dir, m = t.TempDir(), &fakeMinter{}
	if _, err := Memory(m, dir, MemoryOptions{Seed: 2, Count: 5}); err != nil {
		t.Fatal(err)
	}
	// A memory note holds a URL and a key: each token appears once in the whole file.
	b, _ = os.ReadFile(filepath.Join(dir, MemoryFile))
	for _, tok := range m.tokens() {
		if n := strings.Count(string(b), tok); n != 1 {
			t.Errorf("memory: token %s appears %d times", tok, n)
		}
	}
}

func TestRepoKeyLayout(t *testing.T) {
	dir, m := t.TempDir(), &fakeMinter{}
	es, err := Repo(m, dir, Options{Layout: LayoutKey})
	if err != nil {
		t.Fatal(err)
	}
	f := dotenvFields(t, filepath.Join(dir, RepoFile))
	if f["PAYMENTS_API_BASE_URL"] != "https://cb.example.test/v1" {
		t.Errorf("base URL = %q, want the tokenless callback URL", f["PAYMENTS_API_BASE_URL"])
	}
	if len(m.calls) != 3 || len(es) != 3 || !strings.HasSuffix(m.calls[0].Label, " api_key") {
		t.Fatalf("key layout mints api_key, db_host, db_password: %+v", m.calls)
	}
	if _, err := Repo(&fakeMinter{}, t.TempDir(), Options{Layout: "dns"}); err == nil {
		t.Error("unknown layout accepted")
	}
}

func TestRepoAdaptFollowsTheRepo(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".env.example", "# app\nNORTHWIND_DB_URL=\"postgres://localhost/app\"\nNORTHWIND_REDIS_URL=\"redis://localhost\"\nexport NORTHWIND_LOG_LEVEL=\"info\"\n")
	write("worker.env", "NORTHWIND_QUEUE=\"jobs\"\nNORTHWIND_CONCURRENCY=\"4\"\n")
	write("README.md", "NOT_AN_ENV=1\nOTHER=2\n") // not a dotenv file: ignored
	m := &fakeMinter{}
	if _, err := Repo(m, dir, Options{Adapt: true}); err != nil {
		t.Fatal(err)
	}
	f := dotenvFields(t, filepath.Join(dir, RepoFile))
	if v, ok := f["NORTHWIND_PAYMENTS_API_KEY"]; !ok || v != `"snrtesttoken02"` {
		t.Fatalf("prefix and quoting not followed: %v", f)
	}
	if f["NORTHWIND_PAYMENTS_DB_USER"] != `"recon_svc"` {
		t.Errorf("db user: %v", f)
	}

	// Mixed prefixes, unquoted values, or a setting word: nothing to follow.
	for _, c := range []string{
		"APP_A=1\nAPP_B=2\nAPP_C=3\nOTHER_D=4\nMORE_E=5\n", // 3 of 5 share APP: not "nearly every"
		"DB_HOST=x\nDB_USER=y\nDB_PASS=z\nDB_NAME=w\n",     // DB names a setting, not the app
	} {
		d := t.TempDir()
		_ = os.WriteFile(filepath.Join(d, ".env"), []byte(c), 0o600)
		if _, err := Repo(&fakeMinter{}, d, Options{Adapt: true}); err != nil {
			t.Fatal(err)
		}
		if _, ok := dotenvFields(t, filepath.Join(d, RepoFile))["PAYMENTS_API_KEY"]; !ok {
			t.Errorf("%q: honey should keep the default names", c)
		}
	}
}
