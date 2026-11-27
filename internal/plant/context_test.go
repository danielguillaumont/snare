package plant

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/admin"
)

// seqMinter mints recognizable, distinct tokens and records each mint.
type seqMinter struct{ kinds, labels []string }

func (f *seqMinter) Mint(kind, label, memo string) (admin.MintResponse, error) {
	f.kinds = append(f.kinds, kind)
	f.labels = append(f.labels, label)
	t := fakeToken(len(f.kinds))
	return admin.MintResponse{ID: "id" + t, Token: t, URL: "https://cb.example/v1/" + t, CallbackURL: "https://cb.example"}, nil
}

// fakeToken is the n-th token (from 1) a seqMinter mints.
func fakeToken(n int) string { return "tok" + strings.Repeat(string(rune('a'+n)), 8) }

func noTells(t *testing.T, s string) {
	t.Helper()
	for _, w := range []string{"snare", "canary", "trap", "tripwire", "honey", "decoy"} {
		if strings.Contains(strings.ToLower(s), w) {
			t.Fatalf("planted text says %q:\n%s", w, s)
		}
	}
}

func TestPromptPassage(t *testing.T) {
	m := &seqMinter{}
	entries, passage, err := Prompt(m, PromptOptions{Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].TokenID == entries[1].TokenID {
		t.Fatalf("want one token per value: %+v", entries)
	}
	for i, e := range entries {
		if e.Type != "prompt" || e.Kind != "prompt_canary" || m.kinds[i] != "prompt_canary" {
			t.Fatalf("entry %+v", e)
		}
	}
	if !strings.Contains(passage, "https://cb.example/v1/tokbbbbbbbb") || !strings.Contains(passage, "tokcccccccc") {
		t.Fatalf("passage lacks its values:\n%s", passage)
	}
	noTells(t, passage)

	seen := map[string]bool{}
	for seed := uint64(0); seed < 12; seed++ {
		_, p, _ := Prompt(&seqMinter{}, PromptOptions{Seed: seed})
		noTells(t, p)
		seen[strings.SplitN(p, ":", 2)[0]] = true
	}
	if len(seen) < 3 {
		t.Fatalf("seeds give %d phrasings, want at least 3", len(seen))
	}
}

func TestPromptFileAppendsOnce(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "system-prompt.md")
	manifest := filepath.Join(t.TempDir(), "m.json")
	orig := "You are the billing support assistant.\n"
	_ = os.WriteFile(file, []byte(orig), 0o644)

	// A dry run mints nothing and writes nothing.
	var out bytes.Buffer
	m := &seqMinter{}
	if _, _, err := Prompt(m, PromptOptions{Options: Options{DryRun: true, Out: &out}, File: file, Manifest: manifest}); err != nil {
		t.Fatal(err)
	}
	if len(m.kinds) != 0 {
		t.Fatal("dry run minted")
	}
	if b, _ := os.ReadFile(file); string(b) != orig {
		t.Fatal("dry run wrote the file")
	}

	entries, passage, err := Prompt(m, PromptOptions{File: file, Manifest: manifest})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	if !strings.HasPrefix(string(b), orig) || !strings.Contains(string(b), strings.TrimSpace(passage)) {
		t.Fatalf("file after plant:\n%s", b)
	}
	if err := AppendManifest(manifest, entries); err != nil {
		t.Fatal(err)
	}
	// Planted once (by the manifest): a second plant into the same file is refused.
	n := len(m.kinds)
	if _, _, err := Prompt(m, PromptOptions{File: file, Manifest: manifest}); !errors.Is(err, ErrExists) {
		t.Fatalf("second plant: %v", err)
	}
	if len(m.kinds) != n {
		t.Fatal("refused plant still minted")
	}
	if _, _, err := Prompt(m, PromptOptions{File: filepath.Join(dir, "missing.md"), Manifest: manifest}); err == nil {
		t.Fatal("a missing prompt file must be an error")
	}
}

func TestMemoryRecords(t *testing.T) {
	dir := t.TempDir()
	m := &seqMinter{}
	entries, err := Memory(m, dir, MemoryOptions{Seed: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2*DefaultMemoryCount {
		t.Fatalf("entries: %d", len(entries))
	}
	f, err := os.Open(filepath.Join(dir, MemoryFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var recs []MemoryRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r MemoryRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		recs = append(recs, r)
	}
	if len(recs) != DefaultMemoryCount {
		t.Fatalf("records: %d", len(recs))
	}
	ids := map[string]bool{}
	for i, r := range recs {
		noTells(t, r.Text)
		if r.ID == "" || ids[r.ID] || r.Metadata["source"] == "" {
			t.Fatalf("record %d: %+v", i, r)
		}
		ids[r.ID] = true
		// Each record carries its own two tokens.
		if !strings.Contains(r.Text, fakeToken(2*i+1)) || !strings.Contains(r.Text, fakeToken(2*i+2)) {
			t.Fatalf("record %d values: %q", i, r.Text)
		}
	}
	for _, k := range m.kinds {
		if k != "memory_canary" {
			t.Fatalf("kind %s", k)
		}
	}
	if _, err := Memory(m, dir, MemoryOptions{}); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	for _, n := range []int{-1, MaxMemoryCount + 1} {
		if _, err := Memory(m, t.TempDir(), MemoryOptions{Count: n}); err == nil {
			t.Errorf("count %d accepted", n)
		}
	}

	md := t.TempDir()
	if _, err := Memory(&seqMinter{}, md, MemoryOptions{Count: 2, Format: "md"}); err != nil {
		t.Fatal(err)
	}
	notes, _ := filepath.Glob(filepath.Join(md, "*.md"))
	if len(notes) != 2 {
		t.Fatalf("md notes: %v", notes)
	}
	for _, p := range notes {
		b, _ := os.ReadFile(p)
		noTells(t, string(b))
		noTells(t, filepath.Base(p))
	}
	if _, err := Memory(&seqMinter{}, t.TempDir(), MemoryOptions{Format: "xml"}); err == nil {
		t.Fatal("unknown format accepted")
	}
}
