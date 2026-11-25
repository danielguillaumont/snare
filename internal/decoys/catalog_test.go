package decoys

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The Go catalog must equal the non-retired decoys in the kill-test data: we only ship
// decoys that passed screening, and we ship all of them.
func TestCatalogMatchesScreenedDecoys(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "experiments", "killtest", "killtest", "data", "decoys.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var screened []string
	var current string
	retired := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if name, ok := strings.CutPrefix(line, "- name: "); ok {
			current = strings.TrimSpace(name)
			screened = append(screened, current)
		} else if strings.HasPrefix(strings.TrimSpace(line), "retired:") {
			retired[current] = true
		}
	}
	var want []string
	for _, n := range screened {
		if !retired[n] {
			want = append(want, n)
		}
	}
	var got []string
	for _, tl := range Catalog {
		got = append(got, tl.Name)
		if len(tl.Params) == 0 || tl.Description == "" {
			t.Errorf("%s: incomplete definition", tl.Name)
		}
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog out of sync with decoys.yaml\n got: %v\nwant: %v", got, want)
	}
	for _, r := range []string{"fetch_internal_wiki", "read_payment_methods", "sync_audit_backup"} {
		if _, ok := Get(r); ok {
			t.Errorf("retired decoy %s must not ship", r)
		}
	}
}
