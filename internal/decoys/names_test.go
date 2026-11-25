package decoys

import (
	"strings"
	"testing"
)

func TestAlternativesCoverCatalogAndAreUnique(t *testing.T) {
	if len(Alternatives) != len(Catalog) {
		t.Fatalf("%d alternatives for %d decoys", len(Alternatives), len(Catalog))
	}
	seen := map[string]string{}
	for _, tl := range Catalog {
		alts, ok := Alternatives[tl.Name]
		if !ok || len(alts) < 3 {
			t.Errorf("%s: need at least 3 alternatives", tl.Name)
		}
		for _, n := range append([]string{tl.Name}, alts...) {
			if prev, dup := seen[n]; dup {
				t.Errorf("%q used by %s and %s", n, prev, tl.Name)
			}
			seen[n] = tl.Name
			if !nameRE.MatchString(n) || strings.ToLower(n) != n {
				t.Errorf("%q: bad snake_case name", n)
			}
		}
	}
	// Retired decoys (M0) must not come back under a new name.
	for _, retired := range []string{"fetch_internal_wiki", "read_payment_methods", "sync_audit_backup"} {
		if _, ok := seen[retired]; ok {
			t.Errorf("retired decoy %s reintroduced", retired)
		}
	}
}

func TestStyled(t *testing.T) {
	cases := map[string]string{"snake": "read_env_secrets", "camel": "readEnvSecrets", "kebab": "read-env-secrets"}
	for st, want := range cases {
		if got := Styled("read_env_secrets", st); got != want {
			t.Errorf("%s: %q", st, got)
		}
	}
}

func TestPickIsDeterministicAndVaries(t *testing.T) {
	a, err := Pick(1, "snake", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Pick(1, "snake", nil)
	c, _ := Pick(2, "snake", nil)
	if len(a) != len(Catalog) {
		t.Fatalf("%d choices", len(a))
	}
	same, differ := true, 0
	for i := range a {
		if a[i] != b[i] {
			same = false
		}
		if a[i].Name != c[i].Name {
			differ++
		}
	}
	if !same {
		t.Error("same seed must give same names")
	}
	if differ < 5 {
		t.Errorf("seeds 1 and 2 differ on only %d of %d names", differ, len(a))
	}
	// Across many installs, the canonical public name is the minority.
	canon := 0
	for seed := uint64(0); seed < 200; seed++ {
		ch, _ := Pick(seed, "snake", nil)
		for _, x := range ch {
			if x.Name == x.Canonical {
				canon++
			}
		}
	}
	if frac := float64(canon) / float64(200*len(Catalog)); frac > 0.35 {
		t.Errorf("canonical names chosen %.0f%% of the time", frac*100)
	}
}

func TestPickOverridesAndValidation(t *testing.T) {
	ch, err := Pick(1, "camel", map[string]Override{"query_vault_v2": {Name: "nwSecretsLookup", Description: "Look up a secret in Northwind's store."}})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range ch {
		if c.Canonical == "query_vault_v2" {
			found = c.Name == "nwSecretsLookup" && c.Custom && strings.Contains(c.Description, "Northwind")
		} else if strings.Contains(c.Name, "_") {
			t.Errorf("camel style produced %q", c.Name)
		}
	}
	if !found {
		t.Error("override not applied")
	}
	if _, err := Pick(1, "SCREAMING", nil); err == nil {
		t.Error("bad style accepted")
	}
	if _, err := Pick(1, "snake", map[string]Override{"sync_audit_backup": {Name: "x"}}); err == nil {
		t.Error("override for a non-catalog (retired) decoy accepted")
	}
	if _, err := Pick(1, "snake", map[string]Override{"query_vault_v2": {Name: "bad name!"}}); err == nil {
		t.Error("invalid override name accepted")
	}
	if _, err := Pick(1, "snake", map[string]Override{"query_vault_v2": {Name: "list_api_keys"}, "list_api_keys": {Name: "list_api_keys"}}); err == nil {
		t.Error("duplicate names accepted")
	}
}

func TestPools(t *testing.T) {
	p, err := Pools("snake")
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != len(Catalog) {
		t.Fatalf("%d pools", len(p))
	}
	for _, tl := range Catalog {
		if got := p[tl.Name]; len(got) != 1+len(Alternatives[tl.Name]) || got[0] != tl.Name {
			t.Errorf("%s: pool %v", tl.Name, got)
		}
	}
	if _, err := Pools("x"); err == nil {
		t.Error("bad style accepted")
	}
}

func TestAllGeneratedIncludesEveryStyle(t *testing.T) {
	all := AllGenerated()
	want := len(Catalog) * 4 * len(Styles)
	if len(all) != want {
		t.Fatalf("%d names, want %d", len(all), want)
	}
	for _, n := range []string{"query_vault_v2", "vaultQuery", "read-vault-path"} {
		found := false
		for _, a := range all {
			if a == n {
				found = true
			}
		}
		if !found {
			t.Errorf("%s missing", n)
		}
	}
}
