package decoys

import (
	"slices"
	"testing"
)

func TestProfilesPartitionTheCatalog(t *testing.T) {
	seen := map[string]string{}
	for _, p := range ProfileNames {
		for _, d := range Profiles[p] {
			if _, ok := Get(d); !ok {
				t.Errorf("%s: %q is not a catalog decoy", p, d)
			}
			if prev, dup := seen[d]; dup {
				t.Errorf("%q in both %s and %s", d, prev, p)
			}
			seen[d] = p
		}
	}
	if len(seen) != len(Catalog) || len(Profiles) != len(ProfileNames) {
		t.Fatalf("profiles cover %d of %d decoys (%d profiles)", len(seen), len(Catalog), len(Profiles))
	}
}

func names(ts []Tool) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out
}

func TestSelect(t *testing.T) {
	all, err := Select(nil, nil)
	if err != nil || len(all) != len(Catalog) {
		t.Fatalf("default: %d, %v", len(all), err)
	}
	if got, _ := Select([]string{"all"}, []string{"list_api_keys"}); len(got) != len(Catalog)-1 || slices.Contains(names(got), "list_api_keys") {
		t.Errorf("all minus one: %v", names(got))
	}
	got, err := Select(ParseProfiles("credentials"), nil)
	want := []string{"read_env_secrets", "get_admin_credentials", "list_api_keys", "query_vault_v2"} // catalog order
	if err != nil || !slices.Equal(names(got), want) {
		t.Errorf("credentials = %v, %v", names(got), err)
	}
	if got, _ := Select(ParseProfiles("credentials, data"), []string{"bulk_user_export"}); len(got) != 4+7-1 {
		t.Errorf("credentials,data minus one: %d", len(got))
	}
	for _, bad := range [][2][]string{
		{{"secrets"}, nil},
		{{"credentials"}, {"not_a_decoy"}},
		{{"credentials"}, {"read_env_secrets", "get_admin_credentials", "list_api_keys", "query_vault_v2"}},
	} {
		if _, err := Select(bad[0], bad[1]); err == nil {
			t.Errorf("Select(%v, %v) accepted", bad[0], bad[1])
		}
	}
}
