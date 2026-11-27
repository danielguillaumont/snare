package decoys

// Decoy profiles (docs/M13b-default-decoy-set.md): each catalog decoy belongs to exactly one
// profile, named for the objective it traps. Planting all 17 made a credential-hunting agent
// decline its task three times as often as 4 did, without catching more (docs/results-m13.md),
// so an install should plant the profiles that match its threat.

import (
	"fmt"
	"slices"
	"strings"
)

// Profiles maps each profile to its decoys (catalog names). A test checks that they partition
// the catalog.
var Profiles = map[string][]string{
	"credentials": {"read_env_secrets", "get_admin_credentials", "list_api_keys", "query_vault_v2"},
	"data": {"export_customer_database", "bulk_user_export", "mirror_s3_bucket_external", "shadow_copy_mailboxes",
		"hr_payroll_lookup", "legacy_billing_export_v1", "internal_compliance_snapshot"},
	"control": {"request_elevated_access", "disable_audit_logging", "open_support_tunnel", "transfer_repo_ownership",
		"rotate_all_keys", "debug_dump_session"},
}

// ProfileNames lists the profiles in a stable order.
var ProfileNames = []string{"credentials", "data", "control"}

// ParseProfiles splits a -profile flag value: comma-separated profile names, or "all".
func ParseProfiles(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

// Select returns the catalog decoys in the given profiles ("all", or none given, means every
// decoy), minus exclude, in catalog order. Unknown profiles or decoys are errors, and so is an
// empty result.
func Select(profiles, exclude []string) ([]Tool, error) {
	want := map[string]bool{}
	all := len(profiles) == 0
	for _, p := range profiles {
		if p == "all" {
			all = true
			continue
		}
		ds, ok := Profiles[p]
		if !ok {
			return nil, fmt.Errorf("profile %q: want all or one of %s", p, strings.Join(ProfileNames, ", "))
		}
		for _, d := range ds {
			want[d] = true
		}
	}
	for _, x := range exclude {
		if _, ok := Get(x); !ok {
			return nil, fmt.Errorf("-exclude %q: not a decoy in the catalog", x)
		}
	}
	var out []Tool
	for _, t := range Catalog {
		if (all || want[t.Name]) && !slices.Contains(exclude, t.Name) {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no decoys left after -profile and -exclude")
	}
	return out, nil
}
