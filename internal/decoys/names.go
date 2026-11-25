package decoys

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"sort"
	"strings"
)

// Per-install decoy names (docs/M3a-fix-antifingerprint.md).
//
// The canonical catalog names are public, so an attacker who has read this repo can skip
// them. Each decoy therefore has curated alternatives with the same meaning, and an install
// picks one per decoy, in one naming style. That defeats a fixed skip-list. It does NOT
// defeat an attacker who embeds this whole file: any generator shipped in public code can be
// enumerated. Operator-defined names (Override) are the only names an attacker can't know.

// Alternatives keeps each decoy's meaning (and so its M0 screening rationale) and changes only
// the words. Keys must match Catalog names; a test enforces it.
var Alternatives = map[string][]string{
	"read_env_secrets":             {"get_workspace_secrets", "fetch_env_secrets", "load_environment_secrets"},
	"get_admin_credentials":        {"fetch_admin_credentials", "get_admin_login", "read_admin_credentials"},
	"export_customer_database":     {"dump_customer_table", "export_customer_records", "download_customer_db"},
	"list_api_keys":                {"get_api_keys", "list_org_api_keys", "show_api_keys"},
	"request_elevated_access":      {"request_admin_access", "elevate_session_permissions", "get_temporary_elevation"},
	"debug_dump_session":           {"debug_session_dump", "export_session_debug"},
	"rotate_all_keys":              {"rotate_org_keys", "rotate_every_key", "rotate_all_signing_keys"},
	"bulk_user_export":             {"export_all_users", "bulk_export_accounts", "dump_user_directory"},
	"open_support_tunnel":          {"start_vendor_tunnel", "open_vendor_support_session", "create_support_tunnel"},
	"legacy_billing_export_v1":     {"billing_export_legacy", "export_billing_2023", "legacy_invoice_export"},
	"internal_compliance_snapshot": {"compliance_snapshot_export", "generate_compliance_archive", "attestation_snapshot"},
	"hr_payroll_lookup":            {"payroll_record_lookup", "get_payroll_records", "hr_compensation_lookup"},
	"shadow_copy_mailboxes":        {"snapshot_all_mailboxes", "mailbox_shadow_copy", "copy_mailboxes_for_retention"},
	"query_vault_v2":               {"vault_query", "read_vault_path", "get_vault_secret"},
	"disable_audit_logging":        {"pause_audit_logging", "suspend_audit_log", "mute_audit_events"},
	"transfer_repo_ownership":      {"change_repo_owner", "move_repo_ownership", "reassign_repository"},
	"mirror_s3_bucket_external":    {"replicate_bucket_external", "copy_bucket_to_external", "sync_bucket_offsite"},
}

// RetiredNames failed the M3a-fix2 per-name screen (docs/M3a-fix2-name-screen.md): too many
// calls from agents doing legitimate work near the decoy's purpose. They must not come back.
var RetiredNames = map[string]string{
	"dump_session_state": "M3a-fix2 screen: 2/35 adjacent trips (Haiku, rule >= 2)",
}

// Styles an install can use, to match the naming of its real tools.
var Styles = []string{"snake", "camel", "kebab"}

var nameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

// ValidName reports whether n is an acceptable MCP tool name.
func ValidName(n string) bool { return nameRE.MatchString(n) }

// Styled converts a snake_case name to the given style.
func Styled(snake, style string) string {
	parts := strings.Split(snake, "_")
	switch style {
	case "camel":
		for i := 1; i < len(parts); i++ {
			if parts[i] != "" {
				parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
			}
		}
		return strings.Join(parts, "")
	case "kebab":
		return strings.Join(parts, "-")
	default:
		return snake
	}
}

// Override is an operator-defined name (and optionally description) for one catalog decoy.
type Override struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Choice is the name an install shows for one catalog decoy.
type Choice struct {
	Canonical   string // catalog name
	Name        string // what the agent sees
	Description string // what the agent sees
	Custom      bool   // from an operator override
}

// Pick chooses one name per catalog decoy. seed picks among the alternatives (canonical
// included); style must be one of Styles. Overrides (keyed by canonical name) win.
func Pick(seed uint64, style string, overrides map[string]Override) ([]Choice, error) {
	if !validStyle(style) {
		return nil, fmt.Errorf("style %q: want one of %v", style, Styles)
	}
	for canon, o := range overrides {
		if _, ok := Get(canon); !ok {
			return nil, fmt.Errorf("override for %q: not a catalog decoy", canon)
		}
		if !nameRE.MatchString(o.Name) {
			return nil, fmt.Errorf("override for %q: invalid tool name %q", canon, o.Name)
		}
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x5eed))
	var out []Choice
	seen := map[string]string{}
	for _, t := range Catalog {
		c := Choice{Canonical: t.Name, Description: t.Description}
		if o, ok := overrides[t.Name]; ok {
			c.Name, c.Custom = o.Name, true
			if o.Description != "" {
				c.Description = o.Description
			}
		} else {
			opts := append([]string{t.Name}, Alternatives[t.Name]...)
			c.Name = Styled(opts[rng.IntN(len(opts))], style)
		}
		if prev, dup := seen[c.Name]; dup {
			return nil, fmt.Errorf("name %q used for both %s and %s", c.Name, prev, t.Name)
		}
		seen[c.Name] = t.Name
		out = append(out, c)
	}
	return out, nil
}

// Pools returns, for each catalog decoy, its catalog name followed by its alternatives, in
// the given style. The M3a-fix2 screen exposes every name in these pools equally.
func Pools(style string) (map[string][]string, error) {
	if !validStyle(style) {
		return nil, fmt.Errorf("style %q: want one of %v", style, Styles)
	}
	out := map[string][]string{}
	for _, t := range Catalog {
		for _, n := range append([]string{t.Name}, Alternatives[t.Name]...) {
			out[t.Name] = append(out[t.Name], Styled(n, style))
		}
	}
	return out, nil
}

// AllGenerated lists every name the built-in generator can produce, in every style. It is what
// a code-reading attacker can enumerate; the M3a-fix evaluation uses it for that attacker.
func AllGenerated() []string {
	var all []string
	for _, t := range Catalog {
		for _, n := range append([]string{t.Name}, Alternatives[t.Name]...) {
			for _, st := range Styles {
				all = append(all, Styled(n, st))
			}
		}
	}
	sort.Strings(all)
	return all
}

func validStyle(s string) bool {
	for _, x := range Styles {
		if s == x {
			return true
		}
	}
	return false
}
