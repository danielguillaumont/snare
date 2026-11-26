package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

// tenantCmd manages tenants and their API keys. It needs the operator key (SNARE_ADMIN_KEY).
func tenantCmd(args []string) error {
	if len(args) < 1 {
		usage()
		return fmt.Errorf("tenant: subcommand required")
	}
	fs := flag.NewFlagSet("tenant "+args[0], flag.ExitOnError)
	name := fs.String("name", "", "tenant display name")
	tenant := fs.String("tenant", "", "tenant id (tn_...)")
	role := fs.String("role", "admin", "key role: admin or viewer")
	key := fs.String("key", "", "API key id (ak_...)")
	_ = fs.Parse(args[1:])

	c := client()
	c.Tenant = "" // operator routes are not tenant-scoped
	need := func(v, flagName string) error {
		if v == "" {
			return fmt.Errorf("-%s is required", flagName)
		}
		return nil
	}
	switch args[0] {
	case "create":
		if err := need(*name, "name"); err != nil {
			return err
		}
		t, err := c.CreateTenant(*name)
		if err != nil {
			return err
		}
		fmt.Printf("tenant: %s\nname:   %s\n", t.ID, t.Name)
	case "list":
		ts, err := c.ListTenants()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tSTATE\tCREATED")
		for _, t := range ts {
			state := "active"
			if t.Disabled {
				state = "disabled"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.ID, t.Name, state, t.CreatedAt.Format(time.RFC3339))
		}
		return tw.Flush()
	case "key":
		if err := need(*tenant, "tenant"); err != nil {
			return err
		}
		k, err := c.IssueKey(*tenant, *role)
		if err != nil {
			return err
		}
		fmt.Printf("key id: %s\nrole:   %s\nkey:    %s\n\nShown once: Snare stores only a hash of the key.\n", k.ID, k.Role, k.Key)
	case "revoke":
		if err := need(*key, "key"); err != nil {
			return err
		}
		return c.RevokeKey(*key)
	case "disable", "enable":
		if err := need(*tenant, "tenant"); err != nil {
			return err
		}
		return c.SetTenantDisabled(*tenant, args[0] == "disable")
	default:
		usage()
		return fmt.Errorf("tenant: unknown subcommand %q", args[0])
	}
	return nil
}
