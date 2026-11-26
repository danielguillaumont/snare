package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

// auditCmd lists audit records, or with -verify checks the hash chain (operator key).
// A tenant key (snk_...) sees its own tenant's records; the operator key sees all of them,
// or one tenant's with -tenant.
func auditCmd(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	tenant := fs.String("tenant", "", "operator only: one tenant's records")
	limit := fs.Int("limit", 50, "max records")
	verify := fs.Bool("verify", false, "operator only: verify the hash chain and print its head")
	_ = fs.Parse(args)

	c := client()
	operator := !strings.HasPrefix(c.Key, store.APIKeyPrefix)
	if *verify {
		v, err := c.VerifyAudit()
		if err != nil {
			return err
		}
		if !v.OK {
			return fmt.Errorf("audit chain BROKEN at seq %d after %d good records: %s", v.BrokenAt, v.Records, v.Reason)
		}
		fmt.Printf("ok: %d records\nhead: %s\n\nKeep the head somewhere else; a later head that doesn't extend it means history was rewritten.\n", v.Records, v.Head)
		return nil
	}
	c.Tenant = ""
	es, err := c.Audit(*tenant, *limit, operator)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEQ\tTIME\tACTOR\tTENANT\tACTION\tTARGET\tDETAIL")
	for _, e := range es {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", e.Seq, e.At.Format(time.RFC3339), e.Actor, e.TenantID, e.Action, e.Target, e.Detail)
	}
	return tw.Flush()
}
