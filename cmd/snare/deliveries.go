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

// deliveriesCmd lists alert deliveries, or requeues a dead one with -retry. A tenant key sees
// its own tenant's deliveries; the operator key sees all of them.
func deliveriesCmd(args []string) error {
	fs := flag.NewFlagSet("deliveries", flag.ExitOnError)
	state := fs.String("state", "", "pending, delivered or dead (default: any)")
	limit := fs.Int("limit", 50, "max rows")
	retry := fs.Int64("retry", 0, "requeue this dead delivery")
	_ = fs.Parse(args)

	c := client()
	operator := !strings.HasPrefix(c.Key, store.APIKeyPrefix)
	if operator {
		c.Tenant = ""
	}
	if *retry != 0 {
		if err := c.RetryDelivery(*retry, operator); err != nil {
			return err
		}
		fmt.Printf("delivery %d requeued\n", *retry)
		return nil
	}
	ds, err := c.Deliveries(*state, *limit, operator)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tEVENT\tSINK\tSTATE\tATTEMPTS\tUPDATED\tLAST ERROR")
	dead := 0
	for _, d := range ds {
		if d.State == store.DeliveryDead {
			dead++
		}
		fmt.Fprintf(tw, "%d\t%d\t%s\t%s\t%d\t%s\t%s\n", d.ID, d.EventID, d.SinkRef, d.State, d.Attempts,
			d.UpdatedAt.Format(time.RFC3339), d.LastError)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if dead > 0 {
		fmt.Fprintf(os.Stderr, "\n%d dead: each is an alert nobody received. Fix the sink, then: snare deliveries -retry ID\n", dead)
	}
	return nil
}
