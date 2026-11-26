package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

// triageCmd records what a touch turned out to be (docs/M4e-lifecycle.md §2).
func triageCmd(args []string) error {
	fs := flag.NewFlagSet("triage", flag.ExitOnError)
	id := fs.Int64("event", 0, "event id (from snare events)")
	status := fs.String("status", "", "acknowledged, resolved, false_positive, or open to reopen")
	note := fs.String("note", "", "what you found (at most 500 bytes; not copied into the audit log)")
	_ = fs.Parse(args)
	if *id == 0 || *status == "" {
		fs.Usage()
		return errors.New("triage needs -event and -status")
	}
	if err := client().Triage(*id, *status, *note); err != nil {
		return err
	}
	fmt.Printf("event %d: %s\n", *id, *status)
	return nil
}

// tokensCmd lists the tenant's tripwires, or mutes / unmutes one (§1).
func tokensCmd(args []string) error {
	fs := flag.NewFlagSet("tokens", flag.ExitOnError)
	disable := fs.String("disable", "", "mute this tripwire: touches are still recorded, never alerted")
	enable := fs.String("enable", "", "unmute this tripwire")
	_ = fs.Parse(args)
	c := client()
	switch {
	case *disable != "" && *enable != "":
		return errors.New("use -disable or -enable, not both")
	case *disable != "":
		if err := c.SetTokenDisabled(*disable, true); err != nil {
			return err
		}
		fmt.Printf("tripwire %s disabled: touches are recorded but no alert is sent\n", *disable)
		return nil
	case *enable != "":
		if err := c.SetTokenDisabled(*enable, false); err != nil {
			return err
		}
		fmt.Printf("tripwire %s enabled\n", *enable)
		return nil
	}
	ts, err := c.Tokens()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tSTATE\tCREATED\tLABEL")
	for _, t := range ts {
		state := "armed"
		if t.Disabled {
			state = "disabled"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", t.ID, t.Kind, state, t.CreatedAt.Format(time.RFC3339), t.Label)
	}
	return tw.Flush()
}
