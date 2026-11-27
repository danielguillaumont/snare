package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/store"
)

// incidentsCmd lists incidents, or prints one incident's timeline (docs/M7-incidents.md §4).
func incidentsCmd(args []string) error {
	fs := flag.NewFlagSet("incidents", flag.ExitOnError)
	id := fs.Int64("id", 0, "print this incident's timeline")
	limit := fs.Int("limit", 50, "max incidents")
	_ = fs.Parse(args)
	c := client()
	if *id != 0 {
		d, err := c.Incident(*id)
		if err != nil {
			return err
		}
		return printTimeline(os.Stdout, d)
	}
	ins, err := c.Incidents(*limit)
	if err != nil {
		return err
	}
	return printIncidents(os.Stdout, ins)
}

func printIncidents(w io.Writer, ins []store.Incident) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tLAST SEEN\tTOUCHES\tTRIPWIRES\tOPEN\tSTAGES\tSOURCE")
	for _, in := range ins {
		fmt.Fprintf(tw, "%d\t%s\t%d\t%d\t%d\t%s\t%s\n", in.ID, in.LastSeen.Format(time.RFC3339), in.Touches,
			in.Tripwires, in.Open, strings.Join(in.Stages, " > "), source(in.Session, in.SourceIP))
	}
	return tw.Flush()
}

func printTimeline(w io.Writer, d admin.IncidentDetail) error {
	fmt.Fprintf(w, "incident %d  %s\n", d.ID, source(d.Session, d.SourceIP))
	fmt.Fprintf(w, "  %s to %s, %d touches of %d tripwires, %d open\n", d.FirstSeen.Format(time.RFC3339),
		d.LastSeen.Format(time.RFC3339), d.Touches, d.Tripwires, d.Open)
	fmt.Fprintf(w, "  stages: %s\n\n", strings.Join(d.Stages, " > "))
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tSTAGE\tLAYER\tEVENT\tSTATUS\tTRIPWIRE")
	for _, t := range d.Timeline {
		stage, layer := t.Stage, t.Layer
		if stage == "" {
			stage, layer = "-", "-"
		}
		status := t.Status
		if t.Warning {
			status = "warning" // a lead, never an alert on its own (M16)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s (%s)\n", t.At.Format(time.RFC3339), stage, layer, t.ID, status, t.Label, t.Kind)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	return printInputs(w, d.Timeline)
}

// printInputs lists, per touch, what the agent received through the gateway before it
// (docs/M9-provenance.md), newest first.
func printInputs(w io.Writer, touches []admin.IncidentTouch) error {
	for _, t := range touches {
		if len(t.Inputs) == 0 {
			continue
		}
		fmt.Fprintf(w, "\ninputs before event %d, newest first:\n", t.ID)
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "  AGO\tTOOL\tCHARS\tFINGERPRINT\tSOURCE")
		for i := len(t.Inputs) - 1; i >= 0; i-- {
			in := t.Inputs[i]
			src := in.Source
			if src == "" {
				src = "-"
			}
			fmt.Fprintf(tw, "  %ds\t%s\t%d\t%s\t%s\n", in.AgeSeconds, in.Tool, in.Length, in.Fingerprint, src)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

func source(session, ip string) string {
	if session != "" {
		return "session " + session + " (first from " + ip + ")"
	}
	return "source " + ip
}
