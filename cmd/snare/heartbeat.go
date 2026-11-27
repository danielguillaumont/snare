package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

// heartbeatCmd prints when each channel was last verified (docs/M11-heartbeat.md §2). It
// exits non-zero when a channel is stale or has never beaten, so it can run from cron.
func heartbeatCmd(args []string) error {
	fs := flag.NewFlagSet("heartbeat", flag.ExitOnError)
	_ = fs.Parse(args)
	bs, err := client().Heartbeats()
	if err != nil {
		return err
	}
	return printBeats(os.Stdout, bs)
}

var errStale = errors.New("a channel is stale or has never been verified")

func printBeats(w io.Writer, bs []store.BeatState) error {
	if len(bs) == 0 {
		fmt.Fprintln(w, "no heartbeats: set SNARE_HEARTBEAT on the server, or plant a gateway (heartbeat on by default)")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CHANNEL\tSTATE\tLAST VERIFIED\tBEATS\tLAST FROM")
	bad := false
	for _, b := range bs {
		last, from := "-", "-"
		if b.State != store.BeatNever {
			last = b.LastAt.Format(time.RFC3339) + " (" + (time.Duration(b.AgeSeconds) * time.Second).String() + " ago)"
			from = b.LastSource
		}
		if b.State != store.BeatOK {
			bad = true
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", b.Channel, b.State, last, b.Count, from)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if bad {
		return errStale
	}
	return nil
}
