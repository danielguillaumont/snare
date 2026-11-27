package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/danielguillaumont/snare/internal/gateway"
)

// gatewayPins lists a gateway's tool-definition pins and accepts a reviewed change
// (docs/M17-tool-integrity.md §2):
//
//	snare gateway pins -config gw.json
//	snare gateway pins -config gw.json -accept send_email
func gatewayPins(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("gateway pins", flag.ContinueOnError)
	config := fs.String("config", "", "gateway config written by snare plant gateway")
	accept := fs.String("accept", "", "re-pin this tool from the latest definition the gateway saw")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *config == "" {
		return errors.New("usage: snare gateway pins -config F [-accept TOOL]")
	}
	cfg, err := gateway.LoadConfig(*config)
	if err != nil {
		return err
	}
	if cfg.Integrity == nil {
		return fmt.Errorf("%s has no integrity block: tool definitions aren't pinned (replant without -integrity=false)", *config)
	}
	path := cfg.Integrity.PinFile
	if *accept != "" {
		ok, err := gateway.AcceptPin(path, *accept)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%s: no changed definition to accept", *accept)
		}
		fmt.Fprintf(out, "accepted the current definition of %s; it is the pin from now on\n", *accept)
		return nil
	}
	pins, err := gateway.ReadPins(path)
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		fmt.Fprintln(out, "no pins yet: they are taken at the first tools/list through this gateway")
		return nil
	}
	names := make([]string, 0, len(pins))
	for n := range pins {
		names = append(names, n)
	}
	sort.Strings(names)
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tSTATE\tPINNED\tLATEST")
	changed := 0
	for _, n := range names {
		p := pins[n]
		state := "unchanged"
		if p.Changed() {
			state, changed = "CHANGED", changed+1
		}
		fmt.Fprintf(tw, "%s\t%s\t%.12s\t%.12s\n", n, state, p.Pinned, p.Seen)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if changed > 0 {
		fmt.Fprintf(out, "\n%d changed. Review the server's current tool definitions, then: snare gateway pins -config %s -accept TOOL\n", changed, *config)
	}
	return nil
}
