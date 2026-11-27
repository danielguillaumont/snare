package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/danielguillaumont/snare/internal/provenance"
)

// provenanceCmd names the file an input fingerprint came from (docs/M9-provenance.md §3).
// It runs on the machine with the documents and sends nothing anywhere.
//
//	snare provenance find -hash 3fa1c2d4e5f60718 kb/ tickets/
func provenanceCmd(args []string) error {
	if len(args) == 0 || args[0] != "find" {
		return errors.New("usage: snare provenance find -hash FINGERPRINT [dir ...]")
	}
	fl := flag.NewFlagSet("provenance find", flag.ExitOnError)
	hash := fl.String("hash", "", "input fingerprint from the alert (16 hex characters)")
	_ = fl.Parse(args[1:])
	dirs := fl.Args()
	if len(dirs) == 0 {
		dirs = []string{"."}
	}
	matches, scanned, err := provenance.Find(strings.ToLower(*hash), dirs)
	if err != nil {
		return err
	}
	return printProvenance(os.Stdout, matches, scanned)
}

func printProvenance(w io.Writer, matches []provenance.Match, scanned int) error {
	for _, m := range matches {
		if m.LF {
			fmt.Fprintf(w, "%s\t(matches with its CRLF line ends read as LF)\n", m.Path)
		} else {
			fmt.Fprintln(w, m.Path)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("no file matches (%d files hashed)", scanned)
	}
	return nil
}
