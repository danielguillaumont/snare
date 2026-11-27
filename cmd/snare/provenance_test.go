package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/provenance"
)

func TestPrintProvenance(t *testing.T) {
	var b bytes.Buffer
	ms := []provenance.Match{{Path: "kb/T-42.md"}, {Path: "mirror/T-42.md", LF: true}}
	if err := printProvenance(&b, ms, 3); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); !strings.HasPrefix(out, "kb/T-42.md\n") || !strings.Contains(out, "mirror/T-42.md\t(matches with its CRLF line ends read as LF)") {
		t.Fatalf("output %q", out)
	}
	if err := printProvenance(&b, nil, 3); err == nil || !strings.Contains(err.Error(), "3 files") {
		t.Fatalf("no-match error: %v", err)
	}
}
