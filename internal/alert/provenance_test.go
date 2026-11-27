package alert

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/store"
)

func TestAlertNamesTheLastInput(t *testing.T) {
	tok := store.Token{ID: "t1", Kind: "decoy", Label: "billing decoy"}
	ev := store.Event{ID: 7, Channel: "http", Inputs: []store.Input{
		{Tool: "search", Fingerprint: "00000000000000aa", Length: 12, AgeSeconds: 90},
		{Tool: "read_file", Fingerprint: "3fa1c2d4e5f60718", Length: 1240, AgeSeconds: 4},
	}}
	a := New(tok, ev)
	want := "Last input before this touch: read_file returned 1,240 characters (fingerprint 3fa1c2d4e5f60718) 4 s earlier"
	if !strings.Contains(a.FindingInfo.Desc, want) {
		t.Fatalf("desc: %q", a.FindingInfo.Desc)
	}
	b, _ := json.Marshal(a)
	if !strings.Contains(string(b), `"inputs":[{"tool":"search"`) {
		t.Fatalf("unmapped.inputs missing: %s", b)
	}
	ev.Inputs[1].Source = "tickets/T-42.md"
	if d := New(tok, ev).FindingInfo.Desc; !strings.Contains(d, "1,240 characters from tickets/T-42.md (") {
		t.Fatalf("named source: %q", d)
	}
	if d := New(tok, store.Event{ID: 8}).FindingInfo.Desc; strings.Contains(d, "Last input") {
		t.Fatalf("no ledger, no sentence: %q", d)
	}
	for n, w := range map[int]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567"} {
		if g := thousands(n); g != w {
			t.Errorf("thousands(%d) = %q", n, g)
		}
	}
	for s, w := range map[int]string{4: "4 s", 119: "119 s", 600: "10 min", 7200: "2 h"} {
		if g := ago(s); g != w {
			t.Errorf("ago(%d) = %q", s, g)
		}
	}
}
