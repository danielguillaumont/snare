package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/gateway"
)

func TestGatewayPins(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gw.json")
	b, _ := json.Marshal(gateway.Config{CallbackURL: "http://127.0.0.1:1", Style: "catalog",
		Integrity: &gateway.Integrity{Token: "integritytok"}})
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := gatewayPins([]string{"-config", cfgPath}, &out); err != nil || !strings.Contains(out.String(), "no pins yet") {
		t.Fatalf("%v %s", err, out.String())
	}
	if err := gateway.WritePins(cfgPath+".pins", map[string]gateway.Pin{
		"read_file":  {Pinned: "aaaa", Seen: "aaaa"},
		"send_email": {Pinned: "bbbb", Seen: "cccc"},
	}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := gatewayPins([]string{"-config", cfgPath}, &out); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "send_email  CHANGED") || !strings.Contains(s, "read_file   unchanged") || !strings.Contains(s, "1 changed") {
		t.Fatalf("list:\n%s", s)
	}
	if err := gatewayPins([]string{"-config", cfgPath, "-accept", "read_file"}, &out); err == nil {
		t.Fatal("accepted an unchanged tool")
	}
	if err := gatewayPins([]string{"-config", cfgPath, "-accept", "send_email"}, &out); err != nil {
		t.Fatal(err)
	}
	pins, _ := gateway.ReadPins(cfgPath + ".pins")
	if p := pins["send_email"]; p.Changed() || p.Pinned != "cccc" {
		t.Fatalf("after accept: %+v", p)
	}
}
