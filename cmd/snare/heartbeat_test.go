package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

func TestPrintBeats(t *testing.T) {
	at := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	ok := []store.BeatState{{Heartbeat: store.Heartbeat{Channel: "http", LastAt: at, Count: 4, LastSource: "203.0.113.5"}, State: store.BeatOK, AgeSeconds: 180}}
	if err := printBeats(&b, ok); err != nil || !strings.Contains(b.String(), "http") || !strings.Contains(b.String(), "3m0s ago") {
		t.Fatalf("%v\n%s", err, b.String())
	}
	b.Reset()
	bad := append(ok, store.BeatState{Heartbeat: store.Heartbeat{Channel: "dns"}, State: store.BeatNever, AgeSeconds: -1})
	if err := printBeats(&b, bad); !errors.Is(err, errStale) || !strings.Contains(b.String(), "never") {
		t.Fatalf("never: %v\n%s", err, b.String())
	}
	b.Reset()
	if err := printBeats(&b, nil); err != nil || !strings.Contains(b.String(), "SNARE_HEARTBEAT") {
		t.Fatalf("none: %v %q", err, b.String())
	}
}
