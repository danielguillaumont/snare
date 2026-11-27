package main

import (
	"bytes"
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/store"
)

// M14 §2 exit: snare demo -attack prints all five steps from a real incident, and each step
// is what the admin API holds.
func TestDemoAttack(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan demoInfo, 1)
	done := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		done <- runDemo(ctx, demoOptions{HTTP: freeAddr(t), Admin: freeAddr(t), Dashboard: freeAddr(t), Attack: true,
			ready: func(i demoInfo) { ready <- i }}, &out)
	}()
	var info demoInfo
	select {
	case info = <-ready:
	case err := <-done:
		t.Fatalf("demo exited early: %v\n%s", err, out.String())
	case <-time.After(30 * time.Second):
		t.Fatal("demo not ready")
	}
	st := info.Story
	if st == nil || st.Leaked || st.Decoy == "" || len(st.Steps) != 5 {
		t.Fatalf("story: %+v", st)
	}
	text := out.String()
	for _, want := range []string{"steered     last input before the first touch: tickets/T-8812.md",
		"recon", "collection", "contained   yes", "attributed  one incident", "isError=true"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}

	// The same facts, from the admin API.
	c := &admin.Client{BaseURL: info.AdminURL, Key: info.AdminKey}
	d, err := c.Incident(st.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(d.Stages, store.StageRecon) || !slices.Contains(d.Stages, store.StageExfiltration) || d.Session == "" {
		t.Fatalf("incident stages %v session %q", d.Stages, d.Session)
	}
	var blocked, named bool
	for _, tch := range d.Timeline {
		if tch.Session != d.Session {
			t.Errorf("touch %d from another session", tch.ID)
		}
		blocked = blocked || tch.Containment == store.ContainBlocked
		for _, in := range tch.Inputs {
			named = named || in.Source == "tickets/T-8812.md"
		}
	}
	if !blocked || !named {
		t.Errorf("blocked %v, ticket named %v: %+v", blocked, named, d.Timeline)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("demo did not stop")
	}
	if _, err := os.Stat(info.Dir); !os.IsNotExist(err) {
		t.Fatalf("demo directory left behind: %v", err)
	}
}
