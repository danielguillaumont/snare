package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/admin"
)

type fakeReleaser struct {
	err      error
	sessions []string
}

func (f *fakeReleaser) ReleaseSession(session, note string) (admin.ReleaseResponse, error) {
	f.sessions = append(f.sessions, session)
	return admin.ReleaseResponse{ContainedTouches: 1}, f.err
}

func TestReleaseFrozen(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "gw.json")
	_ = os.WriteFile(cfg, []byte(`{"callback_url":"https://cb.example.test","style":"auto","contain":{}}`), 0o600)
	state := cfg + ".frozen"

	if _, _, err := releaseFrozen(&fakeReleaser{}, cfg, "n"); err == nil || !strings.Contains(err.Error(), "not frozen") {
		t.Fatalf("nothing frozen: %v", err)
	}
	_ = os.WriteFile(state, []byte(`{"session":"s0123456789ab","stage":"exfiltration"}`), 0o600)

	// The server refuses: the freeze stays.
	down := &fakeReleaser{err: errors.New("connection refused")}
	if _, _, err := releaseFrozen(down, cfg, "n"); err == nil || !strings.Contains(err.Error(), "stays frozen") {
		t.Fatalf("server down: %v", err)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatal("freeze removed although the release was not recorded")
	}

	ok := &fakeReleaser{}
	if n, _, err := releaseFrozen(ok, cfg, "INC-1"); err != nil || n != 1 || len(ok.sessions) != 1 || ok.sessions[0] != "s0123456789ab" {
		t.Fatalf("release: %d %v %v", n, err, ok.sessions)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("freeze not removed after an audited release")
	}

	// Containment off: refuse, rather than pretend.
	_ = os.WriteFile(cfg, []byte(`{"callback_url":"https://cb.example.test","style":"auto"}`), 0o600)
	if _, _, err := releaseFrozen(ok, cfg, "n"); err == nil || !strings.Contains(err.Error(), "containment is off") {
		t.Fatalf("no contain block: %v", err)
	}
}
