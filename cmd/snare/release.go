package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/gateway"
)

// gatewayRelease lifts a containment freeze (docs/M8-containment.md §4). The release is
// recorded through the admin API first; the freeze is deleted only if that succeeds.
//
//	snare gateway release -config gw.json -note "INC-142: poisoned ticket removed"
func gatewayRelease(args []string) error {
	fs := flag.NewFlagSet("gateway release", flag.ExitOnError)
	config := fs.String("config", "", "gateway config whose session is frozen")
	note := fs.String("note", "", "why it is safe to release (recorded in the audit log)")
	_ = fs.Parse(args)
	if *config == "" || strings.TrimSpace(*note) == "" {
		fs.Usage()
		return errors.New("usage: snare gateway release -config F -note TEXT")
	}
	n, state, err := releaseFrozen(client(), *config, *note)
	if err != nil {
		return err
	}
	fmt.Printf("released: %s removed; %d contained touch(es) on record; audited as session.release\n", state, n)
	return nil
}

type releaser interface {
	ReleaseSession(session, note string) (admin.ReleaseResponse, error)
}

func releaseFrozen(c releaser, config, note string) (int, string, error) {
	cfg, err := gateway.LoadConfig(config)
	if err != nil {
		return 0, "", err
	}
	if cfg.Contain == nil {
		return 0, "", fmt.Errorf("%s has no contain block: containment is off for this gateway", config)
	}
	f, frozen, err := gateway.ReadFrozen(cfg.Contain.StateFile)
	if err != nil {
		return 0, "", err
	}
	if !frozen {
		return 0, "", fmt.Errorf("not frozen: %s does not exist", cfg.Contain.StateFile)
	}
	if f.Session == "" {
		return 0, "", fmt.Errorf("%s is unreadable, so the session is unknown; check it, then delete it by hand (that release is not audited)", cfg.Contain.StateFile)
	}
	r, err := c.ReleaseSession(f.Session, strings.TrimSpace(note))
	if err != nil {
		return 0, "", fmt.Errorf("recording the release (the session stays frozen): %w", err)
	}
	if err := os.Remove(cfg.Contain.StateFile); err != nil {
		return 0, "", fmt.Errorf("release recorded, but %s could not be removed: %w", cfg.Contain.StateFile, err)
	}
	return r.ContainedTouches, cfg.Contain.StateFile, nil
}
