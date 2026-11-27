package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/advise"
	"github.com/danielguillaumont/snare/internal/clientcfg"
	"github.com/danielguillaumont/snare/internal/decoys"
	"github.com/danielguillaumont/snare/internal/gateway"
	"github.com/danielguillaumont/snare/internal/plant"
	"github.com/danielguillaumont/snare/internal/store"
)

// initCmd is snare init (docs/M14-first-run.md §1): find MCP client configs, plan, wrap
// servers behind the gateway, check the alert path and print layer coverage.
func initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	clientPath := fs.String("client", "", "MCP client config to read (default: look in the known locations)")
	servers := fs.String("servers", "", "comma-separated servers to wrap (default: every local server with untrusted input, private data or a way out)")
	dir := fs.String("dir", "", "where gateway configs and the manifest go (default ~/.snare)")
	profile := fs.String("profile", "all", "decoy profiles for each wrapped server: all, or a comma-separated list of credentials, data, control")
	apply := fs.Bool("apply", false, "carry the plan out (default: print it and change nothing)")
	undo := fs.Bool("undo", false, "put wrapped servers back to their original commands")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		return fmt.Errorf("init takes no arguments, got %q", fs.Args())
	}
	o := initOptions{Apply: *apply, Undo: *undo, Profile: *profile, Admin: client(),
		Servers: strings.FieldsFunc(*servers, func(r rune) bool { return r == ',' || r == ' ' })}
	home, _ := os.UserHomeDir()
	o.Dir = *dir
	if o.Dir == "" {
		if home == "" {
			return errors.New("no home directory: pass -dir")
		}
		o.Dir = filepath.Join(home, ".snare")
	}
	abs, err := filepath.Abs(o.Dir) // client configs need an absolute gateway config path
	if err != nil {
		return err
	}
	o.Dir = abs
	if *clientPath != "" {
		o.Clients = []clientcfg.Candidate{{Client: clientName(*clientPath), Path: *clientPath}}
	} else {
		cwd, _ := os.Getwd()
		for _, c := range clientcfg.Candidates(runtime.GOOS, home, os.Getenv("APPDATA"), cwd) {
			if _, err := os.Stat(c.Path); err == nil {
				o.Clients = append(o.Clients, c)
			}
		}
		if len(o.Clients) == 0 {
			return errors.New("no MCP client config found in the known locations: pass -client FILE")
		}
	}
	if o.Snare, err = os.Executable(); err != nil {
		return err
	}
	return runInit(context.Background(), o, os.Stdout)
}

// clientName names a client config passed with -client, for gateway config file names.
func clientName(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if base == "mcp" || base == "" { // .vscode/mcp.json, .cursor/mcp.json
		base = filepath.Base(filepath.Dir(path))
	}
	return strings.TrimPrefix(base, ".")
}

type initOptions struct {
	Clients []clientcfg.Candidate
	Servers []string
	Dir     string
	Profile string
	Apply   bool
	Undo    bool
	Snare   string // absolute path of this binary, written into client configs
	Admin   *admin.Client
	// BeatWait bounds the liveness check (default 10s).
	BeatWait time.Duration
}

var errNotVerified = errors.New("a gateway could not be verified: see above")

func runInit(ctx context.Context, o initOptions, out io.Writer) error {
	if o.Undo {
		return runUndo(o, out)
	}
	manifest := filepath.Join(o.Dir, "snare-planted.json")
	type pending struct {
		file *clientcfg.File
		orig []byte
		gws  []string // gateway configs for the servers this run wraps
	}
	var todo []pending
	var recs []advise.Recommendation
	wrapCount := 0
	for _, c := range o.Clients {
		orig, err := os.ReadFile(c.Path)
		if err != nil {
			fmt.Fprintf(out, "%s: %v (skipped)\n", c.Path, err)
			continue
		}
		f, err := clientcfg.Parse(c.Path, orig)
		if err != nil {
			fmt.Fprintf(out, "%s: %v (skipped, not changed)\n", c.Path, err)
			continue
		}
		acts, rep, err := clientcfg.Plan(f, o.Servers)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s (%s):\n", c.Path, c.Client)
		p := pending{file: f, orig: orig}
		for _, a := range acts {
			fmt.Fprintf(out, "  %-6s %-20s %s\n", a.Do, a.Server, a.Why)
			if a.Do != clientcfg.Wrap {
				continue
			}
			wrapCount++
			gw := clientcfg.GatewayPath(o.Dir, c.Client, a.Server)
			p.gws = append(p.gws, gw)
			if o.Apply {
				if err := f.Wrap(a.Server, o.Snare, gw); err != nil {
					return err
				}
			}
		}
		todo = append(todo, p)
		for _, r := range rep.Recommendations {
			if !strings.HasPrefix(r.Command, "snare plant mcp") && r.Command != "" { // the gateway replaces the decoy server
				recs = append(recs, r)
			}
		}
	}
	n := len(decoys.Catalog)
	if sel, err := decoys.Select(decoys.ParseProfiles(o.Profile), nil); err == nil {
		n = len(sel)
	} else {
		return fmt.Errorf("-profile: %w", err)
	}
	if wrapCount > 0 {
		fmt.Fprintf(out, "\nEach wrapped server gets %d decoys in its tool list (-profile %s).\n", n, o.Profile)
		if wrapCount > 1 && o.Profile == "all" {
			fmt.Fprintln(out, "With several servers, a long list of sensitive-sounding tools can make the agent decline real work")
			fmt.Fprintln(out, "(docs/results-m13.md). -profile credentials plants 4 per server instead.")
		}
	}
	if len(recs) > 0 {
		fmt.Fprintln(out, "\nAlso worth doing (init doesn't, because these write into your own data):")
		seen := map[string]bool{}
		for _, r := range recs {
			if !seen[r.Command] {
				seen[r.Command] = true
				fmt.Fprintf(out, "  $ %s\n    %s\n", r.Command, r.Why)
			}
		}
	}
	if !o.Apply {
		fmt.Fprintln(out, "\nDry run: nothing minted or written. Re-run with -apply to do it.")
		return nil
	}
	if wrapCount == 0 {
		fmt.Fprintln(out, "\nNothing to wrap.")
		return coverage(manifest, out)
	}

	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return err
	}
	var gws []string
	for _, p := range todo {
		for _, gw := range p.gws {
			if _, err := os.Stat(gw); err == nil {
				fmt.Fprintf(out, "reusing %s\n", gw)
			} else {
				entries, _, err := plant.Gateway(o.Admin, plant.GatewayOptions{ConfigPath: gw, Profiles: decoys.ParseProfiles(o.Profile),
					Style: "auto", Seed: randSeed(), Command: o.Snare})
				if err != nil {
					return fmt.Errorf("plant gateway %s: %w", gw, err)
				}
				if err := plant.AppendManifest(manifest, entries); err != nil {
					return err
				}
			}
			gws = append(gws, gw)
		}
		if len(p.gws) == 0 {
			continue
		}
		backup := p.file.Path + ".snare-backup-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.WriteFile(backup, p.orig, 0o600); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		if err := writeKeepingMode(p.file.Path, p.file.Bytes()); err != nil {
			return err
		}
		fmt.Fprintf(out, "updated %s (backup: %s)\n", p.file.Path, backup)
	}

	fmt.Fprintln(out, "\nLiveness:")
	ok := true
	for _, gw := range gws {
		msg, err := verify(ctx, o, gw)
		if err != nil {
			ok = false
			fmt.Fprintf(out, "  NOT VERIFIED %s: %v\n", filepath.Base(gw), err)
			continue
		}
		fmt.Fprintf(out, "  verified     %s: %s\n", filepath.Base(gw), msg)
	}
	fmt.Fprintln(out)
	if err := coverage(manifest, out); err != nil {
		return err
	}
	fmt.Fprintln(out, "\nRestart your MCP client to pick up the change. To undo: snare init -undo")
	if !ok {
		fmt.Fprintln(out, "Until a gateway is verified its touches may not reach Snare; it still forwards every call (fail-open).")
		return errNotVerified
	}
	return nil
}

// verify sends one heartbeat through gw's callback URL and waits until Snare records it.
func verify(ctx context.Context, o initOptions, gw string) (string, error) {
	cfg, err := gateway.LoadConfig(gw)
	if err != nil {
		return "", err
	}
	session := "init-" + randHex(8)
	start := time.Now()
	if err := gateway.Beat(ctx, cfg, session, nil); err != nil {
		return "", fmt.Errorf("%w (is SNARE_PUBLIC_URL on the server the address this machine reaches it at?)", err)
	}
	wait := o.BeatWait
	if wait == 0 {
		wait = 10 * time.Second
	}
	for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		bs, err := o.Admin.Heartbeats()
		if err != nil {
			return "", fmt.Errorf("reading heartbeats: %w", err)
		}
		for _, b := range bs {
			if b.Channel == store.BeatGateway && b.LastSource == session {
				return fmt.Sprintf("heartbeat recorded %s after sending", time.Since(start).Round(time.Millisecond)), nil
			}
		}
	}
	return "", fmt.Errorf("the heartbeat was sent but Snare hadn't recorded it after %s (does the callback URL reach this tenant's server?)", wait)
}

func coverage(manifest string, out io.Writer) error {
	ps, err := advise.LoadManifest(manifest)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(out, "No manifest yet: nothing planted.")
		return nil
	}
	if err != nil {
		return err
	}
	printCoverageTo(out, advise.Coverage(ps))
	return nil
}

func runUndo(o initOptions, out io.Writer) error {
	changed := 0
	for _, c := range o.Clients {
		orig, err := os.ReadFile(c.Path)
		if err != nil {
			fmt.Fprintf(out, "%s: %v (skipped)\n", c.Path, err)
			continue
		}
		f, err := clientcfg.Parse(c.Path, orig)
		if err != nil {
			fmt.Fprintf(out, "%s: %v (skipped, not changed)\n", c.Path, err)
			continue
		}
		var names []string
		for _, s := range f.Servers() {
			if ok, err := f.Unwrap(s.Name); err != nil {
				return err
			} else if ok {
				names = append(names, s.Name)
			}
		}
		if len(names) == 0 {
			continue
		}
		backup := c.Path + ".snare-backup-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.WriteFile(backup, orig, 0o600); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		if err := writeKeepingMode(c.Path, f.Bytes()); err != nil {
			return err
		}
		changed += len(names)
		fmt.Fprintf(out, "%s: restored %s (backup: %s)\n", c.Path, strings.Join(names, ", "), backup)
	}
	if changed == 0 {
		fmt.Fprintln(out, "No wrapped servers found.")
		return nil
	}
	fmt.Fprintf(out, "\nGateway configs in %s are kept. Their decoys can still fire if an agent learned a name;\n", o.Dir)
	fmt.Fprintf(out, "disable them with snare tokens -disable ID (IDs are in %s).\n", filepath.Join(o.Dir, "snare-planted.json"))
	fmt.Fprintln(out, "Restart your MCP client to pick up the change.")
	return nil
}

// writeKeepingMode replaces path with b through a temp file, keeping path's permissions.
func writeKeepingMode(path string, b []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snare-init-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func randSeed() uint64 {
	s, _, err := nameOptions("", "")
	if err != nil {
		panic(err)
	}
	return s
}
