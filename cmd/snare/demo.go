package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/server"
	"github.com/danielguillaumont/snare/internal/store"
)

// demoCmd runs a complete, throwaway Snare on this machine (docs/M4e-lifecycle.md §3).
func demoCmd(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	httpAddr := fs.String("http", "127.0.0.1:18080", "callback listener")
	adminAddr := fs.String("admin", "127.0.0.1:18081", "admin API")
	dashAddr := fs.String("dashboard", "127.0.0.1:18090", "dashboard")
	_ = fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runDemo(ctx, demoOptions{HTTP: *httpAddr, Admin: *adminAddr, Dashboard: *dashAddr}, os.Stdout)
}

type demoOptions struct {
	HTTP, Admin, Dashboard string
	// ready, if set, is called with what the demo printed once it is ready (tests).
	ready func(demoInfo)
}

type demoInfo struct {
	Dir, DashboardURL, ViewerKey, AdminURL, AdminKey string
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func runDemo(ctx context.Context, o demoOptions, out io.Writer) error {
	dir, err := os.MkdirTemp("", "snare-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	logf, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		return err
	}
	defer logf.Close()

	opKey := randHex(24)
	srv, err := server.Start(server.Config{
		Key: randBytes(32), AdminKey: []byte(opKey), SealKey: randBytes(32),
		HTTPAddr: o.HTTP, AdminAddr: o.Admin, DashboardAddr: o.Dashboard, DashboardDev: true,
		PublicURL: "http://" + o.HTTP, DBPath: filepath.Join(dir, "snare.db"),
	}, slog.New(slog.NewTextHandler(logf, nil)))
	if err != nil {
		return fmt.Errorf("start: %w (is another demo already running? choose ports with -http, -admin, -dashboard)", err)
	}
	defer srv.Shutdown(context.Background())
	pub := "http://" + srv.HTTPAddr
	op := &admin.Client{BaseURL: "http://" + srv.AdminAddr, Key: opKey}

	tn, err := op.CreateTenant("Acme Support Agents")
	if err != nil {
		return err
	}
	viewer, err := op.IssueKey(tn.ID, store.RoleViewer)
	if err != nil {
		return err
	}
	adm, err := op.IssueKey(tn.ID, store.RoleAdmin)
	if err != nil {
		return err
	}
	ta := &admin.Client{BaseURL: op.BaseURL, Key: adm.Key}
	honey, err := ta.Mint("honey_credential", "billing-svc/.env: PAYMENTS_API_KEY", "")
	if err != nil {
		return err
	}
	if _, err := ta.Mint("decoy_tool", "support-agent MCP: export_customer_records", ""); err != nil {
		return err
	}
	canary, err := ta.Mint("canary_url", "KB article 4471: refund runbook link", "")
	if err != nil {
		return err
	}

	// The "attack": an agent that read a poisoned ticket follows the canary link, then tries
	// the payments key it found in the repo. Two tripwires from one source: Critical.
	attacker := &http.Client{Timeout: 5 * time.Second}
	for _, req := range []func() (*http.Request, error){
		func() (*http.Request, error) { return http.NewRequest("GET", pub+"/v1/"+canary.Token+"?ref=ticket-8812", nil) },
		func() (*http.Request, error) {
			r, err := http.NewRequest("GET", pub+"/v1/charges", nil)
			if err == nil {
				r.Header.Set("Authorization", "Bearer "+honey.Token)
			}
			return r, err
		},
	} {
		r, err := req()
		if err != nil {
			return err
		}
		r.Header.Set("User-Agent", "python-httpx/0.28 (agent)")
		resp, err := attacker.Do(r)
		if err != nil {
			return err
		}
		resp.Body.Close()
		time.Sleep(200 * time.Millisecond)
	}

	info := demoInfo{Dir: dir, DashboardURL: "http://" + srv.DashboardAddr, ViewerKey: viewer.Key,
		AdminURL: op.BaseURL, AdminKey: adm.Key}
	fmt.Fprintf(out, `
Snare demo is running. Nothing leaves this machine and no model is called.

  Dashboard:  %s
  Sign in with this viewer key:
    %s

  Three tripwires are planted for tenant %q. A simulated agent just followed
  the canary link and then used the honey API key, so the second touch is Critical.

  Try the CLI from another terminal. Set these two variables:
    SNARE_ADMIN_URL=%s
    SNARE_ADMIN_KEY=%s
  then run: snare events
  and:      snare triage -event ID -status false_positive -note "just the demo"

  Everything lives in %s and is deleted on exit.
  Ctrl-C to stop.
`, info.DashboardURL, info.ViewerKey, tn.Name, info.AdminURL, info.AdminKey, dir)
	if o.ready != nil {
		o.ready(info)
	}
	<-ctx.Done()
	fmt.Fprintln(out, "\nstopping; demo data deleted")
	return nil
}
