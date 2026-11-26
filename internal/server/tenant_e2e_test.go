package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
)

// M4 through real listeners: the operator creates two tenants and issues keys; each tenant mints
// a token through the API; a touch on one shows up for that tenant only, over the API and the
// dashboard listener.
func TestEndToEndTwoTenants(t *testing.T) {
	op := "test-operator-key-0123456789abcdef"
	cfg := Config{
		Key:           bytes.Repeat([]byte{42}, 32),
		AdminKey:      []byte(op),
		HTTPAddr:      "127.0.0.1:0",
		AdminAddr:     "127.0.0.1:0",
		DashboardAddr: "127.0.0.1:0",
		DashboardDev:  true,
		Zone:          "cb.test.",
		AnswerIP:      net.ParseIP("127.0.0.1"),
		PublicURL:     "http://cb.test",
		DBPath:        filepath.Join(t.TempDir(), "snare.db"),
		SealKey:       bytes.Repeat([]byte{5}, 32),
	}
	s, err := Start(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	base := "http://" + s.AdminAddr
	operator := &admin.Client{BaseURL: base, Key: op}

	type tenantEnv struct {
		id     string
		c      *admin.Client
		minted admin.MintResponse
	}
	var tenants []tenantEnv
	for _, name := range []string{"Acme", "Beta"} {
		tn, err := operator.CreateTenant(name)
		if err != nil {
			t.Fatal(err)
		}
		k, err := operator.IssueKey(tn.ID, "admin")
		if err != nil {
			t.Fatal(err)
		}
		c := &admin.Client{BaseURL: base, Key: k.Key}
		m, err := c.Mint("canary_url", name+" runbook link", "")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenantEnv{tn.ID, c, m})
	}

	resp, err := http.Get("http://" + s.HTTPAddr + "/r/" + tenants[1].minted.Token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		evs, err := tenants[1].c.Events("", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) == 1 && evs[0].TokenID == tenants[1].minted.ID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tenant B never saw its event: %+v", evs)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if evs, _ := tenants[0].c.Events("", 10); len(evs) != 0 {
		t.Fatalf("tenant A sees %d events from B", len(evs))
	}
	// Tenant A asking for B's token by id is a 404, same as a token that doesn't exist.
	if _, err := tenants[0].c.Events(tenants[1].minted.ID, 10); err != nil {
		t.Fatalf("filter by foreign id should just be empty: %v", err)
	}
	if evs, _ := tenants[0].c.Events(tenants[1].minted.ID, 10); len(evs) != 0 {
		t.Fatal("tenant A read B's events by naming B's token id")
	}

	// Dashboard listener is up with its security headers.
	res, err := http.Get("http://" + s.DashboardAddr + "/login")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("dashboard /login: %d %q", res.StatusCode, res.Header.Get("Content-Security-Policy"))
	}
}

func TestDashboardDevModeRefusedOffLoopback(t *testing.T) {
	t.Setenv("SNARE_KEY", strings.Repeat("ab", 32))
	t.Setenv("SNARE_ADMIN_KEY", strings.Repeat("x", 32))
	t.Setenv("SNARE_DASHBOARD_ADDR", "0.0.0.0:8443")
	t.Setenv("SNARE_DASHBOARD_DEV", "1")
	if _, err := FromEnv(); err == nil {
		t.Fatal("dev-mode dashboard (no Secure cookies) accepted on a public address")
	}
}
