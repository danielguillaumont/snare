package egress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	deny := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0",
		"100.64.0.1", "224.0.0.1", "255.255.255.255", "198.18.0.1",
		"::1", "::", "fe80::1", "fc00::1", "fd12::1", "ff02::1",
		"::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::a00:1", "2002:a00:1::1",
	}
	allow := []string{"8.8.8.8", "1.1.1.1", "203.0.114.1", "2606:4700:4700::1111"}
	for _, s := range deny {
		if Allowed(netip.MustParseAddr(s)) {
			t.Errorf("allowed %s", s)
		}
	}
	for _, s := range allow {
		if !Allowed(netip.MustParseAddr(s)) {
			t.Errorf("denied %s", s)
		}
	}
}

func TestCheckURL(t *testing.T) {
	ctx := context.Background()
	var p Policy
	for _, u := range []string{
		"http://8.8.8.8/x",                    // not https
		"https://127.0.0.1/",                  // loopback literal
		"https://[::ffff:169.254.169.254]/",   // mapped metadata address
		"https://localhost/",                  // resolves to loopback
		"https://user:pw@8.8.8.8/",            // credentials in URL
		"ftp://8.8.8.8/", "https://", "::bad", // malformed
	} {
		if err := p.CheckURL(ctx, u); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
	if err := p.CheckURL(ctx, "https://8.8.8.8/services/collector/event"); err != nil {
		t.Errorf("rejected public literal: %v", err)
	}
	dev := Policy{AllowPrivate: true}
	if err := dev.CheckURL(ctx, "http://127.0.0.1:8088/"); err != nil {
		t.Errorf("dev policy rejected localhost: %v", err)
	}
}

// The connect-time check is what stops DNS rebinding: even a URL that passed CheckURL can't
// reach a loopback listener through the production client.
func TestClientRefusesPrivateAtConnectTime(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer ts.Close()
	_, err := Policy{}.Client(2 * time.Second).Get(ts.URL)
	if err == nil || !errors.Is(err, ErrForbidden) {
		t.Fatalf("production client reached %s: %v", ts.URL, err)
	}
	resp, err := Policy{AllowPrivate: true}.Client(2 * time.Second).Get(ts.URL)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("dev client: %v", err)
	}
	resp.Body.Close()
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Error("redirect followed") }))
	defer target.Close()
	ts := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer ts.Close()
	resp, err := Policy{AllowPrivate: true}.Client(2 * time.Second).Get(ts.URL)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("got %v %v", resp, err)
	}
	resp.Body.Close()
}
