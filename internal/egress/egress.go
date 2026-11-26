// Package egress keeps tenant-configured sink URLs from reaching our own network (SSRF).
//
// A hosted Snare sends HTTP requests to URLs its tenants choose. Without a guard, a tenant
// could point a "SIEM" at 169.254.169.254 (cloud metadata), at localhost:8081 (the admin
// API), or at anything else inside the VPC. Two checks:
//
//  1. CheckURL at configuration time, for a clear error message.
//  2. Client, whose dialer refuses forbidden addresses at connect time. This is the check
//     that matters: it sees the address actually dialled, so DNS rebinding (a host that
//     resolves public at config time and private at send time) doesn't get through.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

var ErrForbidden = errors.New("egress: destination not allowed")

// Policy controls what sink URLs may reach. The zero value is the production policy.
type Policy struct {
	// AllowPrivate permits http:// and private/loopback addresses. Tests and self-hosted
	// single-team installs only (SNARE_SINK_ALLOW_PRIVATE=1).
	AllowPrivate bool
}

var extraBlocked = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT / shared address space
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64: can embed a private IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("2002::/16"),      // 6to4: can embed a private IPv4
}

// Allowed reports whether an address may be dialled under the production policy.
func Allowed(a netip.Addr) bool {
	a = a.Unmap() // ::ffff:10.0.0.1 is 10.0.0.1
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range extraBlocked {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// CheckURL validates a sink URL before it is stored.
func (p Policy) CheckURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("egress: invalid URL")
	}
	if u.User != nil {
		return fmt.Errorf("egress: credentials in URLs are not allowed; use the sink's auth fields")
	}
	if p.AllowPrivate {
		if u.Scheme != "https" && u.Scheme != "http" {
			return fmt.Errorf("egress: scheme must be http or https")
		}
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("egress: sink URLs must use https")
	}
	host := u.Hostname()
	if a, err := netip.ParseAddr(host); err == nil {
		if !Allowed(a) {
			return fmt.Errorf("%w: %s", ErrForbidden, host)
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("egress: cannot resolve %s", host)
	}
	for _, a := range addrs {
		if !Allowed(a) {
			return fmt.Errorf("%w: %s resolves to %s", ErrForbidden, host, a)
		}
	}
	return nil
}

// Client returns an HTTP client whose every connection is checked against the policy, with
// redirects disabled (a redirect is a second, unchecked destination).
func (p Policy) Client(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	if !p.AllowPrivate {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !Allowed(ap.Addr()) {
				return fmt.Errorf("%w: %s", ErrForbidden, address)
			}
			return nil
		}
	}
	tr := &http.Transport{
		Proxy:                 nil, // a proxy would hide the real destination from the check
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
