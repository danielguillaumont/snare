package server

// End-to-end test for the M11 exit criterion (docs/M11-heartbeat.md): a real server probing
// its own public URL and DNS name, and a planted gateway beating at start. All three channels
// show verified, nothing becomes an event, and breaking DNS turns only that channel stale.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/gateway"
	"github.com/danielguillaumont/snare/internal/plant"
	"github.com/danielguillaumont/snare/internal/store"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestEndToEndHeartbeat(t *testing.T) {
	clk := &testClock{t: time.Now().UTC()}
	httpAddr := freePort(t)
	cfg := Config{
		Key:           bytes.Repeat([]byte{11}, 32),
		AdminKey:      []byte("test-admin-key-0123456789abcdef"),
		HTTPAddr:      httpAddr,
		AdminAddr:     "127.0.0.1:0",
		DNSAddr:       "127.0.0.1:0",
		DashboardAddr: "127.0.0.1:0",
		Zone:          "cb.test.",
		AnswerIP:      net.ParseIP("127.0.0.1"),
		PublicURL:     "http://" + httpAddr, // the probe goes out through the public URL
		DBPath:        filepath.Join(t.TempDir(), "snare.db"),
		Heartbeat:     time.Hour, // one probe at start; the test drives the rest
		now:           clk.now,
		resolver: func(s *Server) *net.Resolver {
			return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, s.DNSAddr)
			}}
		},
	}
	s, err := Start(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	c := &admin.Client{BaseURL: "http://" + s.AdminAddr, Key: string(cfg.AdminKey)}

	// A planted gateway beats once at start.
	gwPath := filepath.Join(t.TempDir(), "gw.json")
	if _, _, err := plant.Gateway(c, plant.GatewayOptions{ConfigPath: gwPath, Seed: 11}); err != nil {
		t.Fatal(err)
	}
	gcfg, err := gateway.LoadConfig(gwPath)
	if err != nil || gcfg.Heartbeat == nil {
		t.Fatalf("gateway config: %+v %v", gcfg.Heartbeat, err)
	}
	gcfg.CallbackURL = "http://" + s.HTTPAddr
	cIn, toGW := io.Pipe()
	_, cOut := io.Pipe()
	sIn, toSrv := io.Pipe()
	fromSrv, sOut := io.Pipe()
	go func() { _, _ = io.Copy(io.Discard, sIn) }()
	g := &gateway.Gateway{Cfg: gcfg}
	go func() { _ = g.Run(context.Background(), cIn, cOut, toSrv, fromSrv) }()
	defer toGW.Close()
	defer sOut.Close()

	states := func(want int) map[string]store.BeatState {
		t.Helper()
		out := map[string]store.BeatState{}
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			bs, err := c.Heartbeats()
			if err != nil {
				t.Fatal(err)
			}
			out = map[string]store.BeatState{}
			ok := 0
			for _, b := range bs {
				out[b.Channel] = b
				if b.State == store.BeatOK {
					ok++
				}
			}
			if ok >= want || time.Now().After(deadline) {
				return out
			}
		}
	}
	metricsText := func() string {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://"+s.AdminAddr+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+string(cfg.AdminKey))
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return string(b)
	}

	// 1. All three channels verified, with no events, incidents or deliveries.
	bs := states(3)
	for _, ch := range []string{store.BeatHTTP, store.BeatDNS, store.BeatGateway} {
		if b := bs[ch]; b.State != store.BeatOK || b.Count < 1 {
			t.Fatalf("%s not verified: %+v", ch, bs)
		}
	}
	if !strings.HasPrefix(bs[store.BeatGateway].LastSource, "s") {
		t.Errorf("gateway beat source should be its session: %+v", bs[store.BeatGateway])
	}
	if evs, _ := c.EventsFiltered(store.EventFilter{}, 50); len(evs) != 0 {
		t.Fatalf("heartbeats became events: %+v", evs)
	}
	if ins, _ := c.Incidents(10); len(ins) != 0 {
		t.Fatalf("incidents: %+v", ins)
	}
	if ds, _ := c.Deliveries("", 10, false); len(ds) != 0 {
		t.Fatalf("deliveries: %+v", ds)
	}
	m := metricsText()
	for _, want := range []string{`snare_heartbeat_stale{channel="http"} 0`, `snare_heartbeat_stale{channel="dns"} 0`,
		`snare_heartbeat_stale{channel="gateway"} 0`, `snare_heartbeat_age_seconds{channel="dns"}`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	viewer, err := c.IssueKey(store.DefaultTenant, store.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	page := dashboardPage(t, "http://"+s.DashboardAddr, viewer.Key, "/")
	if strings.Count(page, "verified ") < 3 || strings.Contains(page, ">stale") {
		t.Fatal("dashboard does not show three verified channels")
	}
	// The server's token is derived: still one heartbeat token for it after the beats.
	toks, _ := c.Tokens()
	n := 0
	for _, tk := range toks {
		if tk.Kind == store.KindHeartbeat && tk.Label == "server heartbeat" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d server heartbeat tokens", n)
	}

	// 2. Break DNS, let time pass beyond the stale limit, and probe again: only the channels
	// that didn't get through go stale. (The gateway hasn't beaten since start either.)
	_ = s.dnsUDP.Shutdown()
	_ = s.dnsTCP.Shutdown()
	clk.add(4 * time.Hour)
	s.beat()
	bs = states(1)
	if bs[store.BeatHTTP].State != store.BeatOK || bs[store.BeatDNS].State != store.BeatStale || bs[store.BeatGateway].State != store.BeatStale {
		t.Fatalf("after breaking DNS: %+v", bs)
	}
	m = metricsText()
	for _, want := range []string{`snare_heartbeat_stale{channel="http"} 0`, `snare_heartbeat_stale{channel="dns"} 1`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q:\n%s", want, m)
		}
	}
	if page := dashboardPage(t, "http://"+s.DashboardAddr, viewer.Key, "/"); !strings.Contains(page, "stale · 4 h ago") {
		t.Error("dashboard does not show the stale DNS channel")
	}
}
