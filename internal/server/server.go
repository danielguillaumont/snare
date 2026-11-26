// Package server wires tokens, store, alert pipeline and listeners into one process.
package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/alert"
	"github.com/danielguillaumont/snare/internal/dashboard"
	"github.com/danielguillaumont/snare/internal/egress"
	"github.com/danielguillaumont/snare/internal/listener"
	"github.com/danielguillaumont/snare/internal/metrics"
	"github.com/danielguillaumont/snare/internal/seal"
	"github.com/danielguillaumont/snare/internal/store"
	"github.com/danielguillaumont/snare/internal/token"
)

type Config struct {
	Key           []byte   // token HMAC key: signs new tokens
	PreviousKeys  [][]byte // retired token keys that still verify (SNARE_KEY_PREVIOUS)
	AdminKey      []byte
	HTTPAddr      string // public callback listener, e.g. ":8080"
	DNSAddr       string // public DNS listener (UDP+TCP), e.g. ":53"; empty disables DNS
	AdminAddr     string // admin API, e.g. "127.0.0.1:8081"
	Zone          string
	AnswerIP      net.IP
	PublicURL     string
	URLPath       string // path before the token in minted URLs (SNARE_URL_PATH, default /v1/)
	DBPath        string
	WebhookURL    string
	WebhookSecret []byte
	TrustProxy    bool
	DedupWindow   time.Duration
	// Token format for newly minted tokens (docs/M3a-fix-antifingerprint.md). Empty prefix and
	// b32 by default. Old tokens verify whatever this is set to.
	TokenPrefix   string
	TokenEncoding token.Encoding

	// M4 (docs/M4-saas.md). SealKey enables per-tenant sinks; DashboardAddr enables the
	// dashboard. SinkAllowPrivate relaxes the SSRF guard (tests, single-team installs).
	SealKey          []byte
	SinkAllowPrivate bool
	DashboardAddr    string
	DashboardDev     bool // cookies without Secure, for http://localhost
}

// FromEnv reads the SNARE_* variables documented in docs/M1-callback.md.
func FromEnv() (Config, error) {
	get := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	key, err := hex.DecodeString(os.Getenv("SNARE_KEY"))
	if err != nil || len(key) < token.MinKeyBytes {
		return Config{}, errors.New("SNARE_KEY must be hex, at least 32 bytes (run: snare keygen)")
	}
	var previous [][]byte
	if v := strings.TrimSpace(os.Getenv("SNARE_KEY_PREVIOUS")); v != "" {
		for _, part := range strings.Split(v, ",") {
			k, err := hex.DecodeString(strings.TrimSpace(part))
			if err != nil {
				return Config{}, errors.New("SNARE_KEY_PREVIOUS must be comma-separated hex keys")
			}
			previous = append(previous, k)
		}
		base, _ := token.NewSigner(key)
		if _, err := base.WithPrevious(previous...); err != nil {
			return Config{}, fmt.Errorf("SNARE_KEY_PREVIOUS: %w", err)
		}
	}
	adminKey := os.Getenv("SNARE_ADMIN_KEY")
	if len(adminKey) < 24 {
		return Config{}, errors.New("SNARE_ADMIN_KEY must be at least 24 characters (run: snare keygen)")
	}
	c := Config{
		Key:           key,
		PreviousKeys:  previous,
		AdminKey:      []byte(adminKey),
		HTTPAddr:      get("SNARE_HTTP_ADDR", ":8080"),
		DNSAddr:       os.Getenv("SNARE_DNS_ADDR"),
		AdminAddr:     get("SNARE_ADMIN_ADDR", "127.0.0.1:8081"),
		Zone:          os.Getenv("SNARE_ZONE"),
		AnswerIP:      net.ParseIP(get("SNARE_ANSWER_IP", "127.0.0.1")),
		PublicURL:     os.Getenv("SNARE_PUBLIC_URL"),
		URLPath:       os.Getenv("SNARE_URL_PATH"),
		DBPath:        get("SNARE_DB", "snare.db"),
		WebhookURL:    os.Getenv("SNARE_WEBHOOK_URL"),
		WebhookSecret: []byte(os.Getenv("SNARE_WEBHOOK_SECRET")),
		TrustProxy:    os.Getenv("SNARE_TRUST_PROXY") == "1",
		TokenPrefix:   os.Getenv("SNARE_TOKEN_PREFIX"),
		TokenEncoding: token.Encoding(get("SNARE_TOKEN_ENCODING", string(token.B32))),
	}
	if v := os.Getenv("SNARE_SEAL_KEY"); v != "" {
		k, err := hex.DecodeString(v)
		if err != nil || len(k) != 32 {
			return Config{}, errors.New("SNARE_SEAL_KEY must be 32 bytes of hex (run: snare keygen)")
		}
		c.SealKey = k
	}
	c.SinkAllowPrivate = os.Getenv("SNARE_SINK_ALLOW_PRIVATE") == "1"
	c.DashboardAddr = os.Getenv("SNARE_DASHBOARD_ADDR")
	c.DashboardDev = os.Getenv("SNARE_DASHBOARD_DEV") == "1"
	if c.DashboardAddr != "" && c.DashboardDev && !strings.HasPrefix(c.DashboardAddr, "127.0.0.1:") && !strings.HasPrefix(c.DashboardAddr, "localhost:") {
		return Config{}, errors.New("SNARE_DASHBOARD_DEV=1 (cookies without Secure) is only allowed on a loopback address")
	}
	if c.DNSAddr != "" && c.Zone == "" {
		return Config{}, errors.New("SNARE_ZONE is required when SNARE_DNS_ADDR is set")
	}
	if c.WebhookURL != "" && len(c.WebhookSecret) < 16 {
		return Config{}, errors.New("SNARE_WEBHOOK_SECRET must be at least 16 characters when a webhook is set")
	}
	return c, nil
}

type Server struct {
	cfg    Config
	log    *slog.Logger
	st     *store.Store
	outbox *alert.Outbox

	httpSrv, adminSrv, dashSrv *http.Server
	dnsUDP, dnsTCP             *dns.Server

	// Bound addresses, useful when configured with port 0.
	HTTPAddr, AdminAddr, DNSAddr, DashboardAddr string
}

// Start opens the store and starts all listeners. It returns once they are accepting.
func Start(cfg Config, log *slog.Logger) (*Server, error) {
	base, err := token.NewSigner(cfg.Key)
	if err != nil {
		return nil, err
	}
	signer, err := base.WithFormat(cfg.TokenPrefix, cfg.TokenEncoding)
	if err != nil {
		return nil, err
	}
	if signer, err = signer.WithPrevious(cfg.PreviousKeys...); err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	// Operator sinks. Refs are stable names: rows queued under them survive a restart.
	ops := []alert.Target{{Ref: "op:log", Sink: alert.LogSink{Log: log}}}
	if cfg.WebhookURL != "" {
		ops = append(ops, alert.Target{Ref: "op:webhook", Sink: alert.WebhookSink{URL: cfg.WebhookURL, Secret: cfg.WebhookSecret}})
	}
	policy := egress.Policy{AllowPrivate: cfg.SinkAllowPrivate}
	reg := metrics.New()
	am := alert.NewMetrics(reg, st)
	ob := &alert.Outbox{Store: st, Operator: ops, Log: log, Metrics: am}
	var sealer *seal.Sealer
	var resolver *alert.TenantResolver
	if cfg.SealKey != nil {
		if sealer, err = seal.New(cfg.SealKey); err != nil {
			st.Close()
			return nil, err
		}
		// Token labels say where tripwires are planted: sealed at rest (docs/M4d-operations.md §2).
		n, err := st.SealLabels(context.Background(), sealer)
		if err != nil {
			st.Close()
			return nil, fmt.Errorf("sealing token labels: %w", err)
		}
		if n > 0 {
			log.Info("sealed plaintext token labels", "tokens", n)
		}
		resolver = &alert.TenantResolver{Store: st, Sealer: sealer, Client: policy.Client(10 * time.Second), Log: log}
		ob.Resolver = resolver // only when non-nil: a nil *TenantResolver in the interface is not nil
	}
	ob.Start()
	window := cfg.DedupWindow
	if window == 0 {
		window = time.Minute
	}
	pipe := &alert.Pipeline{Store: st, Outbox: ob, Dedup: alert.NewDedup(window), Log: log, Metrics: am}
	s := &Server{cfg: cfg, log: log, st: st, outbox: ob}

	cleanup := func(e error) (*Server, error) { s.Shutdown(context.Background()); return nil, e }

	httpLn, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return cleanup(fmt.Errorf("http listen: %w", err))
	}
	s.HTTPAddr = httpLn.Addr().String()
	s.httpSrv = &http.Server{
		Handler:           &listener.HTTP{Signer: signer, Recorder: pipe, Log: log, TrustProxy: cfg.TrustProxy},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	go s.serveHTTP(s.httpSrv, httpLn, "callback")

	adminLn, err := net.Listen("tcp", cfg.AdminAddr)
	if err != nil {
		return cleanup(fmt.Errorf("admin listen: %w", err))
	}
	s.AdminAddr = adminLn.Addr().String()
	api := &admin.API{Key: cfg.AdminKey, Signer: signer, Store: st, PublicURL: cfg.PublicURL, URLPath: cfg.URLPath, Zone: cfg.Zone, Log: log,
		Sealer: sealer, Egress: policy, Resolver: resolver, Metrics: reg, Wake: ob.Notify}
	s.adminSrv = &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go s.serveHTTP(s.adminSrv, adminLn, "admin")

	if cfg.DashboardAddr != "" {
		d := &dashboard.Dashboard{Store: st, SessionKey: deriveKey(cfg.Key, "snare-dashboard-session-key-v1"), Dev: cfg.DashboardDev, TrustProxy: cfg.TrustProxy, Log: log}
		h, err := d.Handler()
		if err != nil {
			return cleanup(err)
		}
		dashLn, err := net.Listen("tcp", cfg.DashboardAddr)
		if err != nil {
			return cleanup(fmt.Errorf("dashboard listen: %w", err))
		}
		s.DashboardAddr = dashLn.Addr().String()
		s.dashSrv = &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
			WriteTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
		go s.serveHTTP(s.dashSrv, dashLn, "dashboard")
	}

	if cfg.DNSAddr != "" {
		h := &listener.DNS{Zone: cfg.Zone, AnswerIP: cfg.AnswerIP, Signer: signer, Recorder: pipe, Log: log}
		pc, tl, err := listenDNS(cfg.DNSAddr)
		if err != nil {
			return cleanup(err)
		}
		s.DNSAddr = pc.LocalAddr().String()
		started := make(chan struct{}, 2)
		notify := func() { started <- struct{}{} }
		s.dnsUDP = &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: notify}
		s.dnsTCP = &dns.Server{Listener: tl, Handler: h, NotifyStartedFunc: notify}
		go func() { _ = s.dnsUDP.ActivateAndServe() }()
		go func() { _ = s.dnsTCP.ActivateAndServe() }()
		<-started
		<-started
	}

	log.Info("snare started", "callback", s.HTTPAddr, "admin", s.AdminAddr, "dns", s.DNSAddr, "dashboard", s.DashboardAddr,
		"tenant_sinks", sealer != nil, "zone", cfg.Zone, "webhook", cfg.WebhookURL != "")
	return s, nil
}

// listenDNS binds UDP and TCP on the same address. With port 0 the OS picks the UDP port, and
// the same TCP port can be unavailable (Windows reserves port ranges), so retry a few times.
func listenDNS(addr string) (net.PacketConn, net.Listener, error) {
	_, port, _ := net.SplitHostPort(addr)
	if port != "0" {
		return bindPair(addr, false)
	}
	// Port 0 (tests): DNS needs the same port on UDP and TCP, and Windows reserves blocks of
	// ephemeral ports per protocol (Hyper-V/WSL), so a port free on one may be refused on the
	// other. Alternate which protocol picks the port, then fall back to explicit ports below
	// the ephemeral range.
	host, _, _ := net.SplitHostPort(addr)
	var lastErr error
	for i := 0; i < 40; i++ {
		a, udpFirst := addr, i%2 == 1
		if i >= 10 {
			a = net.JoinHostPort(host, strconv.Itoa(20000+mrand.IntN(20000)))
		}
		pc, tl, err := bindPair(a, udpFirst)
		if err == nil {
			return pc, tl, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

// bindPair binds UDP and TCP on one port; the first protocol picks it when the port is 0.
func bindPair(addr string, udpFirst bool) (net.PacketConn, net.Listener, error) {
	if udpFirst {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("dns udp listen: %w", err)
		}
		tl, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			pc.Close()
			return nil, nil, fmt.Errorf("dns tcp listen: %w", err)
		}
		return pc, tl, nil
	}
	tl, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dns tcp listen: %w", err)
	}
	pc, err := net.ListenPacket("udp", tl.Addr().String())
	if err != nil {
		tl.Close()
		return nil, nil, fmt.Errorf("dns udp listen: %w", err)
	}
	return pc, tl, nil
}

func (s *Server) serveHTTP(srv *http.Server, ln net.Listener, name string) {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Error("listener stopped", "listener", name, "err", err)
	}
}

// Shutdown stops listeners and the delivery loop, then closes the store.
func (s *Server) Shutdown(ctx context.Context) {
	for _, h := range []*http.Server{s.httpSrv, s.adminSrv, s.dashSrv} {
		if h != nil {
			_ = h.Shutdown(ctx)
		}
	}
	for _, d := range []*dns.Server{s.dnsUDP, s.dnsTCP} {
		if d != nil {
			_ = d.Shutdown()
		}
	}
	if s.outbox != nil {
		s.outbox.Close() // in-flight attempts finish; pending rows wait for the next start
	}
	if s.st != nil {
		_ = s.st.Close()
	}
}

// deriveKey gives each use of the master key its own subkey, so the dashboard's session MAC can
// never be confused with a token MAC even though both come from SNARE_KEY.
func deriveKey(master []byte, label string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(label))
	return m.Sum(nil)
}
