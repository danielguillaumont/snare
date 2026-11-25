// Package server wires tokens, store, alert pipeline and listeners into one process.
package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/alert"
	"github.com/danielguillaumont/snare/internal/listener"
	"github.com/danielguillaumont/snare/internal/store"
	"github.com/danielguillaumont/snare/internal/token"
)

type Config struct {
	Key           []byte // token HMAC key
	AdminKey      []byte
	HTTPAddr      string // public callback listener, e.g. ":8080"
	DNSAddr       string // public DNS listener (UDP+TCP), e.g. ":53"; empty disables DNS
	AdminAddr     string // admin API, e.g. "127.0.0.1:8081"
	Zone          string
	AnswerIP      net.IP
	PublicURL     string
	DBPath        string
	WebhookURL    string
	WebhookSecret []byte
	TrustProxy    bool
	DedupWindow   time.Duration
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
	adminKey := os.Getenv("SNARE_ADMIN_KEY")
	if len(adminKey) < 24 {
		return Config{}, errors.New("SNARE_ADMIN_KEY must be at least 24 characters (run: snare keygen)")
	}
	c := Config{
		Key:           key,
		AdminKey:      []byte(adminKey),
		HTTPAddr:      get("SNARE_HTTP_ADDR", ":8080"),
		DNSAddr:       os.Getenv("SNARE_DNS_ADDR"),
		AdminAddr:     get("SNARE_ADMIN_ADDR", "127.0.0.1:8081"),
		Zone:          os.Getenv("SNARE_ZONE"),
		AnswerIP:      net.ParseIP(get("SNARE_ANSWER_IP", "127.0.0.1")),
		PublicURL:     os.Getenv("SNARE_PUBLIC_URL"),
		DBPath:        get("SNARE_DB", "snare.db"),
		WebhookURL:    os.Getenv("SNARE_WEBHOOK_URL"),
		WebhookSecret: []byte(os.Getenv("SNARE_WEBHOOK_SECRET")),
		TrustProxy:    os.Getenv("SNARE_TRUST_PROXY") == "1",
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
	cfg  Config
	log  *slog.Logger
	st   *store.Store
	disp *alert.Dispatcher

	httpSrv, adminSrv *http.Server
	dnsUDP, dnsTCP    *dns.Server

	// Bound addresses, useful when configured with port 0.
	HTTPAddr, AdminAddr, DNSAddr string
}

// Start opens the store and starts all listeners. It returns once they are accepting.
func Start(cfg Config, log *slog.Logger) (*Server, error) {
	signer, err := token.NewSigner(cfg.Key)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	sinks := []alert.Sink{alert.LogSink{Log: log}}
	if cfg.WebhookURL != "" {
		sinks = append(sinks, alert.WebhookSink{URL: cfg.WebhookURL, Secret: cfg.WebhookSecret})
	}
	disp := alert.NewDispatcher(log, alert.DispatcherOpts{}, sinks...)
	window := cfg.DedupWindow
	if window == 0 {
		window = time.Minute
	}
	pipe := &alert.Pipeline{Store: st, Dispatcher: disp, Dedup: alert.NewDedup(window), Log: log}
	s := &Server{cfg: cfg, log: log, st: st, disp: disp}

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
	api := &admin.API{Key: cfg.AdminKey, Signer: signer, Store: st, PublicURL: cfg.PublicURL, Zone: cfg.Zone, Log: log}
	s.adminSrv = &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go s.serveHTTP(s.adminSrv, adminLn, "admin")

	if cfg.DNSAddr != "" {
		h := &listener.DNS{Zone: cfg.Zone, AnswerIP: cfg.AnswerIP, Signer: signer, Recorder: pipe, Log: log}
		pc, err := net.ListenPacket("udp", cfg.DNSAddr)
		if err != nil {
			return cleanup(fmt.Errorf("dns udp listen: %w", err))
		}
		s.DNSAddr = pc.LocalAddr().String()
		tl, err := net.Listen("tcp", s.DNSAddr)
		if err != nil {
			pc.Close()
			return cleanup(fmt.Errorf("dns tcp listen: %w", err))
		}
		started := make(chan struct{}, 2)
		notify := func() { started <- struct{}{} }
		s.dnsUDP = &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: notify}
		s.dnsTCP = &dns.Server{Listener: tl, Handler: h, NotifyStartedFunc: notify}
		go func() { _ = s.dnsUDP.ActivateAndServe() }()
		go func() { _ = s.dnsTCP.ActivateAndServe() }()
		<-started
		<-started
	}

	log.Info("snare started", "callback", s.HTTPAddr, "admin", s.AdminAddr, "dns", s.DNSAddr, "zone", cfg.Zone, "webhook", cfg.WebhookURL != "")
	return s, nil
}

func (s *Server) serveHTTP(srv *http.Server, ln net.Listener, name string) {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Error("listener stopped", "listener", name, "err", err)
	}
}

// Shutdown stops listeners, drains queued alerts and closes the store.
func (s *Server) Shutdown(ctx context.Context) {
	for _, h := range []*http.Server{s.httpSrv, s.adminSrv} {
		if h != nil {
			_ = h.Shutdown(ctx)
		}
	}
	for _, d := range []*dns.Server{s.dnsUDP, s.dnsTCP} {
		if d != nil {
			_ = d.Shutdown()
		}
	}
	if s.disp != nil {
		s.disp.Close()
	}
	if s.st != nil {
		_ = s.st.Close()
	}
}
