package listener

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/danielguillaumont/snare/internal/token"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type hit struct{ id, channel, ip, detail string }

type rec struct {
	mu   sync.Mutex
	hits []hit
}

func (r *rec) Hit(_ context.Context, id, ch, ip, d string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits = append(r.hits, hit{id, ch, ip, d})
	return nil
}
func (r *rec) all() []hit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hit(nil), r.hits...)
}

func newSigner(t *testing.T) *token.Signer {
	s, err := token.NewSigner(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHTTPRecordsValidTokenOnly(t *testing.T) {
	s := newSigner(t)
	r := &rec{}
	h := &HTTP{Signer: s, Recorder: r, Log: quiet}
	tok, id, _ := s.Mint()
	forged := "snr" + strings.Repeat("a", 32)

	for _, path := range []string{"/t/" + tok, "/v1/models?key=" + tok, "/t/" + forged, "/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader("stolen=data")))
		if w.Code != 200 || w.Body.String() != `{"status":"ok"}` {
			t.Fatalf("%s: bland response expected, got %d %q", path, w.Code, w.Body.String())
		}
	}
	got := r.all()
	if len(got) != 2 || got[0].id != id || got[0].channel != "http" || strings.Contains(got[0].detail, "stolen") {
		t.Fatalf("hits: %+v", got)
	}
}

func TestHTTPTokenInHost(t *testing.T) {
	s := newSigner(t)
	r := &rec{}
	h := &HTTP{Signer: s, Recorder: r, Log: quiet}
	tok, id, _ := s.Mint()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = tok + ".cb.example.com"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got := r.all(); len(got) != 1 || got[0].id != id {
		t.Fatalf("hits: %+v", got)
	}
}

func TestHTTPRateLimitPerIP(t *testing.T) {
	s := newSigner(t)
	h := &HTTP{Signer: s, Recorder: &rec{}, Log: quiet, PerIPRate: 1, PerIPBurst: 3}
	codes := map[int]int{}
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113.9:5555"
		h.ServeHTTP(w, req)
		codes[w.Code]++
	}
	if codes[200] != 3 || codes[429] != 7 {
		t.Fatalf("codes: %v", codes)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:5555"
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal("other IP must not be limited")
	}
}

func TestHTTPTrustProxyUsesLastHop(t *testing.T) {
	h := &HTTP{TrustProxy: true}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.20")
	if ip := h.clientIP(req); ip != "198.51.100.20" {
		t.Fatalf("got %s", ip)
	}
	h.TrustProxy = false
	req.RemoteAddr = "192.0.2.5:1"
	if ip := h.clientIP(req); ip != "192.0.2.5" {
		t.Fatalf("got %s", ip)
	}
}

func startDNS(t *testing.T, d *DNS) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: d}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func query(t *testing.T, addr, name string, qt uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	c := &dns.Client{Timeout: 2 * time.Second}
	var resp *dns.Msg
	var err error
	for i := 0; i < 20; i++ { // server goroutine may not be serving yet
		if resp, _, err = c.Exchange(m, addr); err == nil {
			return resp
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

func TestDNSRecordsTokenAndAnswersBlandly(t *testing.T) {
	s := newSigner(t)
	r := &rec{}
	addr := startDNS(t, &DNS{Zone: "cb.example.com", AnswerIP: net.ParseIP("192.0.2.53"), Signer: s, Recorder: r, Log: quiet})
	tok, id, _ := s.Mint()

	resp := query(t, addr, "x."+strings.ToUpper(tok)+".cb.example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || len(resp.Answer) != 1 {
		t.Fatalf("resp: %v", resp)
	}
	if a := resp.Answer[0].(*dns.A); !a.A.Equal(net.ParseIP("192.0.2.53")) || a.Hdr.Ttl != 0 {
		t.Fatalf("answer: %v", a)
	}
	query(t, addr, "www.cb.example.com", dns.TypeA)    // in zone, no token
	query(t, addr, tok+".cb.example.com", dns.TypeTXT) // token, other type

	got := r.all()
	if len(got) != 2 || got[0].id != id || got[0].channel != "dns" || got[1].id != id {
		t.Fatalf("hits: %+v", got)
	}
}

func TestDNSRefusesOutOfZone(t *testing.T) {
	s := newSigner(t)
	r := &rec{}
	addr := startDNS(t, &DNS{Zone: "cb.example.com.", AnswerIP: net.ParseIP("192.0.2.53"), Signer: s, Recorder: r, Log: quiet})
	tok, _, _ := s.Mint()
	resp := query(t, addr, tok+".evil.example.net", dns.TypeA)
	if resp.Rcode != dns.RcodeRefused || len(r.all()) != 0 {
		t.Fatalf("out-of-zone must be refused and not recorded: %v", resp)
	}
}

var _ http.Handler = (*HTTP)(nil)
