package listener

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/danielguillaumont/snare/internal/token"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type hit struct {
	id, channel, ip, detail string
	ctx                     Context
}

type rec struct {
	mu   sync.Mutex
	hits []hit
}

func (r *rec) Hit(ctx context.Context, tm token.Match, ch, ip, d string) error {
	id := tm.ID
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits = append(r.hits, hit{id, ch, ip, d, ContextFrom(ctx)})
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

func TestHTTPStolenKeyInHeaderIsItsOwnHit(t *testing.T) {
	s := newSigner(t)
	r := &rec{}
	h := &HTTP{Signer: s, Recorder: r, Log: quiet}
	urlTok, urlID, _ := s.Mint()
	keyTok, keyID, _ := s.Mint()
	req := httptest.NewRequest("GET", "/t/"+urlTok+"/v1/payouts", nil)
	req.Header.Set("Authorization", "Bearer "+keyTok)
	h.ServeHTTP(httptest.NewRecorder(), req)
	got := r.all()
	if len(got) != 2 || got[0].id != urlID || got[1].id != keyID || !strings.Contains(got[1].detail, "via=credential-header") {
		t.Fatalf("hits: %+v", got)
	}
	if strings.Contains(got[1].detail, keyTok) {
		t.Fatal("header value must not be stored")
	}
	// Key alone, to any path on the callback host.
	r2 := &rec{}
	h2 := &HTTP{Signer: s, Recorder: r2, Log: quiet}
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Api-Key", keyTok)
	h2.ServeHTTP(httptest.NewRecorder(), req)
	if g := r2.all(); len(g) != 1 || g[0].id != keyID {
		t.Fatalf("header-only hits: %+v", g)
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

func TestHTTPCallbackContextIsAllowlisted(t *testing.T) {
	s := newSigner(t)
	r := &rec{}
	h := &HTTP{Signer: s, Recorder: r, Log: quiet}
	tok, _, _ := s.Mint()
	q := "?layer=egress&tool=send_email&session=s1a2b3&secret=hunter2&tool=dup" +
		"&x=" + strings.Repeat("y", 10)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/"+tok+q, nil))
	bad := "?layer=%3Cscript%3E&tool=" + strings.Repeat("a", 65) + "&session=ok_1.2-3"
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/"+tok+bad, nil))
	got := r.all()
	if len(got) != 2 {
		t.Fatalf("hits: %+v", got)
	}
	if !strings.HasSuffix(got[0].detail, " layer=egress tool=send_email session=s1a2b3") || strings.Contains(got[0].detail, "hunter2") {
		t.Errorf("detail: %q", got[0].detail)
	}
	if !strings.HasSuffix(got[1].detail, " session=ok_1.2-3") || strings.Contains(got[1].detail, "layer=") || strings.Contains(got[1].detail, "tool=") {
		t.Errorf("bad values must be dropped: %q", got[1].detail)
	}
	// The same facts reach the recorder as structured context (M7 §1).
	if !reflect.DeepEqual(got[0].ctx, Context{Via: "egress", Session: "s1a2b3"}) || !reflect.DeepEqual(got[1].ctx, Context{Session: "ok_1.2-3"}) {
		t.Errorf("structured context: %+v / %+v", got[0].ctx, got[1].ctx)
	}
}

// Only the gateway's egress layer is a via; other layer values never promote a touch, and a
// credential header is "use" whatever the query says.
func TestHTTPArrivalContext(t *testing.T) {
	s := newSigner(t)
	r := &rec{}
	h := &HTTP{Signer: s, Recorder: r, Log: quiet}
	urlTok, _, _ := s.Mint()
	keyTok, _, _ := s.Mint()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/"+urlTok+"?layer=use&session=s1", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/"+urlTok+"?layer=tool&contain=killed", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/"+urlTok+"?layer=egress&contain=blocked&session=s3", nil))
	req := httptest.NewRequest("GET", "/v1/"+urlTok+"?layer=egress&session=s2", nil)
	req.Header.Set("X-Api-Key", keyTok)
	h.ServeHTTP(httptest.NewRecorder(), req)
	got := r.all()
	want := []Context{{Session: "s1"}, {}, {Via: "egress", Session: "s3", Containment: "blocked"},
		{Via: "egress", Session: "s2"}, {Via: "use", Session: "s2"}}
	if len(got) != len(want) {
		t.Fatalf("hits: %+v", got)
	}
	for i, w := range want {
		if !reflect.DeepEqual(got[i].ctx, w) {
			t.Errorf("hit %d: context %+v, want %+v", i, got[i].ctx, w)
		}
	}
	if !reflect.DeepEqual(ContextFrom(context.Background()), Context{}) {
		t.Error("no context must read as the zero Context")
	}
}

// The input ledger (M9 §2): each in<k> must have the exact shape or it is dropped with its
// src<k>; good entries keep their order, and nothing else reaches the detail.
func TestHTTPInputsAreValidated(t *testing.T) {
	s := newSigner(t)
	r := &rec{}
	h := &HTTP{Signer: s, Recorder: r, Log: quiet}
	tok, _, _ := s.Mint()
	fp := "3fa1c2d4e5f60718"
	q := "?layer=tool&session=s1" +
		"&in0=read_file~" + fp + "~1240~4&src0=tickets/T-42.md" +
		"&in1=read_file~" + strings.ToUpper(fp) + "~1~1&src1=dropped-with-its-entry" + // hex must be lower case
		"&in2=bad%20tool~" + fp + "~1~1" + // tool charset
		"&in3=search~" + fp + "~12~0~extra" + // too many fields
		"&in4=search~" + fp + "~1234567890~0" + // length over 9 digits
		"&in5=search~" + fp[:15] + "~1~0" + // short fingerprint
		"&in6=search~" + fp + "~7~0&src6=" + strings.Repeat("a", 129) + // source too long: entry kept, source dropped
		"&in7=list~" + fp + "~0~3600&src7=a%20b" + // source charset
		"&in8=extra~" + fp + "~1~1" // only in0..in7
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/"+tok+q, nil))
	got := r.all()
	if len(got) != 1 {
		t.Fatalf("hits: %+v", got)
	}
	want := []Input{
		{Tool: "read_file", Fingerprint: fp, Length: 1240, AgeSeconds: 4, Source: "tickets/T-42.md"},
		{Tool: "search", Fingerprint: fp, Length: 7, AgeSeconds: 0},
		{Tool: "list", Fingerprint: fp, Length: 0, AgeSeconds: 3600},
	}
	if !reflect.DeepEqual(got[0].ctx.Inputs, want) {
		t.Fatalf("inputs: got %+v, want %+v", got[0].ctx.Inputs, want)
	}
	if strings.Contains(got[0].detail, "in0") || strings.Contains(got[0].detail, "T-42") {
		t.Fatalf("ledger leaked into the detail: %q", got[0].detail)
	}
}
