package listener

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"

	"github.com/danielguillaumont/snare/internal/token"
)

// validIDs returns the ids of every substring of text that verifies as a whole token (any
// supported length), found independently of the scanner under test.
func validIDs(s *token.Signer, text string) map[string]bool {
	out := map[string]bool{}
	low := strings.ToLower(text)
	for _, n := range []int{32, 35, 40} {
		for i := 0; i+n <= len(low); i++ {
			if id, err := s.Verify(low[i : i+n]); err == nil {
				out[id] = true
			}
		}
	}
	return out
}

func fuzzSigner(f *testing.F) (*token.Signer, string, string) {
	s, err := token.NewSigner(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	tok, id, _ := s.Mint()
	return s, tok, id
}

// Every HTTP request gets the same bland reply, whatever it contains, and a hit is recorded
// only for the one token that exists.
func FuzzHTTP(f *testing.F) {
	s, tok, _ := fuzzSigner(f)
	for _, seed := range [][5]string{
		{"cb.example", "/v1/" + tok, "", "", "curl/8"},
		{tok + ".cb.example", "/", "a=b", "", ""},
		{"cb.example", "/", "key=" + tok, "Bearer " + tok, "python-httpx/0.28"},
		{"", "/" + strings.Repeat("%", 100), "%zz", "Basic \x00", strings.Repeat("A", 4000)},
		{"[::1]:80", "/../../etc/passwd", "", "", ""},
	} {
		f.Add(seed[0], seed[1], seed[2], seed[3], seed[4])
	}
	f.Fuzz(func(t *testing.T, host, path, query, auth, ua string) {
		r := &rec{}
		h := &HTTP{Signer: s, Recorder: r, Log: quiet, PerIPRate: rate.Inf, PerIPBurst: 1}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		req.URL = &url.URL{Path: path, RawQuery: query}
		req.Header.Set("Authorization", auth)
		req.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK || w.Body.String() != `{"status":"ok"}` {
			t.Fatalf("reply %d %q: a toucher must learn nothing", w.Code, w.Body.String())
		}
		// Seeds are minted in the coordinating process and fuzz workers mint their own, so
		// "equals the planted id" is not an invariant. This is: every recorded id comes from a
		// token that really verifies somewhere in what the client sent.
		valid := validIDs(s, host+" "+path+" "+query+" "+auth)
		for _, x := range r.all() {
			if !valid[x.id] {
				t.Fatalf("hit for id %q, which no token in the request carries", x.id)
			}
		}
		if len(r.all()) > 2 {
			t.Fatalf("%d hits from one request; at most URL + credential header", len(r.all()))
		}
	})
}

type fakeDNSWriter struct {
	msgs []*dns.Msg
}

func (w *fakeDNSWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *fakeDNSWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5353}
}
func (w *fakeDNSWriter) WriteMsg(m *dns.Msg) error {
	w.msgs = append(w.msgs, m)
	return nil
}
func (w *fakeDNSWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *fakeDNSWriter) Close() error                { return nil }
func (w *fakeDNSWriter) TsigStatus() error           { return nil }
func (w *fakeDNSWriter) TsigTimersOnly(bool)         {}
func (w *fakeDNSWriter) Hijack()                     {}

// Arbitrary query names and types: always exactly one reply, never a hit outside the zone,
// and never a hit for a token that wasn't minted.
func FuzzDNS(f *testing.F) {
	s, tok, _ := fuzzSigner(f)
	for _, seed := range []struct {
		name  string
		qtype uint16
	}{
		{tok + ".cb.example.", dns.TypeA},
		{"x." + tok + ".cb.example.", dns.TypeAAAA},
		{tok + ".other.example.", dns.TypeA},
		{"cb.example.", dns.TypeSOA},
		{".", dns.TypeANY},
		{strings.Repeat("a.", 120), dns.TypeTXT},
		{"\x00\xff.cb.example.", 65535},
	} {
		f.Add(seed.name, seed.qtype)
	}
	f.Fuzz(func(t *testing.T, name string, qtype uint16) {
		r := &rec{}
		d := &DNS{Zone: "cb.example.", AnswerIP: net.IPv4(198, 51, 100, 7), Signer: s, Recorder: r, Log: quiet}
		req := new(dns.Msg)
		req.Question = []dns.Question{{Name: name, Qtype: qtype, Qclass: dns.ClassINET}}
		w := &fakeDNSWriter{}
		d.ServeDNS(w, req)
		if len(w.msgs) != 1 {
			t.Fatalf("%d replies", len(w.msgs))
		}
		hits := r.all()
		if len(hits) > 1 {
			t.Fatalf("%d hits for one query", len(hits))
		}
		if len(hits) == 1 {
			if !validIDs(s, name)[hits[0].id] {
				t.Fatalf("hit for id %q, which no token in the query name carries", hits[0].id)
			}
			if !dns.IsSubDomain("cb.example.", strings.ToLower(name)) {
				t.Fatalf("hit for %q, outside the zone", name)
			}
		}
	})
}
