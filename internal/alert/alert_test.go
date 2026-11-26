package alert

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type memSink struct {
	mu   sync.Mutex
	got  []Alert
	fail int32 // number of initial failures
	n    int32
}

func (m *memSink) Name() string { return "mem" }
func (m *memSink) Send(_ context.Context, a Alert) error {
	if atomic.AddInt32(&m.n, 1) <= m.fail {
		return errors.New("transient")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.got = append(m.got, a)
	return nil
}
func (m *memSink) alerts() []Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Alert(nil), m.got...)
}

func TestDedupWindow(t *testing.T) {
	d := NewDedup(time.Minute)
	t0 := time.Unix(1000, 0)
	if !d.Allow("k", t0) || d.Allow("k", t0.Add(30*time.Second)) {
		t.Fatal("second hit inside window must be suppressed")
	}
	if !d.Allow("k", t0.Add(61*time.Second)) {
		t.Fatal("hit after window must pass")
	}
	if !d.Allow("other", t0) {
		t.Fatal("different key must pass")
	}
}

func TestPipelineStoresEveryEventButDedupsAlerts(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(":memory:")
	defer st.Close()
	_ = st.Tenant(store.DefaultTenant).CreateToken(ctx, store.Token{ID: "tid", Kind: "honey_credential", Label: "repo .env in payments-api"})
	sink := &memSink{}
	disp := NewDispatcher(quiet, DispatcherOpts{}, sink)
	p := &Pipeline{Store: st, Dispatcher: disp, Dedup: NewDedup(time.Minute), Log: quiet}

	for i := 0; i < 5; i++ { // resolver retry storm
		if err := p.Hit(ctx, "tid", "dns", "198.51.100.4", "tid.cb.example. A"); err != nil {
			t.Fatal(err)
		}
	}
	_ = p.Hit(ctx, "tid", "http", "198.51.100.4", "GET /t/x")
	disp.Close()

	evs, _ := st.Tenant(store.DefaultTenant).ListEvents(ctx, "tid", 100)
	if len(evs) != 6 {
		t.Fatalf("stored %d events, want 6", len(evs))
	}
	got := sink.alerts()
	if len(got) != 2 {
		t.Fatalf("sent %d alerts, want 2 (one per channel)", len(got))
	}
	a := got[0]
	if a.ClassUID != 2004 || a.Unmapped.Label != "repo .env in payments-api" || a.SrcEndpoint.IP != "198.51.100.4" {
		t.Fatalf("alert content: %+v", a)
	}
}

func TestUnregisteredTokenStillAlerts(t *testing.T) {
	st, _ := store.Open(":memory:")
	defer st.Close()
	sink := &memSink{}
	disp := NewDispatcher(quiet, DispatcherOpts{}, sink)
	p := &Pipeline{Store: st, Dispatcher: disp, Dedup: NewDedup(time.Minute), Log: quiet}
	_ = p.Hit(context.Background(), "ghost", "http", "192.0.2.1", "")
	disp.Close()
	if got := sink.alerts(); len(got) != 1 || got[0].Unmapped.Kind != "unknown" {
		t.Fatalf("got %+v", got)
	}
}

func TestDispatcherRetries(t *testing.T) {
	sink := &memSink{fail: 2}
	disp := NewDispatcher(quiet, DispatcherOpts{Attempts: 3, Backoff: time.Millisecond}, sink)
	disp.Enqueue(Alert{FindingInfo: FindingInfo{UID: "x"}})
	disp.Close()
	if len(sink.alerts()) != 1 {
		t.Fatal("expected delivery on third attempt")
	}
}

func TestEnqueueNeverBlocks(t *testing.T) {
	block := make(chan struct{})
	slow := sinkFunc(func(context.Context, Alert) error { <-block; return nil })
	disp := NewDispatcher(quiet, DispatcherOpts{QueueSize: 1, Workers: 1}, slow)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			disp.Enqueue(Alert{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Enqueue blocked")
	}
	close(block)
	disp.Close()
}

type sinkFunc func(context.Context, Alert) error

func (sinkFunc) Name() string                              { return "func" }
func (f sinkFunc) Send(ctx context.Context, a Alert) error { return f(ctx, a) }

func TestWebhookSignatureRoundTrip(t *testing.T) {
	secret := []byte("webhook-secret")
	var body []byte
	var ts, sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		ts, sig = r.Header.Get("X-Snare-Timestamp"), r.Header.Get("X-Snare-Signature")
	}))
	defer srv.Close()

	s := WebhookSink{URL: srv.URL, Secret: secret}
	if err := s.Send(context.Background(), Alert{ClassUID: 2004, Message: "hi"}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWebhook(secret, ts, sig, body, time.Now(), 5*time.Minute); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var a Alert
	if json.Unmarshal(body, &a) != nil || a.Message != "hi" {
		t.Fatal("body is not the alert")
	}
	if VerifyWebhook([]byte("wrong"), ts, sig, body, time.Now(), 5*time.Minute) == nil {
		t.Fatal("wrong secret must fail")
	}
	if VerifyWebhook(secret, ts, sig, append(body, ' '), time.Now(), 5*time.Minute) == nil {
		t.Fatal("tampered body must fail")
	}
	if VerifyWebhook(secret, ts, sig, body, time.Now().Add(time.Hour), 5*time.Minute) == nil {
		t.Fatal("replay outside window must fail")
	}
}

func TestWebhookNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	if err := (WebhookSink{URL: srv.URL, Secret: []byte("s")}).Send(context.Background(), Alert{}); err == nil {
		t.Fatal("500 must be an error")
	}
}
