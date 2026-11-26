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
