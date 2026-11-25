package server

// End-to-end test for the M1 exit criterion: a planted token fires an alert in < 5 s.
// Everything runs in-process on loopback ports: callback HTTP, DNS, admin API and a
// webhook receiver that verifies Snare's signature like a real customer would.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/alert"
	"github.com/danielguillaumont/snare/internal/store"
)

const exitCriterion = 5 * time.Second

type received struct {
	alert alert.Alert
	at    time.Time
}

func TestEndToEndTokenFiresAlert(t *testing.T) {
	webhookSecret := []byte("0123456789abcdef-webhook")
	var mu sync.Mutex
	var got []received
	arrived := make(chan struct{}, 10)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := alert.VerifyWebhook(webhookSecret, r.Header.Get("X-Snare-Timestamp"), r.Header.Get("X-Snare-Signature"), body, time.Now(), time.Minute); err != nil {
			t.Errorf("webhook signature: %v", err)
			w.WriteHeader(401)
			return
		}
		var a alert.Alert
		if err := json.Unmarshal(body, &a); err != nil {
			t.Errorf("webhook body: %v", err)
		}
		mu.Lock()
		got = append(got, received{a, time.Now()})
		mu.Unlock()
		arrived <- struct{}{}
	}))
	defer hook.Close()

	adminKey := "test-admin-key-0123456789abcdef"
	cfg := Config{
		Key:           bytes.Repeat([]byte{42}, 32),
		AdminKey:      []byte(adminKey),
		HTTPAddr:      "127.0.0.1:0",
		AdminAddr:     "127.0.0.1:0",
		DNSAddr:       "127.0.0.1:0",
		Zone:          "cb.test.",
		AnswerIP:      net.ParseIP("127.0.0.1"),
		PublicURL:     "http://cb.test",
		DBPath:        filepath.Join(t.TempDir(), "snare.db"),
		WebhookURL:    hook.URL,
		WebhookSecret: webhookSecret,
	}
	s, err := Start(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	adminBase := "http://" + s.AdminAddr

	// Admin API rejects missing / wrong keys.
	if code := adminCall(t, "POST", adminBase+"/api/tokens", "wrong", admin.MintRequest{Kind: "decoy_tool", Label: "x"}, nil); code != 401 {
		t.Fatalf("wrong admin key: got %d", code)
	}

	// 1. Plant: mint a honey credential.
	var minted admin.MintResponse
	if code := adminCall(t, "POST", adminBase+"/api/tokens", adminKey, admin.MintRequest{Kind: "honey_credential", Label: "payments-api .env: OPENAI_API_KEY"}, &minted); code != 201 {
		t.Fatalf("mint: %d", code)
	}

	// 2. Touch over HTTP, as a leaked key used against a fake API base URL would.
	start := time.Now()
	resp, err := http.Get("http://" + s.HTTPAddr + "/v1/chat/completions?key=" + minted.Token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	waitFor(t, arrived, start, "http")

	// 3. Touch over DNS, as an agent resolving a canary hostname would.
	start = time.Now()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(minted.Hostname), dns.TypeA)
	if _, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, s.DNSAddr); err != nil {
		t.Fatal(err)
	}
	waitFor(t, arrived, start, "dns")

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("alerts: %d", len(got))
	}
	channels := map[string]bool{}
	for _, r := range got {
		a := r.alert
		channels[a.Unmapped.Channel] = true
		if a.ClassUID != 2004 || a.Unmapped.TokenID != minted.ID || a.Unmapped.Label != "payments-api .env: OPENAI_API_KEY" || a.SrcEndpoint.IP != "127.0.0.1" {
			t.Fatalf("alert content: %+v", a)
		}
	}
	if !channels["http"] || !channels["dns"] {
		t.Fatalf("channels: %v", channels)
	}

	// 4. Events are queryable through the admin API.
	var evs []store.Event
	if code := adminCall(t, "GET", adminBase+"/api/events?token="+minted.ID, adminKey, nil, &evs); code != 200 || len(evs) != 2 {
		t.Fatalf("events: %d %+v", code, evs)
	}
}

func waitFor(t *testing.T, arrived <-chan struct{}, start time.Time, what string) {
	t.Helper()
	select {
	case <-arrived:
		t.Logf("%s: touch to verified webhook in %v (limit %v)", what, time.Since(start).Round(time.Millisecond), exitCriterion)
	case <-time.After(exitCriterion):
		t.Fatalf("%s alert did not arrive within %v", what, exitCriterion)
	}
}

func adminCall(t *testing.T, method, url, key string, body, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode
}
