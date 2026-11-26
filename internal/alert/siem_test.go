package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/egress"
	"github.com/danielguillaumont/snare/internal/seal"
	"github.com/danielguillaumont/snare/internal/store"
)

type captured struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func (c *captured) handler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.reqs = append(c.reqs, r)
		c.body = append(c.body, b)
		c.mu.Unlock()
		w.WriteHeader(status)
	}
}

func TestSplunkHECWireFormat(t *testing.T) {
	var c captured
	ts := httptest.NewServer(c.handler(200))
	defer ts.Close()
	a := sampleAlert()
	if err := (SplunkHECSink{URL: ts.URL + "/", Token: "hec-tok", Index: "security"}).Send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	r := c.reqs[0]
	if r.URL.Path != "/services/collector/event" || r.Header.Get("Authorization") != "Splunk hec-tok" {
		t.Fatalf("path %s auth %q", r.URL.Path, r.Header.Get("Authorization"))
	}
	var ev struct {
		Time       float64 `json:"time"`
		SourceType string  `json:"sourcetype"`
		Index      string  `json:"index"`
		Event      Alert   `json:"event"`
	}
	_ = json.Unmarshal(c.body[0], &ev)
	if ev.Time != float64(a.Time)/1000 || ev.SourceType != "snare:ocsf:detection_finding" || ev.Index != "security" ||
		ev.Event.FindingInfo.UID != a.FindingInfo.UID {
		t.Fatalf("event %+v", ev)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"text":"Invalid token","code":4}`))
	}))
	defer bad.Close()
	err := (SplunkHECSink{URL: bad.URL, Token: "x"}).Send(context.Background(), a)
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "hec-tok") {
		t.Fatalf("error %v", err)
	}
}

func TestElasticWireFormatIsIdempotent(t *testing.T) {
	var c captured
	ts := httptest.NewServer(c.handler(201))
	defer ts.Close()
	a := sampleAlert()
	s := ElasticSink{URL: ts.URL, APIKey: "aWQ6a2V5"}
	for i := 0; i < 2; i++ { // a retry
		if err := s.Send(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	r := c.reqs[0]
	if r.Method != http.MethodPut || r.URL.Path != "/snare-alerts/_doc/"+a.FindingInfo.UID ||
		r.Header.Get("Authorization") != "ApiKey aWQ6a2V5" {
		t.Fatalf("%s %s %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
	}
	if c.reqs[1].URL.Path != r.URL.Path {
		t.Fatal("retry used a different document id")
	}
	var doc map[string]any
	_ = json.Unmarshal(c.body[0], &doc)
	if doc["@timestamp"] != "2025-11-24T16:00:00Z" || doc["class_uid"] != float64(2004) {
		t.Fatalf("doc %v", doc)
	}
}

func TestSentinelTokenFlowAndCaching(t *testing.T) {
	var tokenCalls, ingestCalls atomic.Int32
	var lastForm url.Values
	var c captured
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenant-guid/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		n := tokenCalls.Add(1)
		_ = r.ParseForm()
		lastForm = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "aad-" + string(rune('0'+n)), "expires_in": 3600})
	})
	mux.HandleFunc("POST /dataCollectionRules/dcr-123/streams/Custom-SnareAlerts_CL", func(w http.ResponseWriter, r *http.Request) {
		ingestCalls.Add(1)
		if r.URL.Query().Get("api-version") != "2023-01-01" {
			t.Errorf("api-version %q", r.URL.RawQuery)
		}
		if ingestCalls.Load() == 2 { // simulate a revoked token once
			w.WriteHeader(401)
			return
		}
		c.handler(204)(w, r)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	s := NewSentinelSink(SentinelSink{Endpoint: ts.URL, RuleID: "dcr-123", Stream: "Custom-SnareAlerts_CL",
		TenantID: "tenant-guid", ClientID: "app", ClientSecret: "shh", Authority: ts.URL})
	ctx := context.Background()
	a := sampleAlert()

	if err := s.Send(ctx, a); err != nil {
		t.Fatal(err)
	}
	if lastForm.Get("grant_type") != "client_credentials" || lastForm.Get("scope") != "https://monitor.azure.com//.default" ||
		lastForm.Get("client_id") != "app" || lastForm.Get("client_secret") != "shh" {
		t.Fatalf("token form %v", lastForm)
	}
	if err := s.Send(ctx, a); err == nil { // the 401
		t.Fatal("401 must be an error")
	}
	if err := s.Send(ctx, a); err != nil { // retry after 401 fetches a new token
		t.Fatal(err)
	}
	if tokenCalls.Load() != 2 {
		t.Fatalf("token calls %d, want 2 (cached once, refreshed after 401)", tokenCalls.Load())
	}
	if got := c.reqs[len(c.reqs)-1].Header.Get("Authorization"); got != "Bearer aad-2" {
		t.Fatalf("auth %q", got)
	}
	var recs []SentinelRecord
	if err := json.Unmarshal(c.body[0], &recs); err != nil || len(recs) != 1 {
		t.Fatalf("body must be a JSON array: %v", err)
	}
	if recs[0].TimeGenerated == "" || recs[0].FindingUID != a.FindingInfo.UID || recs[0].OCSF.ClassUID != 2004 {
		t.Fatalf("record %+v", recs[0])
	}
}

func TestSinkConfigValidateAndPublic(t *testing.T) {
	ctx := context.Background()
	prod := egress.Policy{}
	for _, c := range []SinkConfig{
		{Type: "splunk_hec", URL: "https://8.8.8.8"},                   // no token
		{Type: "webhook", URL: "https://8.8.8.8", Secret: "short"},     // short secret
		{Type: "elastic", URL: "https://169.254.169.254", APIKey: "k"}, // metadata IP
		{Type: "splunk_hec", URL: "http://8.8.8.8", Token: "t"},        // http
		{Type: "sentinel", URL: "https://8.8.8.8", RuleID: "d", Stream: "s", AzureTenant: "t", ClientID: "c", ClientSecret: "s",
			Authority: "https://127.0.0.1"}, // authority must pass too
		{Type: "pagerduty", URL: "https://8.8.8.8"},
	} {
		if err := c.Validate(ctx, prod); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	ok := SinkConfig{Type: "splunk_hec", URL: "https://8.8.8.8", Token: "hec-secret", Index: "sec"}
	if err := ok.Validate(ctx, prod); err != nil {
		t.Fatal(err)
	}
	pub, _ := json.Marshal(SinkConfig{Type: "sentinel", URL: "u", ClientSecret: "cs", Token: "t", APIKey: "k", Secret: "s"}.Public())
	for _, secret := range []string{`"cs"`, `"t"`, `"k"`, `"s"`} {
		if bytes.Contains(pub, []byte(secret)) {
			t.Errorf("Public() leaks %s: %s", secret, pub)
		}
	}
}

// A touch on B's token reaches B's sink and only B's sink; a sealed config moved to another
// tenant's row doesn't open.
func TestTenantRoutingAndSealBinding(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(":memory:")
	defer st.Close()
	sealer, _ := seal.New(bytes.Repeat([]byte{7}, 32))
	op := st.Operator()
	ta, _ := op.CreateTenant(ctx, "A")
	tb, _ := op.CreateTenant(ctx, "B")

	var hitsA, hitsB captured
	srvA := httptest.NewServer(hitsA.handler(200))
	defer srvA.Close()
	srvB := httptest.NewServer(hitsB.handler(200))
	defer srvB.Close()
	for _, x := range []struct {
		tn  store.Tenant
		url string
		tok string
	}{{ta, srvA.URL, "tok_a"}, {tb, srvB.URL, "tok_b"}} {
		v := st.Tenant(x.tn.ID)
		_ = v.CreateToken(ctx, store.Token{ID: x.tok, Kind: "canary_url", Label: "label " + x.tok})
		id := store.NewID("sk_")
		blob, _ := SealConfig(sealer, SinkConfig{Type: "splunk_hec", URL: x.url, Token: "hec-" + x.tn.ID}, x.tn.ID, id)
		_ = v.CreateSink(ctx, store.SinkRecord{ID: id, Type: "splunk_hec", Config: blob})
	}
	res := &TenantResolver{Store: st, Sealer: sealer, Client: egress.Policy{AllowPrivate: true}.Client(5 * time.Second), Log: quiet}
	op1 := &memSink{}
	ob := fastOutbox(st, op1)
	ob.Resolver = res
	p := &Pipeline{Store: st, Outbox: ob, Dedup: NewDedup(time.Minute), Log: quiet}
	if err := p.Hit(ctx, "tok_b", "http", "203.0.113.1", "GET"); err != nil {
		t.Fatal(err)
	}
	drain(t, ob)
	if len(hitsA.reqs) != 0 {
		t.Fatalf("tenant A's sink received B's alert")
	}
	if len(hitsB.reqs) != 1 || hitsB.reqs[0].Header.Get("Authorization") != "Splunk hec-"+tb.ID {
		t.Fatalf("B's sink got %d requests", len(hitsB.reqs))
	}
	if !bytes.Contains(hitsB.body[0], []byte(`"tenant_uid":"`+tb.ID+`"`)) {
		t.Fatal("alert lacks tenant_uid")
	}
	if got := op1.alerts(); len(got) != 1 {
		t.Fatalf("operator sink got %d", len(got))
	}

	// Move A's sealed blob into B's row: it must not open.
	recsA, _ := st.Tenant(ta.ID).ListSinks(ctx)
	moved := recsA[0]
	moved.TenantID = tb.ID
	if _, err := OpenConfig(sealer, moved); err == nil {
		t.Fatal("A's sink config opened as B's")
	}
}
