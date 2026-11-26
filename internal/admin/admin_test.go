package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/alert"
	"github.com/danielguillaumont/snare/internal/egress"
	"github.com/danielguillaumont/snare/internal/metrics"
	"github.com/danielguillaumont/snare/internal/seal"
	"github.com/danielguillaumont/snare/internal/store"
	"github.com/danielguillaumont/snare/internal/token"
)

const opKey = "operator-key-0123456789abcdef"

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type tenantFix struct {
	id, admin, viewer, revoked  string
	tokID, label, sinkID, keyID string
	deliveryID                  string // a dead delivery to sinkID
	eventID                     string // the hit on tokID
}

type env struct {
	t    *testing.T
	srv  *httptest.Server
	st   *store.Store
	a, b tenantFix
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	signer, _ := token.NewSigner(bytes.Repeat([]byte{1}, 32))
	sealer, _ := seal.New(bytes.Repeat([]byte{2}, 32))
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	t.Cleanup(hook.Close)
	api := &API{Key: []byte(opKey), Signer: signer, Store: st, PublicURL: "https://cb.example.com", Log: quiet,
		Sealer: sealer, Egress: egress.Policy{AllowPrivate: true}}
	reg := metrics.New()
	alert.NewMetrics(reg, st)
	api.Metrics = reg
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	e := &env{t: t, srv: srv, st: st}

	op := st.Operator()
	mk := func(name string) tenantFix {
		tn, _ := op.CreateTenant(ctx, name)
		f := tenantFix{id: tn.ID}
		var k store.APIKey
		f.admin, k, _ = op.CreateAPIKey(ctx, tn.ID, store.RoleAdmin)
		f.keyID = k.ID
		f.viewer, _, _ = op.CreateAPIKey(ctx, tn.ID, store.RoleViewer)
		var rk store.APIKey
		f.revoked, rk, _ = op.CreateAPIKey(ctx, tn.ID, store.RoleAdmin)
		_ = op.RevokeAPIKey(ctx, rk.ID)
		f.label = "secret-label-of-" + name
		var m MintResponse
		e.call("POST", "/api/tokens", f.admin, "", MintRequest{Kind: "canary_url", Label: f.label}, 201, &m)
		f.tokID = m.ID
		_, ev, _, _, err := st.RecordHit(ctx, store.Event{TokenID: m.ID, Channel: "http", SourceIP: "203.0.113.2", At: time.Now()}, true)
		if err != nil {
			t.Fatal(err)
		}
		f.eventID = strconv.FormatInt(ev.ID, 10)
		var s sinkView
		e.call("POST", "/api/sinks", f.admin, "", alert.SinkConfig{Type: "webhook", URL: hook.URL, Secret: "webhook-secret-" + name}, 201, &s)
		f.sinkID = s.ID
		// The hit's delivery to that sink has failed for good.
		ob := st.Outbox()
		due, _ := ob.Due(ctx, time.Now().Add(time.Minute), 10)
		for _, d := range due {
			if d.IsMarker() && d.TenantID == tn.ID {
				_ = ob.Expand(ctx, d, []string{s.ID}, time.Now())
			}
		}
		rows, _ := st.Tenant(tn.ID).ListDeliveries(ctx, "", 10)
		if len(rows) != 1 {
			t.Fatalf("fixture deliveries %+v", rows)
		}
		_ = ob.MarkFailed(ctx, rows[0].ID, 20, time.Now(), "connection refused", true, time.Now())
		f.deliveryID = strconv.FormatInt(rows[0].ID, 10)
		return f
	}
	e.a, e.b = mk("acme"), mk("beta")
	return e
}

func (e *env) do(method, path, key, tenantHdr string, body any) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if tenantHdr != "" {
		req.Header.Set(TenantHeader, tenantHdr)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func (e *env) call(method, path, key, hdr string, body any, want int, out any) {
	e.t.Helper()
	code, data := e.do(method, path, key, hdr, body)
	if code != want {
		e.t.Fatalf("%s %s: %d %s (want %d)", method, path, code, data, want)
	}
	if out != nil {
		_ = json.Unmarshal(data, out)
	}
}

// secrets of a tenant that must never appear in a response made on behalf of the other.
func (f tenantFix) secrets() []string {
	return []string{f.tokID, f.label, f.sinkID, f.id, f.keyID, "webhook-secret-"}
}

type caller struct {
	name, key, hdr string
	actsAs         string // "a", "b", or "" (rejected before acting)
	role           string
}

func (e *env) callers() []caller {
	return []caller{
		{"A admin", e.a.admin, "", "a", store.RoleAdmin},
		{"A viewer", e.a.viewer, "", "a", store.RoleViewer},
		{"operator as A", opKey, e.a.id, "a", store.RoleAdmin},
		{"operator as B", opKey, e.b.id, "b", store.RoleAdmin},
		{"A admin naming B", e.a.admin, e.b.id, "", ""},
		{"operator naming unknown tenant", opKey, "tn_nope", "", ""},
		{"A revoked", e.a.revoked, "", "", ""},
		{"no key", "", "", "", ""},
		{"garbage key", "snk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "", ""},
		{"B key hash as key", store.HashKey(e.b.admin), "", "", ""},
	}
}

// TestAPITenantIsolationMatrix is the M4 exit test at the API layer.
func TestAPITenantIsolationMatrix(t *testing.T) {
	covered := map[string]bool{}
	for _, rt := range Routes() {
		if rt.Access == AccessOperator {
			continue // TestOperatorRoutes
		}
		covered[rt.Pattern] = true
		rt := rt
		t.Run(rt.Pattern, func(t *testing.T) {
			e := newEnv(t)
			method, path, _ := strings.Cut(rt.Pattern, " ")
			hasID := strings.Contains(path, "{id}")
			for i := range e.callers() {
				if method == "DELETE" || strings.HasSuffix(path, "/retry") {
					e = newEnv(t) // destructive: each caller gets fresh resources
				}
				c := e.callers()[i]
				own, other := e.a, e.b
				if c.actsAs == "b" {
					own, other = e.b, e.a
				}
				targets := []struct {
					label string
					f     tenantFix
				}{{"own", own}}
				if hasID {
					targets = append(targets, struct {
						label string
						f     tenantFix
					}{"other", other})
				}
				for _, tg := range targets {
					p := path
					if hasID {
						id := tg.f.tokID
						if strings.HasPrefix(path, "/api/sinks/") {
							id = tg.f.sinkID
						}
						if strings.HasPrefix(path, "/api/deliveries/") {
							id = tg.f.deliveryID
						}
						if strings.HasPrefix(path, "/api/events/") {
							id = tg.f.eventID
						}
						p = strings.Replace(path, "{id}", id, 1)
					}
					code, body := e.do(method, p, c.key, c.hdr, bodyFor(rt.Pattern))
					want := expect(c, rt, tg.label)
					if code != want {
						t.Errorf("%s on %s id: %d %s, want %d", c.name, tg.label, code, body, want)
					}
					if c.actsAs != "" {
						for _, s := range other.secrets() {
							if bytes.Contains(body, []byte(s)) && !(s == "webhook-secret-") {
								t.Errorf("%s: response leaks other tenant's %q: %s", c.name, s, body)
							}
						}
					}
					if bytes.Contains(body, []byte("webhook-secret-")) {
						t.Errorf("%s: response contains a sink secret: %s", c.name, body)
					}
				}
			}
		})
	}
	for _, rt := range Routes() {
		if rt.Access != AccessOperator && !covered[rt.Pattern] {
			t.Errorf("route %s has no isolation case", rt.Pattern)
		}
	}
}

func bodyFor(pattern string) any {
	switch pattern {
	case "POST /api/tokens":
		return MintRequest{Kind: "canary_doc", Label: "new"}
	case "POST /api/sinks":
		return alert.SinkConfig{Type: "splunk_hec", URL: "https://8.8.8.8", Token: "hec"}
	case "POST /api/events/{id}/triage":
		return TriageRequest{Status: store.StatusAcknowledged, Note: "looking"}
	}
	return nil
}

// success is the status a permitted caller gets on its own tenant's resource.
var success = map[string]int{
	"POST /api/tokens":                201,
	"GET /api/tokens":                 200,
	"GET /api/tokens/{id}":            200,
	"GET /api/events":                 200,
	"GET /api/events/export":          200,
	"GET /api/sinks":                  200,
	"POST /api/sinks":                 201,
	"DELETE /api/sinks/{id}":          204,
	"POST /api/sinks/{id}/test":       200,
	"POST /api/tokens/{id}/disable":   204,
	"POST /api/tokens/{id}/enable":    204,
	"POST /api/events/{id}/triage":    204,
	"GET /api/audit":                  200,
	"GET /api/deliveries":             200,
	"POST /api/deliveries/{id}/retry": 204,
}

func expect(c caller, rt Route, target string) int {
	switch c.name {
	case "A admin naming B":
		return 403
	case "operator naming unknown tenant":
		return 404
	}
	if c.actsAs == "" {
		return 401
	}
	if rt.Access == AccessAdmin && c.role != store.RoleAdmin {
		return 403
	}
	if target == "other" {
		return 404
	}
	return success[rt.Pattern]
}

func TestOperatorRoutes(t *testing.T) {
	e := newEnv(t)
	for _, rt := range Routes() {
		if rt.Access != AccessOperator {
			continue
		}
		method, path, _ := strings.Cut(rt.Pattern, " ")
		p := strings.Replace(path, "{id}", e.b.id, 1)
		for _, c := range []struct {
			name, key string
			want      int
		}{{"tenant admin", e.a.admin, 404}, {"tenant viewer", e.a.viewer, 404}, {"no key", "", 401}, {"revoked", e.a.revoked, 401}} {
			if code, body := e.do(method, p, c.key, "", nil); code != c.want {
				t.Errorf("%s %s by %s: %d %s, want %d", method, p, c.name, code, body, c.want)
			}
		}
	}
	// Operator flow: create a tenant, issue a key (shown once), use it, disable, revoke.
	var tn store.Tenant
	e.call("POST", "/api/operator/tenants", opKey, "", map[string]string{"name": "Gamma"}, 201, &tn)
	var issued struct {
		store.APIKey
		Key string `json:"key"`
	}
	e.call("POST", "/api/operator/tenants/"+tn.ID+"/keys", opKey, "", map[string]string{"role": "viewer"}, 201, &issued)
	if !strings.HasPrefix(issued.Key, store.APIKeyPrefix) || issued.TenantID != tn.ID {
		t.Fatalf("issued %+v", issued)
	}
	var keys []store.APIKey
	e.call("GET", "/api/operator/tenants/"+tn.ID+"/keys", opKey, "", nil, 200, &keys)
	if raw, _ := json.Marshal(keys); bytes.Contains(raw, []byte(issued.Key)) {
		t.Fatal("key listing contains the plaintext key")
	}
	e.call("GET", "/api/tokens", issued.Key, "", nil, 200, nil)
	e.call("POST", "/api/tokens", issued.Key, "", MintRequest{Kind: "canary_url", Label: "x"}, 403, nil)
	e.call("POST", "/api/operator/tenants/"+tn.ID+"/keys", opKey, "", map[string]string{"role": "root"}, 400, nil)
	e.call("POST", "/api/operator/tenants/tn_missing/keys", opKey, "", nil, 404, nil)
	e.call("POST", "/api/operator/tenants/"+tn.ID+"/disable", opKey, "", nil, 204, nil)
	e.call("GET", "/api/tokens", issued.Key, "", nil, 401, nil)
	e.call("POST", "/api/operator/tenants/"+tn.ID+"/enable", opKey, "", nil, 204, nil)
	e.call("GET", "/api/tokens", issued.Key, "", nil, 200, nil)
	e.call("DELETE", "/api/operator/keys/"+issued.ID, opKey, "", nil, 204, nil)
	e.call("GET", "/api/tokens", issued.Key, "", nil, 401, nil)
	e.call("POST", "/api/operator/tenants/default/disable", opKey, "", nil, 400, nil)
	var all []store.Tenant
	e.call("GET", "/api/operator/tenants", opKey, "", nil, 200, &all)
	if len(all) != 4 { // default, acme, beta, gamma
		t.Fatalf("tenants %+v", all)
	}
}

// Pre-M4 behaviour: the operator key with no tenant header acts on the default tenant, so
// `snare plant` and existing scripts keep working.
func TestOperatorKeyDefaultsToDefaultTenant(t *testing.T) {
	e := newEnv(t)
	var m MintResponse
	e.call("POST", "/api/tokens", opKey, "", MintRequest{Kind: "canary_url", Label: "legacy"}, 201, &m)
	if _, err := e.st.Tenant(store.DefaultTenant).GetToken(context.Background(), m.ID); err != nil {
		t.Fatalf("legacy mint not in default tenant: %v", err)
	}
	var toks []store.Token
	e.call("GET", "/api/tokens", opKey, "", nil, 200, &toks)
	if len(toks) != 1 || toks[0].ID != m.ID {
		t.Fatalf("default tenant sees %+v (must not include acme/beta)", toks)
	}
}

func TestExportIsOCSFNDJSONForOwnTenant(t *testing.T) {
	e := newEnv(t)
	code, body := e.do("GET", "/api/events/export?since=0", e.a.viewer, "", nil)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	lines := bytes.Split(bytes.TrimSpace(body), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("want 1 finding, got %d: %s", len(lines), body)
	}
	var a alert.Alert
	if err := json.Unmarshal(lines[0], &a); err != nil {
		t.Fatal(err)
	}
	if a.ClassUID != 2004 || a.Metadata.TenantUID != e.a.id || a.Unmapped.TokenID != e.a.tokID || a.Unmapped.Label != e.a.label {
		t.Fatalf("finding %+v", a)
	}
	if code, _ := e.do("GET", "/api/events/export?since=yesterday", e.a.viewer, "", nil); code != 400 {
		t.Fatalf("bad since accepted: %d", code)
	}
}

func TestSinkEndpointsRejectSSRFTargetsInProduction(t *testing.T) {
	e := newEnv(t)
	// Swap in the production egress policy.
	api := &API{Key: []byte(opKey), Store: e.st, Log: quiet, Sealer: mustSealer(), Egress: egress.Policy{}}
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	for _, u := range []string{"https://169.254.169.254/latest", "https://127.0.0.1:8081/api/operator/tenants", "http://8.8.8.8"} {
		b, _ := json.Marshal(alert.SinkConfig{Type: "splunk_hec", URL: u, Token: "t"})
		req, _ := http.NewRequest("POST", srv.URL+"/api/sinks", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+e.a.admin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("sink %s accepted: %d", u, resp.StatusCode)
		}
	}
}

func mustSealer() *seal.Sealer {
	s, _ := seal.New(bytes.Repeat([]byte{2}, 32))
	return s
}

// Changes made through the API are attributed to the key that made them, a tenant sees only
// its own records, and the operator's verify endpoint reports an intact chain.
func TestAuditThroughAPI(t *testing.T) {
	e := newEnv(t)
	var created struct {
		ID string `json:"id"`
	}
	e.call("POST", "/api/sinks", e.a.admin, "", alert.SinkConfig{Type: "splunk_hec", URL: "https://8.8.8.8", Token: "hec"}, 201, &created)

	var es []store.AuditEntry
	e.call("GET", "/api/audit", e.a.viewer, "", nil, 200, &es)
	if len(es) == 0 || es[0].Action != store.ActSinkCreate || es[0].Target != created.ID {
		t.Fatalf("latest record %+v", es)
	}
	var adminKeyID string
	if k, err := e.st.Authenticate(context.Background(), e.a.admin); err == nil {
		adminKeyID = k.ID
	}
	if es[0].Actor != adminKeyID || adminKeyID == "" {
		t.Fatalf("actor %q, want A's admin key %q", es[0].Actor, adminKeyID)
	}
	for _, x := range es {
		if x.TenantID != e.a.id {
			t.Fatalf("A sees another tenant's record %+v", x)
		}
	}

	var v AuditVerification
	e.call("GET", "/api/operator/audit/verify", opKey, "", nil, 200, &v)
	if !v.OK || v.Records < 2 || len(v.Head) != 64 {
		t.Fatalf("verify %+v", v)
	}
	var all []store.AuditEntry
	e.call("GET", "/api/operator/audit?tenant="+e.b.id, opKey, "", nil, 200, &all)
	for _, x := range all {
		if x.TenantID != e.b.id {
			t.Fatalf("tenant filter leaked %+v", x)
		}
	}
}

func TestMetricsAndOperatorDeliveries(t *testing.T) {
	e := newEnv(t)
	code, body := e.do("GET", "/metrics", opKey, "", nil)
	if code != 200 || !bytes.Contains(body, []byte("snare_deliveries_dead 2\n")) ||
		!bytes.Contains(body, []byte("# TYPE snare_deliveries_total counter")) {
		t.Fatalf("metrics: %d\n%s", code, body)
	}
	if bytes.Contains(body, []byte(e.a.id)) || bytes.Contains(body, []byte(e.a.label)) {
		t.Fatal("metrics carry tenant data")
	}

	var dead []struct {
		ID       int64  `json:"id"`
		TenantID string `json:"tenant_id"`
		Sink     string `json:"sink"`
	}
	e.call("GET", "/api/operator/deliveries?state=dead", opKey, "", nil, 200, &dead)
	if len(dead) != 2 {
		t.Fatalf("operator sees %+v", dead)
	}
	e.call("GET", "/api/operator/deliveries?state=bogus", opKey, "", nil, 400, nil)
	e.call("GET", "/api/deliveries?state=bogus", e.a.viewer, "", nil, 400, nil)
	id := strconv.FormatInt(dead[0].ID, 10)
	e.call("POST", "/api/operator/deliveries/"+id+"/retry", opKey, "", nil, 204, nil)
	e.call("POST", "/api/operator/deliveries/"+id+"/retry", opKey, "", nil, 404, nil) // no longer dead
	e.call("POST", "/api/operator/deliveries/x/retry", opKey, "", nil, 404, nil)
	var audit []store.AuditEntry
	e.call("GET", "/api/operator/audit?tenant="+dead[0].TenantID, opKey, "", nil, 200, &audit)
	if len(audit) == 0 || audit[0].Action != store.ActDeliveryRetry || audit[0].Actor != "operator" {
		t.Fatalf("retry not audited: %+v", audit)
	}
}
