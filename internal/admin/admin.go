// Package admin serves the authenticated management API. It listens on its own address
// (default localhost), separate from the public listeners.
//
// Tenancy (docs/M4-saas.md): the tenant comes only from the authenticated credential.
//   - A tenant API key (snk_...) acts on its own tenant, nothing else.
//   - The operator key (SNARE_ADMIN_KEY) manages tenants on /api/operator/..., and acts on a
//     tenant's data only when it names that tenant in X-Snare-Tenant (default: "default", so
//     single-team installs and `snare plant` keep working unchanged).
package admin

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielguillaumont/snare/internal/alert"
	"github.com/danielguillaumont/snare/internal/egress"
	"github.com/danielguillaumont/snare/internal/metrics"
	"github.com/danielguillaumont/snare/internal/seal"
	"github.com/danielguillaumont/snare/internal/store"
	"github.com/danielguillaumont/snare/internal/token"
)

var Kinds = map[string]bool{
	"decoy_tool": true, "honey_credential": true, "canary_doc": true,
	"canary_url": true, "canary_instruction": true, "other": true,
	"prompt_canary": true, "memory_canary": true,
	store.KindHeartbeat: true, // touches are heartbeats, never alerts (docs/M11-heartbeat.md)
}

// TenantHeader lets the operator key act on one tenant's data.
const TenantHeader = "X-Snare-Tenant"

type API struct {
	Key       []byte // operator key
	Signer    *token.Signer
	Store     *store.Store
	PublicURL string // e.g. https://cb.example.com
	// URLPath sits between PublicURL and the token in minted URLs (default "/v1/"). M3a showed a
	// fixed, Snare-specific path ("/t/") is a fingerprint, so it is generic and configurable.
	URLPath string
	Zone    string // e.g. cb.example.com.
	Log     *slog.Logger

	// Tenant sinks (M4). With Sealer nil, sink endpoints answer 503.
	Sealer   *seal.Sealer
	Egress   egress.Policy
	Resolver *alert.TenantResolver

	// M4c. Metrics nil means GET /metrics answers 503. Wake, when set, nudges the delivery
	// outbox after a manual retry.
	Metrics *metrics.Registry
	Wake    func()

	// Beats rates heartbeat channels (M11). Now is a clock for tests.
	Beats store.BeatPolicy
	Now   func() time.Time
}

type MintRequest struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Memo  string `json:"memo,omitempty"`
}

type MintResponse struct {
	ID       string `json:"id"`
	Token    string `json:"token"`
	URL      string `json:"url,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	// CallbackURL is the server's public base URL: where tools such as the decoy MCP server
	// report a hit. Never planted where an agent can see it.
	CallbackURL string `json:"callback_url,omitempty"`
}

// DefaultURLPath is used when API.URLPath is empty.
const DefaultURLPath = "/v1/"

// NormalizeURLPath returns p as "/seg/.../" (leading and trailing slash), or the default.
func NormalizeURLPath(p string) string {
	p = strings.Trim(p, "/")
	if p == "" {
		return DefaultURLPath
	}
	return "/" + p + "/"
}

// Principal is who is calling, as established by Authenticate.
type Principal struct {
	Operator bool
	TenantID string // the tenant this request acts on ("" for operator-only routes)
	Role     string // store.RoleAdmin or store.RoleViewer; operator acts as admin
	KeyID    string // tenant key id ("" for the operator)
}

type ctxKey struct{}

func principal(r *http.Request) Principal { return r.Context().Value(ctxKey{}).(Principal) }

// Access levels for routes.
const (
	AccessViewer   = "viewer"   // any key of the tenant
	AccessAdmin    = "admin"    // a tenant admin key, or the operator
	AccessOperator = "operator" // the operator key only
)

// Route is one authenticated endpoint. The isolation test iterates Routes(), so an endpoint
// can't be added without a cross-tenant case.
type Route struct {
	Pattern string // "METHOD /path"
	Access  string
	handler func(*API) http.HandlerFunc
}

func Routes() []Route {
	h := func(f func(*API, http.ResponseWriter, *http.Request)) func(*API) http.HandlerFunc {
		return func(a *API) http.HandlerFunc { return func(w http.ResponseWriter, r *http.Request) { f(a, w, r) } }
	}
	return []Route{
		{"POST /api/tokens", AccessAdmin, h((*API).mint)},
		{"GET /api/tokens", AccessViewer, h((*API).listTokens)},
		{"GET /api/tokens/{id}", AccessViewer, h((*API).getToken)},
		{"POST /api/tokens/{id}/disable", AccessAdmin, func(a *API) http.HandlerFunc { return a.setTokenDisabled(true) }},
		{"POST /api/tokens/{id}/enable", AccessAdmin, func(a *API) http.HandlerFunc { return a.setTokenDisabled(false) }},
		{"POST /api/fingerprints", AccessAdmin, h((*API).fingerprints)},
		{"GET /api/events", AccessViewer, h((*API).listEvents)},
		{"GET /api/events/export", AccessViewer, h((*API).exportEvents)},
		{"POST /api/events/{id}/triage", AccessAdmin, h((*API).triageEvent)},
		{"GET /api/incidents", AccessViewer, h((*API).listIncidents)},
		{"GET /api/heartbeats", AccessViewer, h((*API).listHeartbeats)},
		{"GET /api/incidents/{id}", AccessViewer, h((*API).getIncident)},
		{"POST /api/sessions/{id}/release", AccessAdmin, h((*API).releaseSession)},
		{"GET /api/sinks", AccessViewer, h((*API).listSinks)},
		{"POST /api/sinks", AccessAdmin, h((*API).createSink)},
		{"DELETE /api/sinks/{id}", AccessAdmin, h((*API).deleteSink)},
		{"POST /api/sinks/{id}/test", AccessAdmin, h((*API).testSink)},
		{"GET /api/audit", AccessViewer, h((*API).listAudit)},
		{"GET /api/deliveries", AccessViewer, h((*API).listDeliveries)},
		{"POST /api/deliveries/{id}/retry", AccessAdmin, h((*API).retryDelivery)},
		{"GET /api/operator/deliveries", AccessOperator, h((*API).operatorDeliveries)},
		{"POST /api/operator/deliveries/{id}/retry", AccessOperator, h((*API).operatorRetryDelivery)},
		{"GET /metrics", AccessOperator, h((*API).metrics)},
		{"GET /api/operator/audit", AccessOperator, h((*API).operatorAudit)},
		{"GET /api/operator/audit/verify", AccessOperator, h((*API).verifyAudit)},
		{"GET /api/operator/tenants", AccessOperator, h((*API).listTenants)},
		{"POST /api/operator/tenants", AccessOperator, h((*API).createTenant)},
		{"POST /api/operator/tenants/{id}/disable", AccessOperator, func(a *API) http.HandlerFunc { return a.setDisabled(true) }},
		{"POST /api/operator/tenants/{id}/enable", AccessOperator, func(a *API) http.HandlerFunc { return a.setDisabled(false) }},
		{"GET /api/operator/tenants/{id}/keys", AccessOperator, h((*API).listKeys)},
		{"POST /api/operator/tenants/{id}/keys", AccessOperator, h((*API).createKey)},
		{"DELETE /api/operator/keys/{id}", AccessOperator, h((*API).revokeKey)},
	}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	for _, rt := range Routes() {
		var h http.Handler
		switch rt.Access {
		case AccessOperator:
			h = a.operatorOnly(rt.handler(a))
		case AccessAdmin:
			h = a.tenantOnly(store.RoleAdmin, rt.handler(a))
		default:
			h = a.tenantOnly(store.RoleViewer, rt.handler(a))
		}
		mux.Handle(rt.Pattern, a.auth(h))
	}
	return mux
}

// Authenticate resolves the bearer credential and, for the operator, the target tenant.
func (a *API) Authenticate(r *http.Request) (Principal, int, string) {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || got == "" {
		return Principal{}, http.StatusUnauthorized, "unauthorized"
	}
	named := strings.TrimSpace(r.Header.Get(TenantHeader))
	if len(a.Key) > 0 && subtle.ConstantTimeCompare([]byte(got), a.Key) == 1 {
		p := Principal{Operator: true, Role: store.RoleAdmin, TenantID: store.DefaultTenant}
		if named != "" {
			if _, err := a.Store.Operator().GetTenant(r.Context(), named); err != nil {
				return Principal{}, http.StatusNotFound, "unknown tenant"
			}
			p.TenantID = named
		}
		return p, 0, ""
	}
	k, err := a.Store.Authenticate(r.Context(), got)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			a.Log.Error("authenticate", "err", err)
		}
		return Principal{}, http.StatusUnauthorized, "unauthorized"
	}
	if named != "" && named != k.TenantID {
		return Principal{}, http.StatusForbidden, "a tenant key acts on its own tenant only"
	}
	return Principal{TenantID: k.TenantID, Role: k.Role, KeyID: k.ID}, 0, ""
}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, code, msg := a.Authenticate(r)
		if code != 0 {
			writeJSON(w, code, map[string]string{"error": msg})
			return
		}
		actor := p.KeyID
		if p.Operator {
			actor = "operator"
		}
		// The actor rides in the context so store writes are attributed in the audit log.
		ctx := store.WithActor(context.WithValue(r.Context(), ctxKey{}, p), actor)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *API) tenantOnly(minRole string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		if minRole == store.RoleAdmin && p.Role != store.RoleAdmin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "this key is read-only"})
			return
		}
		next(w, r)
	})
}

func (a *API) operatorOnly(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !principal(r).Operator {
			// Same answer as an unknown route would give a tenant: nothing to learn here.
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		next(w, r)
	})
}

func (a *API) view(r *http.Request) store.TenantStore { return a.Store.Tenant(principal(r).TenantID) }

// --------------------------------------------------------------------------- tokens and events

func (a *API) mint(w http.ResponseWriter, r *http.Request) {
	var req MintRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if !Kinds[req.Kind] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown kind"})
		return
	}
	if req.Label == "" || len(req.Label) > 200 || len(req.Memo) > 2000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "label required (max 200 chars); memo max 2000"})
		return
	}
	tok, id, err := a.Signer.Mint()
	if err != nil {
		a.fail(w, "mint", err)
		return
	}
	if err := a.view(r).CreateToken(r.Context(), store.Token{ID: id, Kind: req.Kind, Label: req.Label, Memo: req.Memo}); err != nil {
		a.fail(w, "store token", err)
		return
	}
	resp := MintResponse{ID: id, Token: tok}
	if a.PublicURL != "" {
		base := strings.TrimRight(a.PublicURL, "/")
		resp.URL = base + NormalizeURLPath(a.URLPath) + tok
		resp.CallbackURL = base
	}
	if a.Zone != "" {
		resp.Hostname = tok + "." + strings.TrimSuffix(a.Zone, ".")
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (a *API) listTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := a.view(r).ListTokens(r.Context())
	if err != nil {
		a.fail(w, "list tokens", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(toks))
}

// FingerprintRequest asks for the tenant's token fingerprints under a caller-chosen salt
// (docs/M6-gateway.md §3).
type FingerprintRequest struct {
	Salt string `json:"salt"`
}

type FingerprintResponse struct {
	Fingerprints []string `json:"fingerprints"`
	Tokens       int      `json:"tokens"`
}

// fingerprints lets the gateway recognize this tenant's honey values without holding them.
// Admin only: it is part of planting. The response holds salted hashes, never tokens.
func (a *API) fingerprints(w http.ResponseWriter, r *http.Request) {
	var req FingerprintRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil || !validSalt(req.Salt) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body: {\"salt\": 16-64 characters of [A-Za-z0-9_-]}"})
		return
	}
	toks, err := a.view(r).ListTokens(r.Context())
	if err != nil {
		a.fail(w, "list tokens", err)
		return
	}
	resp := FingerprintResponse{Fingerprints: []string{}}
	for _, t := range toks {
		bodies, err := a.Signer.Bodies(t.ID)
		if err != nil {
			continue // not a minted id (imported rows); it can't appear as a token
		}
		resp.Tokens++
		for _, b := range bodies {
			resp.Fingerprints = append(resp.Fingerprints, token.Fingerprint(req.Salt, b))
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func validSalt(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (a *API) getToken(w http.ResponseWriter, r *http.Request) {
	t, err := a.view(r).GetToken(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		a.fail(w, "get token", err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	f := store.EventFilter{TokenID: q.Get("token"), Status: q.Get("status")}
	if f.Status != "" && !store.ValidStatus(f.Status) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status: open, acknowledged, resolved or false_positive"})
		return
	}
	evs, err := a.view(r).ListEventsFiltered(r.Context(), f, limit)
	if err != nil {
		a.fail(w, "list events", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(evs))
}

// TriageRequest is the body of POST /api/events/{id}/triage.
type TriageRequest struct {
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

func (a *API) triageEvent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	var req TriageRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body: {\"status\": ..., \"note\": ...}"})
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	err = a.view(r).TriageEvent(r.Context(), id, req.Status, req.Note)
	switch {
	case errors.Is(err, store.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf(
			"status must be open, acknowledged, resolved or false_positive; note at most %d bytes", store.MaxTriageNote)})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case err != nil:
		a.fail(w, "triage event", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// setTokenDisabled mutes or unmutes one tripwire (docs/M4e-lifecycle.md §1).
func (a *API) setTokenDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		err := a.view(r).SetTokenDisabled(r.Context(), id, disabled)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if err != nil {
			a.fail(w, "set token state", err)
			return
		}
		a.Log.Info("tripwire state changed", "token", id, "disabled", disabled, "tenant", principal(r).TenantID)
		w.WriteHeader(http.StatusNoContent)
	}
}

// exportEvents streams the tenant's events as OCSF Detection Findings, one JSON object per
// line, oldest first. `since` is RFC 3339 or epoch milliseconds.
func (a *API) exportEvents(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if s := r.URL.Query().Get("since"); s != "" {
		if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
			since = time.UnixMilli(ms)
		} else if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "since: RFC 3339 or epoch ms"})
			return
		}
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v := a.view(r)
	evs, err := v.EventsSince(r.Context(), since, limit)
	if err != nil {
		a.fail(w, "export events", err)
		return
	}
	toks, err := v.ListTokens(r.Context())
	if err != nil {
		a.fail(w, "export tokens", err)
		return
	}
	byID := make(map[string]store.Token, len(toks))
	for _, t := range toks {
		byID[t.ID] = t
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	for _, e := range evs {
		// e comes from this tenant's view, so its correlation is computed within the tenant.
		al, err := alert.Build(r.Context(), a.Store, byID[e.TokenID], e, alert.DefaultCorrelationWindow)
		if err != nil {
			a.Log.Error("export: correlate", "err", err)
			al = alert.New(byID[e.TokenID], e)
		}
		_ = enc.Encode(al)
	}
	_ = bw.Flush()
}

// --------------------------------------------------------------------------- sinks

type sinkView struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Config    map[string]string `json:"config"` // secrets removed
	CreatedAt time.Time         `json:"created_at"`
}

func (a *API) sinksEnabled(w http.ResponseWriter) bool {
	if a.Sealer == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant sinks are disabled: set SNARE_SEAL_KEY"})
		return false
	}
	return true
}

func (a *API) listSinks(w http.ResponseWriter, r *http.Request) {
	if !a.sinksEnabled(w) {
		return
	}
	recs, err := a.view(r).ListSinks(r.Context())
	if err != nil {
		a.fail(w, "list sinks", err)
		return
	}
	out := []sinkView{}
	for _, rec := range recs {
		v := sinkView{ID: rec.ID, Type: rec.Type, CreatedAt: rec.CreatedAt}
		if cfg, err := alert.OpenConfig(a.Sealer, rec); err == nil {
			v.Config = cfg.Public()
		} else {
			v.Config = map[string]string{"error": "config does not open (seal key changed?)"}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createSink(w http.ResponseWriter, r *http.Request) {
	if !a.sinksEnabled(w) {
		return
	}
	var cfg alert.SinkConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := cfg.Validate(r.Context(), a.Egress); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	v := a.view(r)
	id := store.NewID("sk_")
	blob, err := alert.SealConfig(a.Sealer, cfg, v.TenantID(), id)
	if err != nil {
		a.fail(w, "seal sink", err)
		return
	}
	rec := store.SinkRecord{ID: id, Type: cfg.Type, Config: blob}
	if err := v.CreateSink(r.Context(), rec); err != nil {
		a.fail(w, "store sink", err)
		return
	}
	if a.Resolver != nil {
		a.Resolver.Invalidate(v.TenantID())
	}
	writeJSON(w, http.StatusCreated, sinkView{ID: id, Type: cfg.Type, Config: cfg.Public(), CreatedAt: time.Now().UTC()})
}

func (a *API) deleteSink(w http.ResponseWriter, r *http.Request) {
	if !a.sinksEnabled(w) {
		return
	}
	v := a.view(r)
	err := v.DeleteSink(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		a.fail(w, "delete sink", err)
		return
	}
	if a.Resolver != nil {
		a.Resolver.Invalidate(v.TenantID())
	}
	w.WriteHeader(http.StatusNoContent)
}

// testSink sends a clearly marked synthetic finding, so a team can check their SIEM mapping
// without touching a tripwire.
func (a *API) testSink(w http.ResponseWriter, r *http.Request) {
	if !a.sinksEnabled(w) {
		return
	}
	v := a.view(r)
	recs, err := v.ListSinks(r.Context())
	if err != nil {
		a.fail(w, "list sinks", err)
		return
	}
	for _, rec := range recs {
		if rec.ID != r.PathValue("id") {
			continue
		}
		cfg, err := alert.OpenConfig(a.Sealer, rec)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "config does not open"})
			return
		}
		s, err := cfg.Build(a.Egress.Client(10 * time.Second))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		al := alert.New(store.Token{ID: "test", Kind: "test", Label: "Snare test alert (not a real touch)"},
			store.Event{ID: 0, TenantID: v.TenantID(), TokenID: "test", Channel: "test", SourceIP: "192.0.2.1", At: time.Now().UTC()})
		al.SeverityID, al.Severity = 1, "Informational"
		if err := s.Send(r.Context(), al); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "delivery failed: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "delivered"})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

// ---------------------------------------------------------------------------- heartbeat

// listHeartbeats rates the tenant's heartbeat channels (docs/M11-heartbeat.md §2).
func (a *API) listHeartbeats(w http.ResponseWriter, r *http.Request) {
	hs, err := a.view(r).ListHeartbeats(r.Context())
	if err != nil {
		a.fail(w, "list heartbeats", err)
		return
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	writeJSON(w, http.StatusOK, nonNil(a.Beats.Status(hs, now().UTC())))
}

// --------------------------------------------------------------------------- audit

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	es, err := a.view(r).ListAudit(r.Context(), limit)
	if err != nil {
		a.fail(w, "list audit", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(es))
}

func (a *API) operatorAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	es, err := a.Store.Operator().ListAudit(r.Context(), r.URL.Query().Get("tenant"), limit)
	if err != nil {
		a.fail(w, "list audit", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(es))
}

func validState(st string) bool {
	return st == "" || st == store.DeliveryPending || st == store.DeliveryDelivered || st == store.DeliveryDead
}

func (a *API) listDeliveries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !validState(q.Get("state")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state must be pending, delivered or dead"})
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	ds, err := a.view(r).ListDeliveries(r.Context(), q.Get("state"), limit)
	if err != nil {
		a.fail(w, "list deliveries", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(ds))
}

func (a *API) operatorDeliveries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !validState(q.Get("state")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state must be pending, delivered or dead"})
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	ds, err := a.Store.Operator().ListDeliveries(r.Context(), q.Get("state"), limit)
	if err != nil {
		a.fail(w, "list deliveries", err)
		return
	}
	// The operator view says whose each delivery is.
	type opDelivery struct {
		store.Delivery
		TenantID string `json:"tenant_id"`
	}
	out := make([]opDelivery, len(ds))
	for i, d := range ds {
		out[i] = opDelivery{d, d.TenantID}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) doRetry(w http.ResponseWriter, r *http.Request, retry func(context.Context, int64) error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	err = retry(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found, or not dead"})
		return
	}
	if err != nil {
		a.fail(w, "retry delivery", err)
		return
	}
	if a.Wake != nil {
		a.Wake()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) retryDelivery(w http.ResponseWriter, r *http.Request) {
	a.doRetry(w, r, a.view(r).RetryDelivery)
}

func (a *API) operatorRetryDelivery(w http.ResponseWriter, r *http.Request) {
	a.doRetry(w, r, a.Store.Operator().RetryDelivery)
}

// metrics serves the Prometheus text format. It sits behind the operator key: counts reveal
// little, but nothing on the admin listener is unauthenticated except /healthz.
func (a *API) metrics(w http.ResponseWriter, _ *http.Request) {
	if a.Metrics == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "metrics not enabled"})
		return
	}
	w.Header().Set("Content-Type", metrics.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	a.Metrics.Write(w)
}

// AuditVerification is the answer of GET /api/operator/audit/verify.
type AuditVerification struct {
	OK       bool   `json:"ok"`
	Records  int    `json:"records"`
	Head     string `json:"head,omitempty"` // record this somewhere else to detect a rewritten chain
	BrokenAt int64  `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func (a *API) verifyAudit(w http.ResponseWriter, r *http.Request) {
	head, n, err := a.Store.Operator().VerifyAudit(r.Context())
	var be *store.AuditBrokenError
	switch {
	case errors.As(err, &be):
		a.Log.Error("audit chain broken", "seq", be.Seq, "reason", be.Reason)
		writeJSON(w, http.StatusOK, AuditVerification{Records: n, BrokenAt: be.Seq, Reason: be.Reason})
	case err != nil:
		a.fail(w, "verify audit", err)
	default:
		writeJSON(w, http.StatusOK, AuditVerification{OK: true, Records: n, Head: head})
	}
}

// --------------------------------------------------------------------------- operator

func (a *API) listTenants(w http.ResponseWriter, r *http.Request) {
	ts, err := a.Store.Operator().ListTenants(r.Context())
	if err != nil {
		a.fail(w, "list tenants", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(ts))
}

func (a *API) createTenant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required (max 100 chars)"})
		return
	}
	t, err := a.Store.Operator().CreateTenant(r.Context(), req.Name)
	if err != nil {
		a.fail(w, "create tenant", err)
		return
	}
	a.Log.Info("tenant created", "tenant", t.ID)
	writeJSON(w, http.StatusCreated, t)
}

func (a *API) setDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == store.DefaultTenant && disabled {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "the default tenant cannot be disabled"})
			return
		}
		err := a.Store.Operator().SetTenantDisabled(r.Context(), id, disabled)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if err != nil {
			a.fail(w, "set tenant state", err)
			return
		}
		a.Log.Info("tenant state changed", "tenant", id, "disabled", disabled)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *API) listKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := a.Store.Operator().ListAPIKeys(r.Context(), r.PathValue("id"))
	if err != nil {
		a.fail(w, "list keys", err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(ks))
}

func (a *API) createKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role string `json:"role"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)
	if req.Role == "" {
		req.Role = store.RoleAdmin
	}
	plain, k, err := a.Store.Operator().CreateAPIKey(r.Context(), r.PathValue("id"), req.Role)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	case err != nil && strings.Contains(err.Error(), "unknown role"):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	case err != nil:
		a.fail(w, "create key", err)
		return
	}
	a.Log.Info("api key issued", "tenant", k.TenantID, "key", k.ID, "role", k.Role)
	writeJSON(w, http.StatusCreated, struct {
		store.APIKey
		Key string `json:"key"` // shown once
	}{k, plain})
}

func (a *API) revokeKey(w http.ResponseWriter, r *http.Request) {
	err := a.Store.Operator().RevokeAPIKey(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		a.fail(w, "revoke key", err)
		return
	}
	a.Log.Info("api key revoked", "key", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// --------------------------------------------------------------------------- helpers

func (a *API) fail(w http.ResponseWriter, what string, err error) {
	a.Log.Error(what, "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
