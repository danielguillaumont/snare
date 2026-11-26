// Package dashboard serves the tenant dashboard (docs/M4-saas.md). It is read-only except for
// admin sessions, which can triage touches and disable tripwires (docs/M4e-lifecycle.md §4).
//
// Sign-in exchanges a tenant API key for a session cookie. The cookie is HMAC-signed and
// carries the key id, so revoking the key (or disabling the tenant) ends the session on the
// next request. Pages are server-rendered with html/template (contextual escaping: token labels
// are attacker-influenced text) under a strict CSP with no inline script or style.
package dashboard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/danielguillaumont/snare/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	cookieName = "snare_session"
	sessionTTL = 8 * time.Hour
)

type Dashboard struct {
	Store      *store.Store
	SessionKey []byte // 32+ bytes; derived from SNARE_KEY by the server
	Dev        bool   // cookies without Secure (http://localhost only)
	TrustProxy bool   // client IP from the last X-Forwarded-For entry (behind our own proxy)
	Log        *slog.Logger
	Now        func() time.Time

	tmpl     *template.Template
	mu       sync.Mutex
	limiters map[string]*rate.Limiter // sign-in attempts per client IP
}

type session struct {
	TenantID string `json:"t"`
	KeyID    string `json:"k"`
	Role     string `json:"r"`
	Expires  int64  `json:"e"`
	CSRF     string `json:"c"`
}

func (d *Dashboard) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Dashboard) Handler() (http.Handler, error) {
	if len(d.SessionKey) < 32 {
		return nil, errors.New("dashboard: session key must be at least 32 bytes")
	}
	t, err := template.New("").Funcs(template.FuncMap{
		"ts": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05Z") },
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	d.tmpl = t
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(assets))
	mux.HandleFunc("GET /login", d.loginPage)
	mux.HandleFunc("POST /login", d.login)
	mux.Handle("POST /logout", d.authed(d.logout))
	mux.Handle("GET /{$}", d.authed(d.overview))
	mux.Handle("GET /tokens/{id}", d.authed(d.tokenPage))
	mux.Handle("GET /sinks", d.authed(d.sinksPage))
	// Admin actions (docs/M4e-lifecycle.md §4). Each redirects back to the tripwire's page.
	mux.Handle("POST /tokens/{id}/disable", d.authed(d.adminForm(d.setTokenDisabled(true))))
	mux.Handle("POST /tokens/{id}/enable", d.authed(d.adminForm(d.setTokenDisabled(false))))
	mux.Handle("POST /tokens/{id}/events/{eid}/triage", d.authed(d.adminForm(d.triage)))
	return secureHeaders(mux), nil
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// --------------------------------------------------------------------------- sessions

func (d *Dashboard) sign(payload []byte) string {
	m := hmac.New(sha256.New, d.SessionKey)
	m.Write([]byte("snare-dashboard-session-v1."))
	m.Write(payload)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (d *Dashboard) encode(s session) string {
	p, _ := json.Marshal(s)
	b := base64.RawURLEncoding.EncodeToString(p)
	return b + "." + d.sign([]byte(b))
}

func (d *Dashboard) decode(v string) (session, bool) {
	b, sig, ok := strings.Cut(v, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(sig), []byte(d.sign([]byte(b)))) != 1 {
		return session{}, false
	}
	p, err := base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return session{}, false
	}
	var s session
	if json.Unmarshal(p, &s) != nil || d.now().Unix() > s.Expires {
		return session{}, false
	}
	return s, true
}

func (d *Dashboard) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: !d.Dev, SameSite: http.SameSiteStrictMode,
	})
}

func (d *Dashboard) authed(next func(http.ResponseWriter, *http.Request, session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		s, ok := d.decode(c.Value)
		if !ok || !d.Store.KeyActive(r.Context(), s.KeyID, s.TenantID) {
			d.setCookie(w, "", -1)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, s)
	})
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --------------------------------------------------------------------------- sign-in

const loginCSRFCookie = "snare_login_csrf"

func (d *Dashboard) loginPage(w http.ResponseWriter, r *http.Request) {
	tok := randToken()
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookie, Value: tok, Path: "/login", MaxAge: 600,
		HttpOnly: true, Secure: !d.Dev, SameSite: http.SameSiteStrictMode})
	d.render(w, "login.html", map[string]any{"CSRF": tok, "Error": r.URL.Query().Get("e") != ""})
}

func (d *Dashboard) clientIP(r *http.Request) string {
	if d.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// The last entry was appended by our own proxy; earlier ones are client-controlled.
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const maxLimiters = 10000

func (d *Dashboard) allow(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.limiters == nil || len(d.limiters) >= maxLimiters {
		// Bounded memory under a spray of source addresses. Resetting forgives everyone at
		// once, which is acceptable: keys are 160-bit random, the limiter is for log noise
		// and cost, not what stands between an attacker and a guessed key.
		d.limiters = map[string]*rate.Limiter{}
	}
	l, ok := d.limiters[ip]
	if !ok {
		l = rate.NewLimiter(rate.Every(12*time.Second), 5) // 5 at once, then 5 per minute
		d.limiters[ip] = l
	}
	return l.Allow()
}

func (d *Dashboard) login(w http.ResponseWriter, r *http.Request) {
	if !d.allow(d.clientIP(r)) {
		http.Error(w, "too many sign-in attempts; wait a minute", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil || c.Value == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostForm.Get("csrf"))) != 1 {
		http.Error(w, "sign-in form expired; reload the page", http.StatusForbidden)
		return
	}
	k, err := d.Store.Authenticate(r.Context(), strings.TrimSpace(r.PostForm.Get("key")))
	if err != nil {
		d.Log.Info("dashboard sign-in failed", "ip", d.clientIP(r))
		http.Redirect(w, r, "/login?e=1", http.StatusSeeOther)
		return
	}
	s := session{TenantID: k.TenantID, KeyID: k.ID, Role: k.Role, Expires: d.now().Add(sessionTTL).Unix(), CSRF: randToken()}
	d.setCookie(w, d.encode(s), int(sessionTTL.Seconds()))
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookie, Value: "", Path: "/login", MaxAge: -1})
	if err := d.Store.Audit(store.WithActor(r.Context(), k.ID), k.TenantID, store.ActSignIn, k.ID, "ip="+d.clientIP(r)); err != nil {
		d.Log.Error("audit sign-in", "err", err)
	}
	d.Log.Info("dashboard sign-in", "tenant", k.TenantID, "key", k.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (d *Dashboard) logout(w http.ResponseWriter, r *http.Request, s session) {
	_ = r.ParseForm()
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.CSRF)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	d.setCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --------------------------------------------------------------------------- pages

func (d *Dashboard) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.tmpl.ExecuteTemplate(w, name, data); err != nil {
		d.Log.Error("render", "template", name, "err", err)
	}
}

type eventRow struct {
	store.Event
	Label string
	// Distinct tripwires this source touched within the correlation window, as the alert
	// computed it (docs/M4c-reliability.md §3). 2 or more is a Critical alert.
	Correlated int
}

// correlationWindow matches alert.DefaultCorrelationWindow; the dashboard doesn't import the
// alert package.
const correlationWindow = time.Hour

func (d *Dashboard) overview(w http.ResponseWriter, r *http.Request, s session) {
	v := d.Store.Tenant(s.TenantID)
	toks, err := v.ListTokens(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	evs, err := v.ListEvents(r.Context(), "", 50)
	if err != nil {
		d.fail(w, err)
		return
	}
	labels := map[string]string{}
	for _, t := range toks {
		labels[t.ID] = t.Label
	}
	rows := make([]eventRow, 0, len(evs))
	touched := map[string]bool{}
	critical, open := 0, 0
	for _, e := range evs {
		_, n, err := v.RelatedTouches(r.Context(), e, correlationWindow, 0)
		if err != nil {
			d.fail(w, err)
			return
		}
		isOpen := e.Status == store.StatusOpen && !e.Muted
		if isOpen {
			open++
			if n >= 2 {
				critical++
			}
		}
		rows = append(rows, eventRow{Event: e, Label: labels[e.TokenID], Correlated: n})
		touched[e.TokenID] = true
	}
	dead, err := v.ListDeliveries(r.Context(), store.DeliveryDead, 100)
	if err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, "overview.html", map[string]any{
		"S": s, "Tokens": toks, "Events": rows, "Touched": touched, "TouchedCount": len(touched),
		"Critical": critical, "Open": open, "Dead": len(dead),
	})
}

func (d *Dashboard) tokenPage(w http.ResponseWriter, r *http.Request, s session) {
	v := d.Store.Tenant(s.TenantID)
	t, err := v.GetToken(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r) // same as a missing id: other tenants' ids can't be probed
		return
	}
	if err != nil {
		d.fail(w, err)
		return
	}
	evs, err := v.ListEvents(r.Context(), t.ID, 200)
	if err != nil {
		d.fail(w, err)
		return
	}
	fp := 0
	for _, e := range evs {
		if e.Status == store.StatusFalsePositive {
			fp++
		}
	}
	d.render(w, "token.html", map[string]any{"S": s, "Token": t, "Events": evs, "FalsePositives": fp,
		"Statuses": []string{store.StatusOpen, store.StatusAcknowledged, store.StatusResolved, store.StatusFalsePositive}})
}

func (d *Dashboard) sinksPage(w http.ResponseWriter, r *http.Request, s session) {
	recs, err := d.Store.Tenant(s.TenantID).ListSinks(r.Context())
	if err != nil {
		d.fail(w, err)
		return
	}
	ds, err := d.Store.Tenant(s.TenantID).ListDeliveries(r.Context(), "", 50)
	if err != nil {
		d.fail(w, err)
		return
	}
	d.render(w, "sinks.html", map[string]any{"S": s, "Sinks": recs, "Deliveries": ds})
}

// adminForm guards a state-changing form: admin sessions only, and the session's CSRF token.
// The store call runs as the signed-in key, so it is audited under that key.
func (d *Dashboard) adminForm(next func(http.ResponseWriter, *http.Request, store.TenantStore) error) func(http.ResponseWriter, *http.Request, session) {
	return func(w http.ResponseWriter, r *http.Request, s session) {
		if s.Role != store.RoleAdmin {
			http.Error(w, "forbidden: sign in with an admin key to change tripwires", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.CSRF)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r = r.WithContext(store.WithActor(r.Context(), s.KeyID))
		err := next(w, r, d.Store.Tenant(s.TenantID))
		switch {
		case errors.Is(err, store.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, store.ErrInvalid):
			http.Error(w, "invalid status or note too long", http.StatusBadRequest)
		case err != nil:
			d.fail(w, err)
		default:
			// Built from the token id, never from the request's Referer or a form field.
			http.Redirect(w, r, "/tokens/"+url.PathEscape(r.PathValue("id")), http.StatusSeeOther)
		}
	}
}

func (d *Dashboard) setTokenDisabled(disabled bool) func(http.ResponseWriter, *http.Request, store.TenantStore) error {
	return func(_ http.ResponseWriter, r *http.Request, v store.TenantStore) error {
		return v.SetTokenDisabled(r.Context(), r.PathValue("id"), disabled)
	}
}

func (d *Dashboard) triage(_ http.ResponseWriter, r *http.Request, v store.TenantStore) error {
	id, err := strconv.ParseInt(r.PathValue("eid"), 10, 64)
	if err != nil {
		return store.ErrNotFound
	}
	return v.TriageEvent(r.Context(), id, r.PostForm.Get("status"), strings.TrimSpace(r.PostForm.Get("note")))
}

func (d *Dashboard) fail(w http.ResponseWriter, err error) {
	d.Log.Error("dashboard", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
