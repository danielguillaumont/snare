package dashboard

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/store"
)

type env struct {
	st         *store.Store
	h          http.Handler
	d          *Dashboard
	a, b       store.Tenant
	keyA, keyB string
	keyAID     string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	op := st.Operator()
	a, _ := op.CreateTenant(ctx, "Acme")
	b, _ := op.CreateTenant(ctx, "Beta")
	keyA, ka, _ := op.CreateAPIKey(ctx, a.ID, store.RoleViewer)
	keyB, _, _ := op.CreateAPIKey(ctx, b.ID, store.RoleAdmin)
	va, vb := st.Tenant(a.ID), st.Tenant(b.ID)
	_ = va.CreateToken(ctx, store.Token{ID: "tok_a", Kind: "canary_url", Label: `acme <script>alert(1)</script>`})
	_ = vb.CreateToken(ctx, store.Token{ID: "tok_b", Kind: "canary_url", Label: "beta-secret-label"})
	_, _, _, _, _ = st.RecordHit(ctx, store.Event{TokenID: "tok_b", Channel: "http", SourceIP: "198.51.100.9", Detail: "GET /beta-path", At: time.Now()}, false)
	_, _, _, _, _ = st.RecordHit(ctx, store.Event{TokenID: "tok_a", Channel: "dns", SourceIP: "203.0.113.5", Detail: "acme-detail", At: time.Now()}, false)
	_ = vb.CreateSink(ctx, store.SinkRecord{ID: "sk_beta", Type: "splunk_hec", Config: []byte("SEALED-BLOB-BYTES")})

	d := &Dashboard{Store: st, SessionKey: bytes.Repeat([]byte{9}, 32), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h, err := d.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return &env{st: st, h: h, d: d, a: a, b: b, keyA: keyA, keyB: keyB, keyAID: ka.ID}
}

func (e *env) do(r *http.Request) *http.Response {
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w.Result()
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// signIn runs the real flow: GET /login for the CSRF cookie and field, POST the key.
func (e *env) signIn(t *testing.T, key string) (*http.Cookie, string) {
	t.Helper()
	res := e.do(httptest.NewRequest("GET", "/login", nil))
	body, _ := io.ReadAll(res.Body)
	m := csrfRe.FindSubmatch(body)
	if m == nil {
		t.Fatal("login page has no csrf field")
	}
	var csrfCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == loginCSRFCookie {
			csrfCookie = c
		}
	}
	form := url.Values{"csrf": {string(m[1])}, "key": {key}}
	r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(csrfCookie)
	res = e.do(r)
	for _, c := range res.Cookies() {
		if c.Name == cookieName && c.Value != "" {
			s, _ := e.d.decode(c.Value)
			return c, s.CSRF
		}
	}
	return nil, res.Header.Get("Location")
}

func (e *env) get(path string, c *http.Cookie) (*http.Response, string) {
	r := httptest.NewRequest("GET", path, nil)
	if c != nil {
		r.AddCookie(c)
	}
	res := e.do(r)
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func TestSignInAndTenantScopedPages(t *testing.T) {
	e := newEnv(t)
	c, _ := e.signIn(t, e.keyA)
	if c == nil {
		t.Fatal("valid key did not get a session")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags %+v", c)
	}
	res, body := e.get("/", c)
	if res.StatusCode != 200 {
		t.Fatalf("overview %d", res.StatusCode)
	}
	if !strings.Contains(body, "acme-detail") {
		t.Fatal("own event missing")
	}
	for _, leak := range []string{"beta-secret-label", "/beta-path", "198.51.100.9", "tok_b"} {
		if strings.Contains(body, leak) {
			t.Fatalf("overview leaks tenant B data %q", leak)
		}
	}
	// html/template escaping of attacker-influenced labels.
	if strings.Contains(body, "<script>alert(1)") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("token label not escaped")
	}
	if res, _ := e.get("/tokens/tok_a", c); res.StatusCode != 200 {
		t.Fatalf("own token %d", res.StatusCode)
	}
	// Another tenant's token id answers exactly like a nonexistent one.
	r1, b1 := e.get("/tokens/tok_b", c)
	r2, b2 := e.get("/tokens/tok_nope", c)
	if r1.StatusCode != 404 || r2.StatusCode != 404 || b1 != b2 {
		t.Fatalf("cross-tenant token: %d vs %d", r1.StatusCode, r2.StatusCode)
	}
	_, body = e.get("/sinks", c)
	if strings.Contains(body, "sk_beta") {
		t.Fatal("sinks page leaks tenant B sink")
	}
	cb, _ := e.signIn(t, e.keyB)
	_, body = e.get("/sinks", cb)
	if !strings.Contains(body, "sk_beta") || strings.Contains(body, "SEALED-BLOB-BYTES") {
		t.Fatal("B's sinks page wrong (missing sink or shows config bytes)")
	}
}

func TestBadKeysAndUnauthenticatedAccess(t *testing.T) {
	e := newEnv(t)
	for _, k := range []string{"", "snk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", e.keyA + "x"} {
		if c, loc := e.signIn(t, k); c != nil || loc != "/login?e=1" {
			t.Errorf("key %q: cookie %v loc %q", k, c, loc)
		}
	}
	for _, p := range []string{"/", "/tokens/tok_a", "/sinks"} {
		res, _ := e.get(p, nil)
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
			t.Errorf("%s without session: %d", p, res.StatusCode)
		}
	}
}

func TestForgedAndTamperedSessionsRejected(t *testing.T) {
	e := newEnv(t)
	c, _ := e.signIn(t, e.keyA)
	s, _ := e.d.decode(c.Value)

	other := &Dashboard{SessionKey: bytes.Repeat([]byte{1}, 32)}
	forgedB := s
	forgedB.TenantID = e.b.ID
	payload, _, _ := strings.Cut(c.Value, ".")
	_, sig, _ := strings.Cut(c.Value, ".")
	swapped := e.d.encode(forgedB)
	swappedPayload, _, _ := strings.Cut(swapped, ".")

	expired := s
	expired.Expires = time.Now().Add(-time.Minute).Unix()

	cases := map[string]string{
		"wrong key":                other.encode(forgedB),
		"payload swapped, old sig": swappedPayload + "." + sig,
		"no signature":             payload,
		"garbage":                  "not-a-session",
		"expired (validly signed)": e.d.encode(expired),
		// Validly signed, but A's key id paired with B's tenant: KeyActive pins key to tenant,
		// so even a leaked session key can't be used to cross tenants with a real key id.
		"key id of other tenant":   e.d.encode(session{TenantID: e.b.ID, KeyID: e.keyAID, Expires: s.Expires}),
		"empty key id, B's tenant": e.d.encode(session{TenantID: e.b.ID, Expires: s.Expires}),
	}
	for name, v := range cases {
		res, body := e.get("/", &http.Cookie{Name: cookieName, Value: v})
		if res.StatusCode != http.StatusSeeOther || strings.Contains(body, "beta-secret-label") {
			t.Errorf("%s: status %d", name, res.StatusCode)
		}
	}
}

func TestRevokedKeyAndDisabledTenantEndSession(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	c, _ := e.signIn(t, e.keyA)
	if res, _ := e.get("/", c); res.StatusCode != 200 {
		t.Fatal("session did not work")
	}
	_ = e.st.Operator().RevokeAPIKey(ctx, e.keyAID)
	res, _ := e.get("/", c)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoked key still has a session: %d", res.StatusCode)
	}
	cleared := false
	for _, k := range res.Cookies() {
		cleared = cleared || (k.Name == cookieName && k.MaxAge < 0)
	}
	if !cleared {
		t.Fatal("cookie not cleared")
	}

	cb, _ := e.signIn(t, e.keyB)
	_ = e.st.Operator().SetTenantDisabled(ctx, e.b.ID, true)
	if res, _ := e.get("/", cb); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("disabled tenant still has a session: %d", res.StatusCode)
	}
}

func TestCSRFOnLoginAndLogout(t *testing.T) {
	e := newEnv(t)
	// Login POST without the CSRF cookie/field pair (a cross-site form post).
	form := url.Values{"csrf": {"x"}, "key": {e.keyA}}
	r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if res := e.do(r); res.StatusCode != http.StatusForbidden {
		t.Fatalf("login without csrf: %d", res.StatusCode)
	}

	c, tok := e.signIn(t, e.keyA)
	post := func(csrf string) *http.Response {
		r := httptest.NewRequest("POST", "/logout", strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(c)
		return e.do(r)
	}
	if res := post("wrong"); res.StatusCode != http.StatusForbidden {
		t.Fatalf("logout with wrong csrf: %d", res.StatusCode)
	}
	if res := post(tok); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", res.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	c, _ := e.signIn(t, e.keyA)
	for _, p := range []string{"/login", "/", "/static/app.css"} {
		res, _ := e.get(p, c)
		h := res.Header
		csp := h.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s CSP %q", p, csp)
		}
		if h.Get("X-Frame-Options") != "DENY" || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("Referrer-Policy") != "no-referrer" || h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s headers %v", p, h)
		}
	}
	// No inline script or style anywhere: the CSP would block it, so it would be a bug.
	_, body := e.get("/", c)
	if strings.Contains(body, "<script") || strings.Contains(body, "style=") || strings.Contains(body, "<style") {
		t.Fatal("inline script/style in page")
	}
}

func TestSignInRateLimited(t *testing.T) {
	e := newEnv(t)
	limited := false
	for i := 0; i < 8; i++ {
		r := httptest.NewRequest("POST", "/login", strings.NewReader("key=x&csrf=y"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if e.do(r).StatusCode == http.StatusTooManyRequests {
			limited = true
		}
	}
	if !limited {
		t.Fatal("8 rapid sign-ins from one IP were not rate limited")
	}
}

func TestRateLimitKeysOnProxiedClientIP(t *testing.T) {
	e := newEnv(t)
	e.d.TrustProxy = true
	post := func(xff string) int {
		r := httptest.NewRequest("POST", "/login", strings.NewReader("key=x&csrf=y"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Forwarded-For", xff)
		return e.do(r).StatusCode
	}
	for i := 0; i < 6; i++ {
		post("6.6.6.6, 198.51.100.1") // attacker rotates the spoofable first entry
	}
	if post("7.7.7.7, 198.51.100.1") != http.StatusTooManyRequests {
		t.Fatal("limiter keyed on the client-controlled XFF entry")
	}
	if post("198.51.100.2") == http.StatusTooManyRequests {
		t.Fatal("a different client behind the proxy was limited")
	}
}

func TestShortSessionKeyRefused(t *testing.T) {
	if _, err := (&Dashboard{SessionKey: []byte("short")}).Handler(); err == nil {
		t.Fatal("accepted a short session key")
	}
}
