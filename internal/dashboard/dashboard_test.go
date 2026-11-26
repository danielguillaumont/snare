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
	"strconv"
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

// A source that touches two of A's tripwires shows as critical, and a dead delivery to A's
// sink shows as undelivered, on A's pages only. B's touch from the same IP never counts.
func TestCriticalTouchesAndUndeliveredAlerts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	va := e.st.Tenant(e.a.ID)
	_ = va.CreateToken(ctx, store.Token{ID: "tok_a2", Kind: "decoy_tool", Label: "acme second"})
	_, _, _, _, _ = e.st.RecordHit(ctx, store.Event{TokenID: "tok_b", Channel: "http", SourceIP: "203.0.113.5", At: time.Now()}, false)
	c, _ := e.signIn(t, e.keyA)
	if _, body := e.get("/", c); strings.Contains(body, "critical") {
		t.Fatal("one tripwire per tenant must not be critical (B's touch from the same IP counted?)")
	}
	_, _, _, _, _ = e.st.RecordHit(ctx, store.Event{TokenID: "tok_a2", Channel: "http", SourceIP: "203.0.113.5", At: time.Now()}, true)
	_ = va.CreateSink(ctx, store.SinkRecord{ID: "sk_acme", Type: "webhook", Config: []byte("x")})
	ob := e.st.Outbox()
	due, _ := ob.Due(ctx, time.Now().Add(time.Minute), 10)
	_ = ob.Expand(ctx, due[0], []string{"sk_acme"}, time.Now())
	rows, _ := va.ListDeliveries(ctx, "", 10)
	_ = ob.MarkFailed(ctx, rows[0].ID, 20, time.Now(), "connection refused", true, time.Now())

	_, body := e.get("/", c)
	for _, want := range []string{"critical · 2 tripwires", `<b>1</b> open critical`, `<b>1</b> undelivered`} {
		if !strings.Contains(body, want) {
			t.Fatalf("overview lacks %q", want)
		}
	}
	_, body = e.get("/sinks", c)
	if !strings.Contains(body, "undelivered") || !strings.Contains(body, "connection refused") {
		t.Fatal("sinks page doesn't show the dead delivery")
	}
	cb, _ := e.signIn(t, e.keyB)
	if _, body := e.get("/", cb); strings.Contains(body, "critical") || strings.Contains(body, "undelivered") {
		t.Fatal("B sees A's critical touch or dead delivery")
	}
}

// M4e: triage and disabled state show on the dashboard. A triaged critical touch is no longer
// counted as open, and a tripwire with two false positives suggests moving it.
func TestTriageAndDisabledTripwiresShown(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	va := e.st.Tenant(e.a.ID)
	_ = va.CreateToken(ctx, store.Token{ID: "tok_a2", Kind: "decoy_tool", Label: "acme second"})
	hit := func(tok, ip string) store.Event {
		_, ev, _, _, err := e.st.RecordHit(ctx, store.Event{TokenID: tok, Channel: "http", SourceIP: ip, At: time.Now()}, true)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	critical := hit("tok_a2", "203.0.113.5") // second tripwire from the fixture's source
	c, _ := e.signIn(t, e.keyA)
	if _, body := e.get("/", c); !strings.Contains(body, `<b>1</b> open critical`) {
		t.Fatal("critical touch not shown as open")
	}
	if err := va.TriageEvent(ctx, critical.ID, store.StatusResolved, "contained, host reimaged"); err != nil {
		t.Fatal(err)
	}
	_, body := e.get("/", c)
	if strings.Contains(body, "open critical") || !strings.Contains(body, "resolved") || !strings.Contains(body, "contained, host reimaged") {
		t.Fatal("resolved critical still counted, or its status/note not shown")
	}

	if err := va.SetTokenDisabled(ctx, "tok_a2", true); err != nil {
		t.Fatal(err)
	}
	hit("tok_a2", "198.51.100.7")
	_, body = e.get("/", c)
	if !strings.Contains(body, ">disabled<") || !strings.Contains(body, ">muted<") {
		t.Fatal("disabled tripwire or muted touch not shown")
	}

	for _, ip := range []string{"198.51.100.20", "198.51.100.21"} {
		ev := hit("tok_a", ip)
		_ = va.TriageEvent(ctx, ev.ID, store.StatusFalsePositive, "")
	}
	if _, body := e.get("/tokens/tok_a", c); !strings.Contains(body, "2 touches of this tripwire were marked false positive") {
		t.Fatal("no placement hint after two false positives")
	}
}

func (e *env) post(path string, c *http.Cookie, form url.Values) *http.Response {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c != nil {
		r.AddCookie(c)
	}
	return e.do(r)
}

// M4e §4: admins triage and disable from the page; viewers, missing CSRF and other tenants'
// ids are refused, and what's allowed is audited under the signed-in key.
func TestDashboardAdminActions(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	adminKeyA, ak, _ := e.st.Operator().CreateAPIKey(ctx, e.a.ID, store.RoleAdmin)
	va := e.st.Tenant(e.a.ID)
	evs, _ := va.ListEvents(ctx, "tok_a", 1)
	evA := strconv.FormatInt(evs[0].ID, 10)
	evsB, _ := e.st.Tenant(e.b.ID).ListEvents(ctx, "tok_b", 1)
	evB := strconv.FormatInt(evsB[0].ID, 10)

	adm, csrf := e.signIn(t, adminKeyA)
	_, page := e.get("/tokens/tok_a", adm)
	if !strings.Contains(page, `action="/tokens/tok_a/disable"`) || !strings.Contains(page, `/events/`+evA+`/triage"`) {
		t.Fatal("admin page has no action forms")
	}
	viewer, vcsrf := e.signIn(t, e.keyA)
	if _, vpage := e.get("/tokens/tok_a", viewer); strings.Contains(vpage, "/disable\"") || strings.Contains(vpage, "/triage\"") {
		t.Fatal("viewer page shows action forms")
	}

	for name, c := range map[string]struct {
		path   string
		cookie *http.Cookie
		form   url.Values
		want   int
	}{
		"viewer disable":       {"/tokens/tok_a/disable", viewer, url.Values{"csrf": {vcsrf}}, 403},
		"viewer triage":        {"/tokens/tok_a/events/" + evA + "/triage", viewer, url.Values{"csrf": {vcsrf}, "status": {"resolved"}}, 403},
		"no csrf":              {"/tokens/tok_a/disable", adm, url.Values{}, 403},
		"wrong csrf":           {"/tokens/tok_a/disable", adm, url.Values{"csrf": {vcsrf}}, 403},
		"no session":           {"/tokens/tok_a/disable", nil, url.Values{"csrf": {csrf}}, 303},
		"other tenant token":   {"/tokens/tok_b/disable", adm, url.Values{"csrf": {csrf}}, 404},
		"other tenant event":   {"/tokens/tok_a/events/" + evB + "/triage", adm, url.Values{"csrf": {csrf}, "status": {"resolved"}}, 404},
		"bad status":           {"/tokens/tok_a/events/" + evA + "/triage", adm, url.Values{"csrf": {csrf}, "status": {"closed"}}, 400},
		"non-numeric event id": {"/tokens/tok_a/events/x/triage", adm, url.Values{"csrf": {csrf}, "status": {"resolved"}}, 404},
	} {
		if res := e.post(c.path, c.cookie, c.form); res.StatusCode != c.want {
			t.Errorf("%s: %d, want %d", name, res.StatusCode, c.want)
		}
	}
	if tb, _ := e.st.Tenant(e.b.ID).GetToken(ctx, "tok_b"); tb.Disabled {
		t.Fatal("A's admin disabled B's tripwire")
	}
	if eb, _ := e.st.Tenant(e.b.ID).ListEvents(ctx, "tok_b", 1); eb[0].Status != store.StatusOpen {
		t.Fatal("A's admin triaged B's event")
	}
	if ta, _ := va.GetToken(ctx, "tok_a"); ta.Disabled {
		t.Fatal("a refused request changed state")
	}

	// Allowed: triage, then disable. Each redirects to the tripwire's page.
	res := e.post("/tokens/tok_a/events/"+evA+"/triage", adm, url.Values{"csrf": {csrf}, "status": {"false_positive"}, "note": {"  pentest  "}})
	if res.StatusCode != 303 || res.Header.Get("Location") != "/tokens/tok_a" {
		t.Fatalf("triage: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if res := e.post("/tokens/tok_a/disable", adm, url.Values{"csrf": {csrf}}); res.StatusCode != 303 {
		t.Fatalf("disable: %d", res.StatusCode)
	}
	got, _ := va.ListEvents(ctx, "tok_a", 1)
	if got[0].Status != store.StatusFalsePositive || got[0].TriageNote != "pentest" || got[0].TriagedBy != ak.ID {
		t.Fatalf("triaged event: %+v", got[0])
	}
	if ta, _ := va.GetToken(ctx, "tok_a"); !ta.Disabled {
		t.Fatal("not disabled")
	}
	_, page = e.get("/tokens/tok_a", adm)
	if !strings.Contains(page, `action="/tokens/tok_a/enable"`) {
		t.Fatal("disabled tripwire offers no enable button")
	}
	audit, _ := va.ListAudit(ctx, 20)
	n := 0
	for _, a := range audit {
		if (a.Action == store.ActEventTriage || a.Action == store.ActTokenDisable) && a.Actor == ak.ID {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("audited actions by the admin key: %d, want 2", n)
	}
}
