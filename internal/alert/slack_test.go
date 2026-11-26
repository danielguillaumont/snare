package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielguillaumont/snare/internal/egress"
)

func TestSlackWireFormatAndEscaping(t *testing.T) {
	var c captured
	ts := httptest.NewServer(c.handler(200))
	defer ts.Close()
	a := sampleAlert()
	// Attacker-controlled detail tries a mass mention and a disguised link.
	a.Unmapped.Detail = "GET /x ua=<!channel> <https://evil.example|click here> & more"
	if err := (SlackSink{URL: ts.URL + "/services/T0/B0/xyz"}).Send(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	r := c.reqs[0]
	if r.Method != http.MethodPost || r.URL.Path != "/services/T0/B0/xyz" || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%s %s %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
	}
	body := c.body[0]
	var msg struct {
		Text   string           `json:"text"`
		Blocks []map[string]any `json:"blocks"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Text, a.Unmapped.Label) || len(msg.Blocks) != 3 {
		t.Fatalf("message %s", body)
	}
	decoded := mustDecode(t, body) // the raw JSON escapes "<", so check the text Slack will read
	for _, bad := range []string{"<!channel>", "<https://evil.example|"} {
		if bytes.Contains(decoded, []byte(bad)) {
			t.Fatalf("unescaped Slack control sequence %q in %s", bad, body)
		}
	}
	if !strings.Contains(string(decoded), "&lt;!channel&gt;") {
		t.Fatalf("detail not escaped: %s", body)
	}
	if !bytes.Contains(body, []byte(a.FindingInfo.UID)) {
		t.Fatal("finding uid missing")
	}
}

func TestSlackErrorsNeverEchoTheURL(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("no_service"))
	}))
	defer bad.Close()
	u := bad.URL + "/services/T0/B0/SECRETPART"
	err := (SlackSink{URL: u}).Send(context.Background(), sampleAlert())
	if err == nil || strings.Contains(err.Error(), "SECRETPART") || !strings.Contains(err.Error(), "404") {
		t.Fatalf("error %v", err)
	}
}

func TestSlackConfigValidateAndPublic(t *testing.T) {
	ctx := context.Background()
	p := egress.Policy{AllowPrivate: true} // host checks below must not depend on DNS
	for _, u := range []string{
		"http://hooks.slack.com/services/T/B/x",           // not https
		"https://hooks.slack.com.evil.example/services/x", // suffix trick
		"https://evil.example/services/T/B/x",             // other host
		"https://hooks.slack.com/api/x",                   // not an incoming webhook path
		"https://user@hooks.slack.com/services/T/B/x",     // userinfo
		"",
	} {
		if err := (SinkConfig{Type: "slack", URL: u}).Validate(ctx, p); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
	if err := validSlackURL("https://hooks.slack.com/services/T00/B00/abc"); err != nil {
		t.Fatal(err)
	}
	pub, _ := json.Marshal(SinkConfig{Type: "slack", URL: "https://hooks.slack.com/services/T00/B00/SECRETPART"}.Public())
	if bytes.Contains(pub, []byte("SECRETPART")) {
		t.Fatalf("Public() leaks the webhook URL: %s", pub)
	}
}

// mustDecode re-encodes the JSON body without HTML escaping, so the text reads as Slack sees it.
func mustDecode(t *testing.T, body []byte) []byte {
	t.Helper()
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return b.Bytes()
}
