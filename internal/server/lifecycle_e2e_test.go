package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/alert"
	"github.com/danielguillaumont/snare/internal/store"
)

// M4e §1 and §2 exit, end to end: a disabled tripwire records its touch without alerting,
// re-enabling restores alerts, triage changes the exported OCSF status, and both actions
// are in the audit log.
func TestTripwireLifecycleEndToEnd(t *testing.T) {
	alerts := make(chan alert.Alert, 8)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var a alert.Alert
		_ = json.Unmarshal(body, &a)
		alerts <- a
	}))
	defer hook.Close()
	adminKey := "test-admin-key-0123456789abcdef"
	s, err := Start(Config{Key: bytes.Repeat([]byte{41}, 32), AdminKey: []byte(adminKey),
		HTTPAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0", PublicURL: "http://cb.test",
		DBPath: filepath.Join(t.TempDir(), "snare.db"), WebhookURL: hook.URL,
		WebhookSecret: []byte("0123456789abcdef-webhook"), DedupWindow: time.Nanosecond},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	base := "http://" + s.AdminAddr

	var m admin.MintResponse
	adminCall(t, "POST", base+"/api/tokens", adminKey, admin.MintRequest{Kind: "canary_url", Label: "removed fixture"}, &m)
	touch := func(src string) {
		req, _ := http.NewRequest("GET", "http://"+s.HTTPAddr+"/v1/"+m.Token, nil)
		req.Header.Set("User-Agent", src)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	if code := adminCall(t, "POST", base+"/api/tokens/"+m.ID+"/disable", adminKey, nil, nil); code != 204 {
		t.Fatalf("disable: %d", code)
	}
	touch("while-disabled")
	select {
	case a := <-alerts:
		t.Fatalf("disabled tripwire alerted: %+v", a.Unmapped)
	case <-time.After(400 * time.Millisecond):
	}
	var evs []store.Event
	adminCall(t, "GET", base+"/api/events?token="+m.ID, adminKey, nil, &evs)
	if len(evs) != 1 || !evs[0].Muted {
		t.Fatalf("muted touch not recorded: %+v", evs)
	}
	muted := evs[0].ID

	adminCall(t, "POST", base+"/api/tokens/"+m.ID+"/enable", adminKey, nil, nil)
	touch("after-enable")
	select {
	case a := <-alerts:
		if a.Unmapped.TokenID != m.ID || a.StatusID != 1 {
			t.Fatalf("alert after enable: %+v status %d", a.Unmapped, a.StatusID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("re-enabled tripwire did not alert")
	}

	adminCall(t, "GET", base+"/api/events?token="+m.ID+"&status=open", adminKey, nil, &evs)
	if len(evs) != 2 {
		t.Fatalf("open events: %+v", evs)
	}
	live := evs[0].ID
	if code := adminCall(t, "POST", base+"/api/events/"+strconv.FormatInt(live, 10)+"/triage", adminKey,
		admin.TriageRequest{Status: store.StatusFalsePositive, Note: "our own scanner"}, nil); code != 204 {
		t.Fatalf("triage: %d", code)
	}
	if code := adminCall(t, "POST", base+"/api/events/"+strconv.FormatInt(live, 10)+"/triage", adminKey,
		admin.TriageRequest{Status: "closed"}, nil); code != 400 {
		t.Fatalf("bad status: %d", code)
	}
	if code := adminCall(t, "GET", base+"/api/events?status=closed", adminKey, nil, nil); code != 400 {
		t.Fatalf("bad filter: %d", code)
	}

	// Export: the muted touch is Suppressed, the false positive Resolved.
	req, _ := http.NewRequest("GET", base+"/api/events/export", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := map[int64]alert.Alert{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var a alert.Alert
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		got[a.Unmapped.EventID] = a
	}
	if a := got[muted]; a.StatusID != 3 || a.StatusDetail != "muted" {
		t.Fatalf("muted export: %d %q", a.StatusID, a.StatusDetail)
	}
	if a := got[live]; a.StatusID != 4 || a.StatusDetail != store.StatusFalsePositive {
		t.Fatalf("triaged export: %d %q", a.StatusID, a.StatusDetail)
	}

	var audit []store.AuditEntry
	adminCall(t, "GET", base+"/api/audit", adminKey, nil, &audit)
	seen := map[string]bool{}
	for _, e := range audit {
		seen[e.Action] = true
	}
	for _, act := range []string{store.ActTokenDisable, store.ActTokenEnable, store.ActEventTriage} {
		if !seen[act] {
			t.Errorf("audit log missing %s", act)
		}
	}
}

