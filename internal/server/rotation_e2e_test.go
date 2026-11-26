package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/alert"
)

// M4c §5 exit: a tripwire minted under the old key still alerts after rotation, marked so it
// can be replanted; with the old key dropped, it no longer verifies.
func TestKeyRotationEndToEnd(t *testing.T) {
	secret := []byte("0123456789abcdef-webhook")
	alerts := make(chan alert.Alert, 10)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var a alert.Alert
		_ = json.Unmarshal(body, &a)
		alerts <- a
	}))
	defer hook.Close()

	oldKey, newKey := bytes.Repeat([]byte{11}, 32), bytes.Repeat([]byte{12}, 32)
	adminKey := "test-admin-key-0123456789abcdef"
	db := filepath.Join(t.TempDir(), "snare.db")
	cfg := func(key []byte, previous ...[]byte) Config {
		return Config{Key: key, PreviousKeys: previous, AdminKey: []byte(adminKey), HTTPAddr: "127.0.0.1:0",
			AdminAddr: "127.0.0.1:0", PublicURL: "http://cb.test", DBPath: db, WebhookURL: hook.URL, WebhookSecret: secret}
	}
	quietLog := slog.New(slog.NewTextHandler(io.Discard, nil))
	touch := func(s *Server, tok string) {
		resp, err := http.Get("http://" + s.HTTPAddr + "/v1/" + tok)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	next := func(what string) alert.Alert {
		select {
		case a := <-alerts:
			return a
		case <-time.After(5 * time.Second):
			t.Fatalf("no alert for %s", what)
		}
		return alert.Alert{}
	}

	// Before rotation: mint under the old key.
	s1, err := Start(cfg(oldKey), quietLog)
	if err != nil {
		t.Fatal(err)
	}
	var old admin.MintResponse
	adminCall(t, "POST", "http://"+s1.AdminAddr+"/api/tokens", adminKey, admin.MintRequest{Kind: "canary_url", Label: "planted before rotation"}, &old)
	s1.Shutdown(context.Background())

	// Rotated: new current key, old key kept as previous.
	s2, err := Start(cfg(newKey, oldKey), quietLog)
	if err != nil {
		t.Fatal(err)
	}
	var fresh admin.MintResponse
	adminCall(t, "POST", "http://"+s2.AdminAddr+"/api/tokens", adminKey, admin.MintRequest{Kind: "canary_url", Label: "planted after rotation"}, &fresh)
	touch(s2, old.Token)
	a := next("old token")
	if a.Unmapped.TokenID != old.ID || !a.Unmapped.VerifiedByPreviousKey {
		t.Fatalf("old token after rotation: %+v", a.Unmapped)
	}
	touch(s2, fresh.Token)
	if a := next("new token"); a.Unmapped.TokenID != fresh.ID || a.Unmapped.VerifiedByPreviousKey {
		t.Fatalf("new token: %+v", a.Unmapped)
	}
	var evs []struct {
		TokenID     string `json:"token_id"`
		PreviousKey bool   `json:"previous_key"`
	}
	adminCall(t, "GET", "http://"+s2.AdminAddr+"/api/events?token="+old.ID, adminKey, nil, &evs)
	if len(evs) != 1 || !evs[0].PreviousKey {
		t.Fatalf("stored event %+v", evs)
	}
	s2.Shutdown(context.Background())

	// Old key dropped: the old token is noise now.
	s3, err := Start(cfg(newKey), quietLog)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Shutdown(context.Background())
	touch(s3, old.Token)
	select {
	case a := <-alerts:
		t.Fatalf("token under a dropped key alerted: %+v", a.Unmapped)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestPreviousKeysFromEnv(t *testing.T) {
	k := func(b byte) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	t.Setenv("SNARE_KEY", k(1))
	t.Setenv("SNARE_ADMIN_KEY", "test-admin-key-0123456789abcdef")
	for _, c := range []struct {
		env  string
		want int
		err  string
	}{
		{"", 0, ""},
		{k(2), 1, ""},
		{k(2) + ", " + k(3), 2, ""},
		{"zz", 0, "SNARE_KEY_PREVIOUS"},
		{k(2) + "," + k(3) + "," + k(4) + "," + k(5), 0, "SNARE_KEY_PREVIOUS"},
		{k(1), 0, "SNARE_KEY_PREVIOUS"}, // same as current
	} {
		t.Setenv("SNARE_KEY_PREVIOUS", c.env)
		cfg, err := FromEnv()
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%q: err %v", c.env, err)
			}
			continue
		}
		if err != nil || len(cfg.PreviousKeys) != c.want {
			t.Errorf("%q: %d keys, err %v", c.env, len(cfg.PreviousKeys), err)
		}
	}
}
