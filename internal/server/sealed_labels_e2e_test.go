package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/admin"
	"github.com/danielguillaumont/snare/internal/alert"
)

// M4d §2 exit: with a seal key, a tripwire's label never reaches the database file in the
// clear, and its alert still carries the real label.
func TestSealedLabelsEndToEnd(t *testing.T) {
	alerts := make(chan alert.Alert, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var a alert.Alert
		_ = json.Unmarshal(body, &a)
		alerts <- a
	}))
	defer hook.Close()

	adminKey := "test-admin-key-0123456789abcdef"
	db := filepath.Join(t.TempDir(), "snare.db")
	s, err := Start(Config{Key: bytes.Repeat([]byte{21}, 32), AdminKey: []byte(adminKey),
		SealKey: bytes.Repeat([]byte{22}, 32), HTTPAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:0",
		PublicURL: "http://cb.test", DBPath: db, WebhookURL: hook.URL,
		WebhookSecret: []byte("0123456789abcdef-webhook")}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	const label, memo = "payments-repo/.env: LEDGER_API_TOKEN", "planted in sprint 41"
	var m admin.MintResponse
	adminCall(t, "POST", "http://"+s.AdminAddr+"/api/tokens", adminKey, admin.MintRequest{Kind: "canary_url", Label: label, Memo: memo}, &m)
	resp, err := http.Get("http://" + s.HTTPAddr + "/v1/" + m.Token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	select {
	case a := <-alerts:
		if a.Unmapped.TokenID != m.ID || a.Unmapped.Label != label || a.Unmapped.Memo != memo {
			t.Fatalf("alert: %+v", a.Unmapped)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no alert")
	}
	s.Shutdown(context.Background())

	// The database, including any WAL left behind, holds the token id but not the label.
	var raw []byte
	files, _ := filepath.Glob(db + "*")
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, b...)
	}
	if !bytes.Contains(raw, []byte(m.ID)) {
		t.Fatal("sanity: token id not found in the database files")
	}
	for _, secret := range []string{label, "LEDGER_API_TOKEN", memo} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("%q is in the database file in plaintext", secret)
		}
	}
}
