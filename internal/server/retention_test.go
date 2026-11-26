package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielguillaumont/snare/internal/metrics"
	"github.com/danielguillaumont/snare/internal/store"
)

func TestEventRetentionFromEnv(t *testing.T) {
	t.Setenv("SNARE_KEY", hex.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv("SNARE_ADMIN_KEY", "test-admin-key-0123456789abcdef")
	for _, c := range []struct {
		env  string
		want time.Duration
		ok   bool
	}{
		{"", 0, true},
		{"0", 0, true},
		{"30", 30 * 24 * time.Hour, true},
		{" 7 ", 7 * 24 * time.Hour, true},
		{"-1", 0, false},
		{"30d", 0, false},
		{"1.5", 0, false},
		{"99999999999", 0, false},
	} {
		t.Setenv("SNARE_EVENT_RETENTION", c.env)
		cfg, err := FromEnv()
		if !c.ok {
			if err == nil || !strings.Contains(err.Error(), "SNARE_EVENT_RETENTION") {
				t.Errorf("%q: accepted (err %v)", c.env, err)
			}
			continue
		}
		if err != nil || cfg.EventRetention != c.want {
			t.Errorf("%q: %v, err %v", c.env, cfg.EventRetention, err)
		}
	}
}

func TestRetentionRunCountsAndZeroDoesNothing(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "snare.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	v := st.Tenant(store.DefaultTenant)
	_ = v.CreateToken(ctx, store.Token{ID: "tok_1", Kind: "canary_url", Label: "l"})
	for i := 0; i < 3; i++ {
		_, ev, _, _, _ := st.RecordHit(ctx, store.Event{TokenID: "tok_1", Channel: "http", SourceIP: "192.0.2.1", At: time.Now().Add(-48 * time.Hour)}, false)
		if i < 2 {
			_ = v.TriageEvent(ctx, ev.ID, store.StatusResolved, "")
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Retention 0: the loop never starts and the gauge reads 0.
	reg0 := metrics.New()
	off := newRetention(st, 0, reg0, log)
	off.start()
	off.close()
	var b bytes.Buffer
	reg0.Write(&b)
	if !strings.Contains(b.String(), "snare_events_open_expired 0") {
		t.Fatalf("gauge with retention off:\n%s", b.String())
	}

	reg := metrics.New()
	r := newRetention(st, 24*time.Hour, reg, log)
	r.run(time.Now())
	if got := r.purged.Value(); got != 2 {
		t.Fatalf("purged counter %v, want 2", got)
	}
	b.Reset()
	reg.Write(&b)
	if !strings.Contains(b.String(), "snare_events_open_expired 1") {
		t.Fatalf("open expired gauge:\n%s", b.String())
	}
}
