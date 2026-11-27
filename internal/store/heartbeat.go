package store

// Heartbeats (docs/M11-heartbeat.md): synthetic touches that prove a path works. They go
// through RecordHit like any touch and stop there: a record per tenant and channel, never an
// event, an incident or an alert.

import (
	"context"
	"database/sql"
	"time"
)

// KindHeartbeat is the token kind whose touches are heartbeats.
const KindHeartbeat = "heartbeat"

// KindExposure is the token kind a gateway touches when a honey value reaches the agent in a
// tool result (docs/M16-early-warning.md). Its touches are warnings: recorded, part of the
// incident, never alerted on their own.
const KindExposure = "exposure_signal"

// KindIntegrity is the token kind a gateway touches when a real tool's definition changed
// under the same name (docs/M17-tool-integrity.md). Its touches are warnings too.
const KindIntegrity = "integrity_signal"

// IsWarningKind reports whether touches of a token kind are warnings: recorded and
// correlated, never alerted on their own.
func IsWarningKind(kind string) bool { return kind == KindExposure || kind == KindIntegrity }

// Heartbeat channels.
const (
	BeatHTTP    = "http"
	BeatDNS     = "dns"
	BeatGateway = "gateway"
)

// Heartbeat is the latest heartbeat on one channel for one tenant.
type Heartbeat struct {
	Channel    string    `json:"channel"`
	LastAt     time.Time `json:"last_at"`
	Count      int64     `json:"count"`
	LastSource string    `json:"last_source"`
}

const heartbeatSchema = `
CREATE TABLE IF NOT EXISTS heartbeats (
  tenant_id   TEXT NOT NULL,
  channel     TEXT NOT NULL,
  last_at     INTEGER NOT NULL,
  count       INTEGER NOT NULL DEFAULT 0,
  last_source TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, channel)
);`

// beatChannel names the path a heartbeat proves. Only gateways send a session, so a beat
// with one came through a gateway; otherwise it is the listener's channel.
func beatChannel(e Event) string {
	if e.Session != "" {
		return BeatGateway
	}
	if e.Channel == BeatDNS {
		return BeatDNS
	}
	return BeatHTTP
}

// recordBeat updates the tenant's heartbeat for e's channel. It runs in RecordHit's
// transaction. The source is the session for gateway beats, else the source IP.
func recordBeat(ctx context.Context, tx *sql.Tx, tenant string, e Event) error {
	src := e.SourceIP
	if e.Session != "" {
		src = truncateTo(e.Session, maxSession)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO heartbeats (tenant_id, channel, last_at, count, last_source)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT (tenant_id, channel) DO UPDATE SET
		  last_at = max(last_at, excluded.last_at), count = count + 1, last_source = excluded.last_source`,
		tenant, beatChannel(e), e.At.UnixMilli(), src)
	return err
}

func truncateTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ListHeartbeats returns the tenant's heartbeats, by channel.
func (v *tenantView) ListHeartbeats(ctx context.Context) ([]Heartbeat, error) {
	rows, err := v.db.QueryContext(ctx,
		`SELECT channel, last_at, count, last_source FROM heartbeats WHERE tenant_id = ? ORDER BY channel`, v.tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Heartbeat
	for rows.Next() {
		var h Heartbeat
		var ms int64
		if err := rows.Scan(&h.Channel, &ms, &h.Count, &h.LastSource); err != nil {
			return nil, err
		}
		h.LastAt = time.UnixMilli(ms).UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}

// LatestHeartbeats returns, per channel, the newest heartbeat across all tenants. It is for
// the operator's metrics, which carry no tenant label.
func (s *Store) LatestHeartbeats(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT channel, max(last_at) FROM heartbeats GROUP BY channel`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var ch string
		var ms int64
		if err := rows.Scan(&ch, &ms); err != nil {
			return nil, err
		}
		out[ch] = time.UnixMilli(ms).UTC()
	}
	return out, rows.Err()
}

// BeatPolicy says which channels should be beating and when one is stale.
type BeatPolicy struct {
	Expected   []string      // channels the server probes; a gateway channel is expected once seen
	StaleAfter time.Duration // 0: DefaultStaleAfter
}

// DefaultStaleAfter is three missed 15-minute gateway beats.
const DefaultStaleAfter = 45 * time.Minute

// Beat states.
const (
	BeatOK    = "ok"
	BeatStale = "stale"
	BeatNever = "never"
)

// BeatState is one channel's status at a moment.
type BeatState struct {
	Heartbeat
	State      string `json:"state"`
	AgeSeconds int64  `json:"age_seconds"` // -1 when never seen
}

func (p BeatPolicy) staleAfter() time.Duration {
	if p.StaleAfter > 0 {
		return p.StaleAfter
	}
	return DefaultStaleAfter
}

// Status rates each seen or expected channel, in a fixed order: http, dns, gateway.
func (p BeatPolicy) Status(hs []Heartbeat, now time.Time) []BeatState {
	seen := map[string]Heartbeat{}
	for _, h := range hs {
		seen[h.Channel] = h
	}
	want := map[string]bool{}
	for _, c := range p.Expected {
		want[c] = true
	}
	var out []BeatState
	for _, c := range []string{BeatHTTP, BeatDNS, BeatGateway} {
		h, ok := seen[c]
		switch {
		case ok:
			age := now.Sub(h.LastAt)
			if age < 0 {
				age = 0
			}
			st := BeatState{Heartbeat: h, State: BeatOK, AgeSeconds: int64(age / time.Second)}
			if age > p.staleAfter() {
				st.State = BeatStale
			}
			out = append(out, st)
		case want[c]:
			out = append(out, BeatState{Heartbeat: Heartbeat{Channel: c}, State: BeatNever, AgeSeconds: -1})
		}
	}
	return out
}
