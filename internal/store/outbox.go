package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Delivery outbox (docs/M4c-reliability.md §1). An alertable hit writes its event and a
// fan-out marker (sink_ref "") in one transaction. A worker expands the marker into one row
// per destination, then delivers each row on its own retry schedule. Rows survive restarts.

const outboxSchema = `
CREATE TABLE IF NOT EXISTS deliveries (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id   INTEGER NOT NULL,
  tenant_id  TEXT NOT NULL,
  sink_ref   TEXT NOT NULL,
  state      TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  next_at    INTEGER NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (event_id, sink_ref)
);
CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries(state, next_at);
CREATE INDEX IF NOT EXISTS deliveries_tenant ON deliveries(tenant_id, id);
`

// Delivery states.
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryDead      = "dead"
)

// MaxPendingDeliveries bounds the outbox. Beyond it, events are still stored but not queued.
var MaxPendingDeliveries = 100_000

type Delivery struct {
	ID        int64     `json:"id"`
	EventID   int64     `json:"event_id"`
	TenantID  string    `json:"-"`
	SinkRef   string    `json:"sink"` // "op:<name>" or a tenant sink id; "" is a fan-out marker
	State     string    `json:"state"`
	Attempts  int       `json:"attempts"`
	NextAt    time.Time `json:"next_at"`
	LastError string    `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsMarker reports whether d still needs to be expanded into per-sink rows.
func (d Delivery) IsMarker() bool { return d.SinkRef == "" }

const deliveryCols = `id, event_id, tenant_id, sink_ref, state, attempts, next_at, last_error, created_at, updated_at`

func scanDeliveries(rows *sql.Rows) ([]Delivery, error) {
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var next, created, updated int64
		if err := rows.Scan(&d.ID, &d.EventID, &d.TenantID, &d.SinkRef, &d.State, &d.Attempts, &next,
			&d.LastError, &created, &updated); err != nil {
			return nil, err
		}
		d.NextAt, d.CreatedAt, d.UpdatedAt = time.UnixMilli(next).UTC(), time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// RecordHit stores an event for a token whose signature the listener has verified. It is the
// one tenant-agnostic write: the listener learns the tenant from the token record. A valid
// token with no record (minted by another instance, or deleted) is stored with no tenant, so
// no tenant ever sees it, and found=false is returned.
//
// When alert is true, a fan-out marker is written in the same transaction, unless the outbox
// is full; queued reports whether it was.
func (s *Store) RecordHit(ctx context.Context, e Event, alert bool) (tok Token, ev Event, found, queued bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Token{}, Event{}, false, false, err
	}
	defer func() { _ = tx.Rollback() }()

	found = true
	t, err := scanToken(tx.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE id = ?`, e.TokenID))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		found = false
	case err != nil:
		return Token{}, Event{}, false, false, err
	default:
		tok = t
	}
	e.TenantID = tok.TenantID
	res, err := tx.ExecContext(ctx,
		`INSERT INTO events (tenant_id, token_id, channel, source_ip, detail, at) VALUES (?, ?, ?, ?, ?, ?)`,
		e.TenantID, e.TokenID, e.Channel, e.SourceIP, e.Detail, e.At.UnixMilli())
	if err != nil {
		return Token{}, Event{}, false, false, err
	}
	e.ID, _ = res.LastInsertId()

	if alert {
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM deliveries WHERE state = ?`, DeliveryPending).Scan(&pending); err != nil {
			return Token{}, Event{}, false, false, err
		}
		if pending < MaxPendingDeliveries {
			now := time.Now().UnixMilli()
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO deliveries (event_id, tenant_id, sink_ref, state, next_at, created_at, updated_at) VALUES (?, ?, '', ?, ?, ?, ?)`,
				e.ID, e.TenantID, DeliveryPending, now, now, now); err != nil {
				return Token{}, Event{}, false, false, err
			}
			queued = true
		}
	}
	if err := tx.Commit(); err != nil {
		return Token{}, Event{}, false, false, err
	}
	return tok, e, found, queued, nil
}

// Outbox is the delivery worker's view of the store. It is cross-tenant by nature, like
// RecordHit; only internal/alert holds one.
type Outbox struct{ db *sql.DB }

func (s *Store) Outbox() *Outbox { return &Outbox{db: s.db} }

// Due returns pending rows whose next attempt is due, markers first, oldest first.
func (o *Outbox) Due(ctx context.Context, now time.Time, limit int) ([]Delivery, error) {
	rows, err := o.db.QueryContext(ctx,
		`SELECT `+deliveryCols+` FROM deliveries WHERE state = ? AND next_at <= ?
		 ORDER BY sink_ref != '', next_at, id LIMIT ?`, DeliveryPending, now.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

// Expand replaces a fan-out marker with one pending row per sink ref, atomically. Expanding a
// marker that is already gone is a no-op.
func (o *Outbox) Expand(ctx context.Context, marker Delivery, refs []string, now time.Time) error {
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM deliveries WHERE id = ? AND sink_ref = ''`, marker.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	ms := now.UnixMilli()
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO deliveries (event_id, tenant_id, sink_ref, state, next_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			marker.EventID, marker.TenantID, ref, DeliveryPending, ms, marker.CreatedAt.UnixMilli(), ms); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MarkDelivered records a successful send.
func (o *Outbox) MarkDelivered(ctx context.Context, id int64, attempts int, now time.Time) error {
	_, err := o.db.ExecContext(ctx,
		`UPDATE deliveries SET state = ?, attempts = ?, last_error = '', updated_at = ? WHERE id = ?`,
		DeliveryDelivered, attempts, now.UnixMilli(), id)
	return err
}

// MarkFailed records a failed attempt: retried at next, or dead when dead is true.
func (o *Outbox) MarkFailed(ctx context.Context, id int64, attempts int, next time.Time, lastErr string, dead bool, now time.Time) error {
	state := DeliveryPending
	if dead {
		state = DeliveryDead
	}
	if len(lastErr) > 300 {
		lastErr = lastErr[:300]
	}
	_, err := o.db.ExecContext(ctx,
		`UPDATE deliveries SET state = ?, attempts = ?, next_at = ?, last_error = ?, updated_at = ? WHERE id = ?`,
		state, attempts, next.UnixMilli(), lastErr, now.UnixMilli(), id)
	return err
}

// AlertData returns what an alert is built from: the event and its token (found=false for an
// unregistered token).
func (o *Outbox) AlertData(ctx context.Context, eventID int64) (Token, Event, bool, error) {
	rows, err := o.db.QueryContext(ctx, `SELECT `+eventCols+` FROM events WHERE id = ?`, eventID)
	if err != nil {
		return Token{}, Event{}, false, err
	}
	evs, err := scanEvents(rows)
	if err != nil {
		return Token{}, Event{}, false, err
	}
	if len(evs) == 0 {
		return Token{}, Event{}, false, ErrNotFound
	}
	ev := evs[0]
	tok, err := scanToken(o.db.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM tokens WHERE id = ?`, ev.TokenID))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ev, false, nil
	}
	if err != nil {
		return Token{}, Event{}, false, err
	}
	return tok, ev, true, nil
}

// RelatedTouch is an earlier touch of a different tripwire by the same source.
type RelatedTouch struct {
	EventID int64
	TokenID string
	Kind    string
	Label   string
	At      time.Time
}

// Related returns, for event ev, the other tripwires the same source touched in the same
// tenant during the window before it: the latest touch of each, newest first, at most limit.
// distinct counts tripwires including ev's own. Only events recorded before ev count, so the
// answer is the same on every retry of a delivery.
func (o *Outbox) Related(ctx context.Context, ev Event, window time.Duration, limit int) (rel []RelatedTouch, distinct int, err error) {
	rows, err := o.db.QueryContext(ctx,
		`SELECT e.id, e.token_id, e.at, COALESCE(t.kind, 'unknown'), COALESCE(t.label, '(unregistered token)')
		   FROM events e LEFT JOIN tokens t ON t.id = e.token_id AND t.tenant_id = e.tenant_id
		  WHERE e.tenant_id = ? AND e.source_ip = ? AND e.id < ? AND e.at >= ? AND e.token_id != ?
		  ORDER BY e.id DESC LIMIT 1000`,
		ev.TenantID, ev.SourceIP, ev.ID, ev.At.Add(-window).UnixMilli(), ev.TokenID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var r RelatedTouch
		var ms int64
		if err := rows.Scan(&r.EventID, &r.TokenID, &ms, &r.Kind, &r.Label); err != nil {
			return nil, 0, err
		}
		if seen[r.TokenID] {
			continue
		}
		seen[r.TokenID] = true
		r.At = time.UnixMilli(ms).UTC()
		if len(rel) < limit {
			rel = append(rel, r)
		}
	}
	return rel, len(seen) + 1, rows.Err()
}

// OutboxStats summarises the outbox for metrics.
type OutboxStats struct {
	Pending, Dead int
	OldestPending time.Duration // 0 when nothing is pending
}

func (o *Outbox) Stats(ctx context.Context, now time.Time) (OutboxStats, error) {
	var st OutboxStats
	var oldest sql.NullInt64
	err := o.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(state = 'pending'), 0), COALESCE(SUM(state = 'dead'), 0),
		        MIN(CASE WHEN state = 'pending' THEN created_at END) FROM deliveries`).Scan(&st.Pending, &st.Dead, &oldest)
	if err != nil {
		return st, err
	}
	if oldest.Valid {
		st.OldestPending = now.Sub(time.UnixMilli(oldest.Int64))
		if st.OldestPending < 0 {
			st.OldestPending = 0
		}
	}
	return st, nil
}

// Purge deletes delivered rows last updated before cutoff.
func (o *Outbox) Purge(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := o.db.ExecContext(ctx, `DELETE FROM deliveries WHERE state = ? AND updated_at < ?`,
		DeliveryDelivered, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------- tenant and operator views

func listDeliveries(ctx context.Context, db *sql.DB, tenantID *string, state string, limit int) ([]Delivery, error) {
	q := `SELECT ` + deliveryCols + ` FROM deliveries WHERE sink_ref != ''`
	var args []any
	if tenantID != nil {
		// Tenants see deliveries to their own sinks, not to the operator's.
		q += ` AND tenant_id = ? AND sink_ref NOT LIKE 'op:%'`
		args = append(args, *tenantID)
	}
	if state != "" {
		q += ` AND state = ?`
		args = append(args, state)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, clampLimit(limit))
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanDeliveries(rows)
}

// retryDelivery requeues a dead delivery and audits it. tenantID nil means any tenant.
func retryDelivery(ctx context.Context, db *sql.DB, tenantID *string, id int64) error {
	q := `SELECT tenant_id, sink_ref FROM deliveries WHERE id = ? AND state = ? AND sink_ref != ''`
	args := []any{id, DeliveryDead}
	if tenantID != nil {
		q += ` AND tenant_id = ? AND sink_ref NOT LIKE 'op:%'`
		args = append(args, *tenantID)
	}
	var tid, ref string
	if err := db.QueryRowContext(ctx, q, args...).Scan(&tid, &ref); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	return inTx(ctx, db, tid, ActDeliveryRetry, fmt.Sprint(id), "sink="+ref, func(tx *sql.Tx) error {
		now := time.Now().UnixMilli()
		res, err := tx.ExecContext(ctx,
			`UPDATE deliveries SET state = ?, attempts = 0, next_at = ?, updated_at = ? WHERE id = ? AND state = ?`,
			DeliveryPending, now, now, id, DeliveryDead)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ListDeliveries returns this tenant's deliveries, newest first; state "" means any.
func (v *tenantView) ListDeliveries(ctx context.Context, state string, limit int) ([]Delivery, error) {
	return listDeliveries(ctx, v.db, &v.tid, state, limit)
}

// RetryDelivery requeues one of this tenant's dead deliveries.
func (v *tenantView) RetryDelivery(ctx context.Context, id int64) error {
	return retryDelivery(ctx, v.db, &v.tid, id)
}

// ListDeliveries returns deliveries across tenants, newest first.
func (o *Operator) ListDeliveries(ctx context.Context, state string, limit int) ([]Delivery, error) {
	return listDeliveries(ctx, o.db, nil, state, limit)
}

// RetryDelivery requeues any dead delivery.
func (o *Operator) RetryDelivery(ctx context.Context, id int64) error {
	return retryDelivery(ctx, o.db, nil, id)
}
