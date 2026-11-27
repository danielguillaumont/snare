package store

import (
	"context"
	"database/sql"
	"encoding/json"
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
		tok = s.openToken(t)
	}
	e.TenantID = tok.TenantID
	if found && tok.Kind == KindHeartbeat { // a heartbeat stops here (M11 §1)
		if err := recordBeat(ctx, tx, tok.TenantID, e); err != nil {
			return Token{}, Event{}, false, false, err
		}
		if err := tx.Commit(); err != nil {
			return Token{}, Event{}, false, false, err
		}
		return tok, Event{TenantID: tok.TenantID, TokenID: e.TokenID, Channel: e.Channel, At: e.At}, true, false, nil
	}
	if found && tok.Disabled { // recorded for the trail, never alerted (M4e §1)
		e.Muted = true
		alert = false
	}
	e.Status = StatusOpen
	e.Layer, e.Stage = Classify(tok.Kind, e.Via)
	if len(e.Session) > maxSession {
		e.Session = e.Session[:maxSession]
	}
	if e.Containment != ContainBlocked && e.Containment != ContainFrozen {
		e.Containment = ""
	}
	if len(e.Inputs) > MaxInputs {
		e.Inputs = e.Inputs[len(e.Inputs)-MaxInputs:]
	}
	var inputs []byte
	if len(e.Inputs) > 0 {
		inputs, _ = json.Marshal(e.Inputs)
	}
	key := incidentKey(e)
	if e.IncidentID, err = joinIncident(ctx, tx, e, key); err != nil {
		return Token{}, Event{}, false, false, err
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO events (tenant_id, token_id, channel, source_ip, detail, at, prev_key, muted, layer, stage, session_id, incident_key, incident_id, containment, inputs)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TenantID, e.TokenID, e.Channel, e.SourceIP, e.Detail, e.At.UnixMilli(), e.PreviousKey, e.Muted,
		e.Layer, e.Stage, e.Session, key, e.IncidentID, e.Containment, string(inputs))
	if err != nil {
		return Token{}, Event{}, false, false, err
	}
	e.ID, _ = res.LastInsertId()
	if e.IncidentID == 0 { // the first touch names the incident
		e.IncidentID = e.ID
		if _, err := tx.ExecContext(ctx, `UPDATE events SET incident_id = ? WHERE id = ?`, e.ID, e.ID); err != nil {
			return Token{}, Event{}, false, false, err
		}
	}

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
type Outbox struct {
	db *sql.DB
	st *Store
}

func (s *Store) Outbox() *Outbox { return &Outbox{db: s.db, st: s} }

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
	return o.st.openToken(tok), ev, true, nil
}

// RelatedTouch is an earlier touch of a different tripwire correlated with a touch.
type RelatedTouch struct {
	EventID int64
	TokenID string
	Kind    string
	Label   string
	Stage   string
	At      time.Time
}

// Related correlates event ev with the events recorded before it (M7 §3): its incident's
// earlier touches, plus the same source's touches in the tenant during the window before
// it, which was the whole rule before M7. The session id comes from the callback, so it
// can join touches but never hide one: a fresh session per touch still correlates by IP.
// Events recorded before M7 (IncidentID 0) get the source rule alone, so a re-export of an
// old finding doesn't change. Only events recorded before ev count, so the answer is the
// same on every retry of a delivery.
func (o *Outbox) Related(ctx context.Context, ev Event, window time.Duration, limit int) (Correlation, error) {
	return related(ctx, o.st, ev, window, limit)
}

// RelatedTouches is Related for one of this tenant's own events. ev must belong to the
// tenant; the query is scoped to the tenant either way.
func (v *tenantView) RelatedTouches(ctx context.Context, ev Event, window time.Duration, limit int) (Correlation, error) {
	if ev.TenantID != v.tid { // the query below filters on tenant_id = ev.TenantID
		return Correlation{}, ErrNotFound
	}
	return related(ctx, v.st, ev, window, limit)
}

func related(ctx context.Context, st *Store, ev Event, window time.Duration, limit int) (Correlation, error) {
	const cols = `SELECT e.id, e.token_id, e.at, e.stage, COALESCE(t.kind, 'unknown'), COALESCE(t.label, '(unregistered token)')
		   FROM events e LEFT JOIN tokens t ON t.id = e.token_id AND t.tenant_id = e.tenant_id`
	rows, err := st.db.QueryContext(ctx, cols+`
		  WHERE e.tenant_id = ? AND e.id < ?
		    AND ((? != 0 AND e.incident_id = ?) OR (e.source_ip = ? AND e.at >= ?))
		  ORDER BY e.id DESC LIMIT 1000`,
		ev.TenantID, ev.ID, ev.IncidentID, ev.IncidentID, ev.SourceIP, ev.At.Add(-window).UnixMilli())
	if err != nil {
		return Correlation{}, err
	}
	defer rows.Close()
	c := Correlation{Touches: 1}
	seen := map[string]bool{ev.TokenID: true}
	stages := map[string]bool{ev.Stage: true}
	for rows.Next() {
		var r RelatedTouch
		var ms int64
		if err := rows.Scan(&r.EventID, &r.TokenID, &ms, &r.Stage, &r.Kind, &r.Label); err != nil {
			return Correlation{}, err
		}
		c.Touches++
		stages[r.Stage] = true
		if seen[r.TokenID] {
			continue
		}
		seen[r.TokenID] = true
		r.Label = st.openField(ev.TenantID, r.TokenID, "label", r.Label, LabelUnreadable)
		r.At = time.UnixMilli(ms).UTC()
		if len(c.Related) < limit {
			c.Related = append(c.Related, r)
		}
	}
	c.Tripwires, c.Stages = len(seen), sortStages(stages)
	return c, rows.Err()
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
