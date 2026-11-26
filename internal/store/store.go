// Package store persists tenants, keys, tokens, events and sink configs in SQLite (pure Go
// driver, no cgo).
//
// Tenant isolation is enforced here (docs/M4-saas.md). Tenant code only ever holds a
// TenantStore, whose every query carries tenant_id = ?. Cross-tenant access exists in exactly
// two places, both named for what they are: Operator (platform administration) and RecordHit
// (a listener sees a token before it knows whose it is).
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/danielguillaumont/snare/internal/seal"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: already exists")
	ErrInvalid  = errors.New("store: invalid value")
)

// DefaultTenant owns everything created before M4 and everything the operator key does on the
// single-team endpoints.
const DefaultTenant = "default"

type Token struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"-"`
	Kind      string    `json:"kind"`  // e.g. decoy_tool, honey_credential, canary_doc, canary_url
	Label     string    `json:"label"` // human description: where it was planted
	Memo      string    `json:"memo,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	// Disabled tripwires still record touches, muted, but don't alert (M4e §1).
	Disabled bool `json:"disabled,omitempty"`
}

type Event struct {
	ID       int64     `json:"id"`
	TenantID string    `json:"-"`
	TokenID  string    `json:"token_id"`
	Channel  string    `json:"channel"` // http | dns
	SourceIP string    `json:"source_ip"`
	Detail   string    `json:"detail"` // user agent + path, or DNS query name and type
	At       time.Time `json:"at"`
	// PreviousKey: the token verified under a retired signing key (M4c §5).
	PreviousKey bool `json:"previous_key,omitempty"`
	// Muted: the tripwire was disabled when touched, so no alert was sent (M4e §1).
	Muted bool `json:"muted,omitempty"`
	// Triage (M4e §2).
	Status     string     `json:"status"`
	TriageNote string     `json:"triage_note,omitempty"`
	TriagedAt  *time.Time `json:"triaged_at,omitempty"`
	TriagedBy  string     `json:"triaged_by,omitempty"`
	// Layer and stage (M7 §1), set by RecordHit from the token's kind and Via.
	Layer string `json:"layer,omitempty"`
	Stage string `json:"stage,omitempty"`
	// Session: the gateway session that reported the touch, if any.
	Session string `json:"session,omitempty"`
	// IncidentID: the id of the incident's first event; 0 for events recorded before M7.
	IncidentID int64 `json:"incident_id,omitempty"`
	// Via is input only: "egress" or "use" when the listener saw how the token arrived.
	Via string `json:"-"`
}

// Triage statuses.
const (
	StatusOpen          = "open"
	StatusAcknowledged  = "acknowledged"
	StatusResolved      = "resolved"
	StatusFalsePositive = "false_positive"
)

// ValidStatus reports whether s is a triage status.
func ValidStatus(s string) bool {
	switch s {
	case StatusOpen, StatusAcknowledged, StatusResolved, StatusFalsePositive:
		return true
	}
	return false
}

// MaxTriageNote bounds a triage note, in bytes.
const MaxTriageNote = 500

// EventFilter narrows ListEventsFiltered. Empty fields match everything.
type EventFilter struct {
	TokenID string
	Status  string
}

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Disabled  bool      `json:"disabled"`
}

// Roles for tenant API keys.
const (
	RoleAdmin  = "admin"  // mint tokens, manage sinks, read everything in the tenant
	RoleViewer = "viewer" // read only
)

type APIKey struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Role       string     `json:"role"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// SinkRecord is one SIEM or webhook destination. Config is sealed by the caller (internal/seal)
// and opaque to the store.
type SinkRecord struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"-"`
	Type      string    `json:"type"`
	Config    []byte    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	db *sql.DB
	// labels seals token labels and memos when set (SealLabels). Nil: stored as written.
	labels atomic.Pointer[seal.Sealer]
}

const schema = `
CREATE TABLE IF NOT EXISTS tenants (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  disabled   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
  id         TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  label      TEXT NOT NULL,
  memo       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  token_id  TEXT NOT NULL,
  channel   TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  detail    TEXT NOT NULL,
  at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL REFERENCES tenants(id),
  role         TEXT NOT NULL,
  hash         TEXT NOT NULL UNIQUE,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at   INTEGER
);
CREATE TABLE IF NOT EXISTS sinks (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL REFERENCES tenants(id),
  type       TEXT NOT NULL,
  config     BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
`

// Columns added in M4. Existing rows belong to the default tenant.
var migrations = []struct{ table, column, ddl string }{
	{"tokens", "tenant_id", `ALTER TABLE tokens ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'`},
	{"events", "tenant_id", `ALTER TABLE events ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''`},
	{"events", "prev_key", `ALTER TABLE events ADD COLUMN prev_key INTEGER NOT NULL DEFAULT 0`},
	// M4e: tripwire lifecycle and triage.
	{"tokens", "disabled_at", `ALTER TABLE tokens ADD COLUMN disabled_at INTEGER`},
	{"events", "muted", `ALTER TABLE events ADD COLUMN muted INTEGER NOT NULL DEFAULT 0`},
	{"events", "status", `ALTER TABLE events ADD COLUMN status TEXT NOT NULL DEFAULT 'open'`},
	{"events", "triage_note", `ALTER TABLE events ADD COLUMN triage_note TEXT NOT NULL DEFAULT ''`},
	{"events", "triaged_at", `ALTER TABLE events ADD COLUMN triaged_at INTEGER`},
	{"events", "triaged_by", `ALTER TABLE events ADD COLUMN triaged_by TEXT NOT NULL DEFAULT ''`},
	{"events", "layer", `ALTER TABLE events ADD COLUMN layer TEXT NOT NULL DEFAULT ''`},
	{"events", "stage", `ALTER TABLE events ADD COLUMN stage TEXT NOT NULL DEFAULT ''`},
	{"events", "session_id", `ALTER TABLE events ADD COLUMN session_id TEXT NOT NULL DEFAULT ''`},
	{"events", "incident_key", `ALTER TABLE events ADD COLUMN incident_key TEXT NOT NULL DEFAULT ''`},
	{"events", "incident_id", `ALTER TABLE events ADD COLUMN incident_id INTEGER NOT NULL DEFAULT 0`},
}

const indexes = `
CREATE INDEX IF NOT EXISTS events_token_at ON events(token_id, at);
CREATE INDEX IF NOT EXISTS tokens_tenant ON tokens(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS events_tenant ON events(tenant_id, id);
CREATE INDEX IF NOT EXISTS sinks_tenant ON sinks(tenant_id);
CREATE INDEX IF NOT EXISTS events_source ON events(tenant_id, source_ip, at);
CREATE INDEX IF NOT EXISTS events_incident_key ON events(tenant_id, incident_key, id);
CREATE INDEX IF NOT EXISTS events_incident ON events(tenant_id, incident_id, id);
`

// Open opens (or creates and migrates) the database. Use ":memory:" in tests.
func Open(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		// synchronous(FULL): a committed event and its queued alert survive power loss, not
		// only a process crash. NORMAL is 4x faster on touches but can drop the last commits
		// (docs/results-bench.md); a touch is an incident, so durability wins.
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; one connection also keeps ":memory:" a single database.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("store: schema: %w", err)
	}
	for _, m := range migrations {
		ok, err := s.hasColumn(m.table, m.column)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := s.db.Exec(m.ddl); err != nil {
				return fmt.Errorf("store: migrate %s.%s: %w", m.table, m.column, err)
			}
		}
	}
	// Events recorded before M4 belong to their token's tenant (default, for old installs).
	if _, err := s.db.Exec(`UPDATE events SET tenant_id = COALESCE((SELECT tenant_id FROM tokens WHERE tokens.id = events.token_id), '') WHERE tenant_id = ''`); err != nil {
		return fmt.Errorf("store: backfill events: %w", err)
	}
	if _, err := s.db.Exec(auditSchema); err != nil {
		return fmt.Errorf("store: audit schema: %w", err)
	}
	if _, err := s.db.Exec(outboxSchema); err != nil {
		return fmt.Errorf("store: outbox schema: %w", err)
	}
	if _, err := s.db.Exec(indexes); err != nil {
		return fmt.Errorf("store: indexes: %w", err)
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO tenants (id, name, created_at) VALUES (?, 'Default', ?)`,
		DefaultTenant, time.Now().UnixMilli())
	return err
}

func (s *Store) hasColumn(table, column string) (bool, error) {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return false, err
		}
		if n == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }

// --------------------------------------------------------------------------- tenant view

// TenantStore is everything tenant-facing code may do. Every method is scoped to one tenant;
// another tenant's object is ErrNotFound, exactly like a missing one. The isolation test
// enumerates this interface by reflection, so a new method can't ship without a cross-tenant
// case.
type TenantStore interface {
	TenantID() string
	CreateToken(ctx context.Context, t Token) error
	GetToken(ctx context.Context, id string) (Token, error)
	ListTokens(ctx context.Context) ([]Token, error)
	ListEvents(ctx context.Context, tokenID string, limit int) ([]Event, error)
	EventsSince(ctx context.Context, since time.Time, limit int) ([]Event, error)
	CreateSink(ctx context.Context, r SinkRecord) error
	ListSinks(ctx context.Context) ([]SinkRecord, error)
	DeleteSink(ctx context.Context, id string) error
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)
	ListDeliveries(ctx context.Context, state string, limit int) ([]Delivery, error)
	RetryDelivery(ctx context.Context, id int64) error
	RelatedTouches(ctx context.Context, ev Event, window time.Duration, limit int) (Correlation, error)
	ListEventsFiltered(ctx context.Context, f EventFilter, limit int) ([]Event, error)
	SetTokenDisabled(ctx context.Context, id string, disabled bool) error
	TriageEvent(ctx context.Context, id int64, status, note string) error
	ListIncidents(ctx context.Context, limit int) ([]Incident, error)
	GetIncident(ctx context.Context, id int64) (Incident, []Event, error)
}

type tenantView struct {
	db  *sql.DB
	tid string
	st  *Store
}

// Tenant returns the view for one tenant. It does not check that the tenant exists; callers
// get a tenant id only from an authenticated key or the operator.
func (s *Store) Tenant(id string) TenantStore { return &tenantView{db: s.db, tid: id, st: s} }

func (v *tenantView) TenantID() string { return v.tid }

func (v *tenantView) CreateToken(ctx context.Context, t Token) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	label, err := v.st.sealField(v.tid, t.ID, "label", t.Label)
	if err != nil {
		return err
	}
	memo, err := v.st.sealField(v.tid, t.ID, "memo", t.Memo)
	if err != nil {
		return err
	}
	_, err = v.db.ExecContext(ctx,
		`INSERT INTO tokens (id, tenant_id, kind, label, memo, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, v.tid, t.Kind, label, memo, t.CreatedAt.UnixMilli())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrConflict
	}
	return err
}

const tokenCols = `id, tenant_id, kind, label, memo, created_at, disabled_at IS NOT NULL`

func scanToken(sc interface{ Scan(...any) error }) (Token, error) {
	var t Token
	var ms int64
	err := sc.Scan(&t.ID, &t.TenantID, &t.Kind, &t.Label, &t.Memo, &ms, &t.Disabled)
	t.CreatedAt = time.UnixMilli(ms).UTC()
	return t, err
}

func (v *tenantView) GetToken(ctx context.Context, id string) (Token, error) {
	t, err := scanToken(v.db.QueryRowContext(ctx,
		`SELECT `+tokenCols+` FROM tokens WHERE id = ? AND tenant_id = ?`, id, v.tid))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	return v.st.openToken(t), err
}

func (v *tenantView) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := v.db.QueryContext(ctx,
		`SELECT `+tokenCols+` FROM tokens WHERE tenant_id = ? ORDER BY created_at DESC, id`, v.tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v.st.openToken(t))
	}
	return out, rows.Err()
}

const eventCols = `id, tenant_id, token_id, channel, source_ip, detail, at, prev_key, muted, status, triage_note, triaged_at, triaged_by, layer, stage, session_id, incident_id`

func scanEvents(rows *sql.Rows) ([]Event, error) {
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ms int64
		var triaged sql.NullInt64
		if err := rows.Scan(&e.ID, &e.TenantID, &e.TokenID, &e.Channel, &e.SourceIP, &e.Detail, &ms, &e.PreviousKey,
			&e.Muted, &e.Status, &e.TriageNote, &triaged, &e.TriagedBy, &e.Layer, &e.Stage, &e.Session, &e.IncidentID); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(ms).UTC()
		if triaged.Valid {
			t := time.UnixMilli(triaged.Int64).UTC()
			e.TriagedAt = &t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func clampLimit(limit int) int {
	if limit <= 0 || limit > 1000 {
		return 100
	}
	return limit
}

// ListEvents returns the most recent events first. tokenID "" means all of the tenant's tokens.
func (v *tenantView) ListEvents(ctx context.Context, tokenID string, limit int) ([]Event, error) {
	return v.ListEventsFiltered(ctx, EventFilter{TokenID: tokenID}, limit)
}

func (v *tenantView) ListEventsFiltered(ctx context.Context, f EventFilter, limit int) ([]Event, error) {
	q := `SELECT ` + eventCols + ` FROM events WHERE tenant_id = ?`
	args := []any{v.tid}
	if f.TokenID != "" {
		q += ` AND token_id = ?`
		args = append(args, f.TokenID)
	}
	if f.Status != "" {
		q += ` AND status = ?`
		args = append(args, f.Status)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, clampLimit(limit))
	rows, err := v.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

// EventsSince returns events at or after since, oldest first (for export and backfill).
func (v *tenantView) EventsSince(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	if limit <= 0 || limit > 10_000 {
		limit = 1000
	}
	rows, err := v.db.QueryContext(ctx,
		`SELECT `+eventCols+` FROM events WHERE tenant_id = ? AND at >= ? ORDER BY at, id LIMIT ?`,
		v.tid, since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}

func (v *tenantView) CreateSink(ctx context.Context, r SinkRecord) error {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	err := inTx(ctx, v.db, v.tid, ActSinkCreate, r.ID, "type="+r.Type, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sinks (id, tenant_id, type, config, created_at) VALUES (?, ?, ?, ?, ?)`,
			r.ID, v.tid, r.Type, r.Config, r.CreatedAt.UnixMilli())
		return err
	})
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrConflict
	}
	return err
}

func (v *tenantView) ListSinks(ctx context.Context) ([]SinkRecord, error) {
	rows, err := v.db.QueryContext(ctx,
		`SELECT id, tenant_id, type, config, created_at FROM sinks WHERE tenant_id = ? ORDER BY created_at, id`, v.tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SinkRecord
	for rows.Next() {
		var r SinkRecord
		var ms int64
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Type, &r.Config, &ms); err != nil {
			return nil, err
		}
		r.CreatedAt = time.UnixMilli(ms).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetTokenDisabled disables or re-enables one of the tenant's tripwires, audited.
// Disabling an already disabled tripwire keeps its original time.
func (v *tenantView) SetTokenDisabled(ctx context.Context, id string, disabled bool) error {
	act, q := ActTokenEnable, `UPDATE tokens SET disabled_at = NULL WHERE id = ? AND tenant_id = ?`
	args := []any{id, v.tid}
	if disabled {
		act = ActTokenDisable
		q = `UPDATE tokens SET disabled_at = COALESCE(disabled_at, ?) WHERE id = ? AND tenant_id = ?`
		args = []any{time.Now().UnixMilli(), id, v.tid}
	}
	return inTx(ctx, v.db, v.tid, act, id, "", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// TriageEvent sets one of the tenant's events' status and note, audited. The audit record
// holds the status and the note's length, not its text.
func (v *tenantView) TriageEvent(ctx context.Context, id int64, status, note string) error {
	if !ValidStatus(status) || len(note) > MaxTriageNote {
		return ErrInvalid
	}
	detail := fmt.Sprintf("status=%s note_bytes=%d", status, len(note))
	return inTx(ctx, v.db, v.tid, ActEventTriage, strconv.FormatInt(id, 10), detail, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE events SET status = ?, triage_note = ?, triaged_at = ?, triaged_by = ? WHERE id = ? AND tenant_id = ?`,
			status, note, time.Now().UnixMilli(), actorFrom(ctx), id, v.tid)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (v *tenantView) DeleteSink(ctx context.Context, id string) error {
	return inTx(ctx, v.db, v.tid, ActSinkDelete, id, "", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM sinks WHERE id = ? AND tenant_id = ?`, id, v.tid)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// --------------------------------------------------------------------------- hit path

// --------------------------------------------------------------------------- operator

// Operator is platform administration: tenants and their keys. Only the operator key reaches it.
type Operator struct{ db *sql.DB }

func (s *Store) Operator() *Operator { return &Operator{db: s.db} }

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randID(prefix string, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return prefix + strings.ToLower(b32.EncodeToString(b))
}

// NewID returns a random id with the given prefix (sinks, tenants, keys).
func NewID(prefix string) string { return randID(prefix, 10) }

// APIKeyPrefix marks Snare tenant API keys. It matches no provider's format; it exists so
// secret scanners can be configured to find leaked Snare keys.
const APIKeyPrefix = "snk_"

// HashKey is how API keys are stored and looked up. Keys carry 160 random bits, so a plain
// SHA-256 is enough (no password-style stretching needed).
func HashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func (o *Operator) CreateTenant(ctx context.Context, name string) (Tenant, error) {
	t := Tenant{ID: NewID("tn_"), Name: name, CreatedAt: time.Now().UTC()}
	err := inTx(ctx, o.db, t.ID, ActTenantCreate, t.ID, "name="+t.Name, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)`, t.ID, t.Name, t.CreatedAt.UnixMilli())
		return err
	})
	return t, err
}

func (o *Operator) GetTenant(ctx context.Context, id string) (Tenant, error) {
	var t Tenant
	var ms int64
	var dis int
	err := o.db.QueryRowContext(ctx, `SELECT id, name, created_at, disabled FROM tenants WHERE id = ?`, id).Scan(&t.ID, &t.Name, &ms, &dis)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	t.CreatedAt, t.Disabled = time.UnixMilli(ms).UTC(), dis != 0
	return t, err
}

func (o *Operator) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := o.db.QueryContext(ctx, `SELECT id, name, created_at, disabled FROM tenants ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		var ms int64
		var dis int
		if err := rows.Scan(&t.ID, &t.Name, &ms, &dis); err != nil {
			return nil, err
		}
		t.CreatedAt, t.Disabled = time.UnixMilli(ms).UTC(), dis != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

func (o *Operator) SetTenantDisabled(ctx context.Context, id string, disabled bool) error {
	d := 0
	if disabled {
		d = 1
	}
	act := ActTenantEnable
	if disabled {
		act = ActTenantDisable
	}
	return inTx(ctx, o.db, id, act, id, "", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE tenants SET disabled = ? WHERE id = ?`, d, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// CreateAPIKey issues a key for a tenant. The plaintext is returned once and never stored.
func (o *Operator) CreateAPIKey(ctx context.Context, tenantID, role string) (string, APIKey, error) {
	if role != RoleAdmin && role != RoleViewer {
		return "", APIKey{}, fmt.Errorf("store: unknown role %q", role)
	}
	if _, err := o.GetTenant(ctx, tenantID); err != nil {
		return "", APIKey{}, err
	}
	plain := randID(APIKeyPrefix, 20)
	k := APIKey{ID: NewID("ak_"), TenantID: tenantID, Role: role, CreatedAt: time.Now().UTC()}
	err := inTx(ctx, o.db, tenantID, ActKeyIssue, k.ID, "role="+role, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO api_keys (id, tenant_id, role, hash, created_at) VALUES (?, ?, ?, ?, ?)`,
			k.ID, k.TenantID, k.Role, HashKey(plain), k.CreatedAt.UnixMilli())
		return err
	})
	if err != nil {
		return "", APIKey{}, err
	}
	return plain, k, nil
}

func (o *Operator) RevokeAPIKey(ctx context.Context, id string) error {
	var tenantID string
	err := o.db.QueryRowContext(ctx, `SELECT tenant_id FROM api_keys WHERE id = ? AND revoked_at IS NULL`, id).Scan(&tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return inTx(ctx, o.db, tenantID, ActKeyRevoke, id, "", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().UnixMilli(), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (o *Operator) ListAPIKeys(ctx context.Context, tenantID string) ([]APIKey, error) {
	rows, err := o.db.QueryContext(ctx,
		`SELECT id, tenant_id, role, created_at, last_used_at, revoked_at FROM api_keys WHERE tenant_id = ? ORDER BY created_at, id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func scanKey(sc interface{ Scan(...any) error }) (APIKey, error) {
	var k APIKey
	var created int64
	var used, revoked sql.NullInt64
	if err := sc.Scan(&k.ID, &k.TenantID, &k.Role, &created, &used, &revoked); err != nil {
		return APIKey{}, err
	}
	k.CreatedAt = time.UnixMilli(created).UTC()
	if used.Valid {
		t := time.UnixMilli(used.Int64).UTC()
		k.LastUsedAt = &t
	}
	if revoked.Valid {
		t := time.UnixMilli(revoked.Int64).UTC()
		k.RevokedAt = &t
	}
	return k, nil
}

// Authenticate resolves a presented tenant key. Revoked keys and keys of disabled tenants are
// ErrNotFound. It records last use at most once a minute per key.
func (s *Store) Authenticate(ctx context.Context, presented string) (APIKey, error) {
	if !strings.HasPrefix(presented, APIKeyPrefix) {
		return APIKey{}, ErrNotFound
	}
	k, err := scanKey(s.db.QueryRowContext(ctx,
		`SELECT k.id, k.tenant_id, k.role, k.created_at, k.last_used_at, k.revoked_at
		   FROM api_keys k JOIN tenants t ON t.id = k.tenant_id
		  WHERE k.hash = ? AND k.revoked_at IS NULL AND t.disabled = 0`, HashKey(presented)))
	if errors.Is(err, sql.ErrNoRows) {
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, err
	}
	now := time.Now()
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) > time.Minute {
		_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, now.UnixMilli(), k.ID)
	}
	return k, nil
}

// KeyActive reports whether a key id is still usable (dashboard sessions re-check on each request).
func (s *Store) KeyActive(ctx context.Context, keyID, tenantID string) bool {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM api_keys k JOIN tenants t ON t.id = k.tenant_id
		  WHERE k.id = ? AND k.tenant_id = ? AND k.revoked_at IS NULL AND t.disabled = 0`, keyID, tenantID).Scan(&one)
	return err == nil
}
