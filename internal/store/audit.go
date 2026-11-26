package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Audit log (docs/M4b-hardening.md §3). Every administrative change writes one record in the
// same transaction as the change itself, so a change without a record can't commit. Records
// form a hash chain: hash = SHA-256(prev_hash ‖ canonical record). Editing or deleting a past
// row breaks verification from that row on. Rewriting the whole chain needs DB write access
// and is detected by comparing the head against a copy kept elsewhere.

const auditSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  at        INTEGER NOT NULL,
  actor     TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  action    TEXT NOT NULL,
  target    TEXT NOT NULL,
  detail    TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_tenant ON audit_log(tenant_id, seq);
`

// Audit actions.
const (
	ActTenantCreate  = "tenant.create"
	ActTenantDisable = "tenant.disable"
	ActTenantEnable  = "tenant.enable"
	ActKeyIssue      = "key.issue"
	ActKeyRevoke     = "key.revoke"
	ActSinkCreate    = "sink.create"
	ActSinkDelete    = "sink.delete"
	ActSignIn        = "dashboard.sign_in"
)

type AuditEntry struct {
	Seq      int64     `json:"seq"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"` // "operator", an API key id, or "system"
	TenantID string    `json:"tenant_id"`
	Action   string    `json:"action"`
	Target   string    `json:"target"`
	Detail   string    `json:"detail,omitempty"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

type actorKey struct{}

// WithActor tags ctx with who is acting; store writes made under it are attributed to them.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

func actorFrom(ctx context.Context) string {
	if a, ok := ctx.Value(actorKey{}).(string); ok && a != "" {
		return a
	}
	return "system"
}

func auditHash(prev string, e AuditEntry) string {
	// A JSON array is an unambiguous encoding of the fields (no delimiter games).
	canon, _ := json.Marshal([]any{prev, e.At.UnixMilli(), e.Actor, e.TenantID, e.Action, e.Target, e.Detail})
	h := sha256.Sum256(canon)
	return hex.EncodeToString(h[:])
}

// inTx runs fn and appends one audit record in the same transaction. fn must use only tx:
// the pool has one connection, so touching db inside would deadlock.
func inTx(ctx context.Context, db *sql.DB, tenantID, action, target, detail string, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if fn != nil {
		if err := fn(tx); err != nil {
			return err
		}
	}
	var prev string
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	e := AuditEntry{At: time.Now().UTC(), Actor: actorFrom(ctx), TenantID: tenantID, Action: action, Target: target, Detail: detail}
	e.Hash = auditHash(prev, e)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log (at, actor, tenant_id, action, target, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At.UnixMilli(), e.Actor, e.TenantID, e.Action, e.Target, e.Detail, prev, e.Hash); err != nil {
		return err
	}
	return tx.Commit()
}

// Audit records an event that has no store change of its own (dashboard sign-in).
func (s *Store) Audit(ctx context.Context, tenantID, action, target, detail string) error {
	return inTx(ctx, s.db, tenantID, action, target, detail, nil)
}

func scanAudit(rows *sql.Rows) ([]AuditEntry, error) {
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ms int64
		if err := rows.Scan(&e.Seq, &ms, &e.Actor, &e.TenantID, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(ms).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

const auditCols = `seq, at, actor, tenant_id, action, target, detail, prev_hash, hash`

// ListAudit returns this tenant's audit records, newest first.
func (v *tenantView) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := v.db.QueryContext(ctx,
		`SELECT `+auditCols+` FROM audit_log WHERE tenant_id = ? ORDER BY seq DESC LIMIT ?`, v.tid, clampLimit(limit))
	if err != nil {
		return nil, err
	}
	return scanAudit(rows)
}

// ListAudit returns audit records for one tenant, or all of them when tenantID is "".
func (o *Operator) ListAudit(ctx context.Context, tenantID string, limit int) ([]AuditEntry, error) {
	q := `SELECT ` + auditCols + ` FROM audit_log ORDER BY seq DESC LIMIT ?`
	args := []any{clampLimit(limit)}
	if tenantID != "" {
		q = `SELECT ` + auditCols + ` FROM audit_log WHERE tenant_id = ? ORDER BY seq DESC LIMIT ?`
		args = []any{tenantID, clampLimit(limit)}
	}
	rows, err := o.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanAudit(rows)
}

// AuditBrokenError names the first record whose chain doesn't check out.
type AuditBrokenError struct {
	Seq    int64
	Reason string
}

func (e *AuditBrokenError) Error() string {
	return fmt.Sprintf("audit chain broken at seq %d: %s", e.Seq, e.Reason)
}

// VerifyAudit walks the whole chain. It returns the head hash and record count when intact,
// or an *AuditBrokenError naming the first bad record.
func (o *Operator) VerifyAudit(ctx context.Context) (head string, n int, err error) {
	rows, err := o.db.QueryContext(ctx, `SELECT `+auditCols+` FROM audit_log ORDER BY seq`)
	if err != nil {
		return "", 0, err
	}
	all, err := scanAudit(rows)
	if err != nil {
		return "", 0, err
	}
	prev := ""
	for _, e := range all {
		if e.PrevHash != prev {
			return "", n, &AuditBrokenError{e.Seq, "prev_hash does not match the previous record (a record was removed or reordered)"}
		}
		if auditHash(prev, e) != e.Hash {
			return "", n, &AuditBrokenError{e.Seq, "contents do not match the hash (the record was edited)"}
		}
		prev = e.Hash
		n++
	}
	return prev, n, nil
}
