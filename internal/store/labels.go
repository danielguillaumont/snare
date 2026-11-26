package store

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/danielguillaumont/snare/internal/seal"
)

// Token labels and memos say where a tripwire is planted. With a seal key they are stored
// sealed, bound to their tenant and token, so a copy of the database (a backup, a snapshot)
// doesn't hand an attacker the map. Design: docs/M4d-operations.md §2.

const sealedPrefix = "sealed:v1:"

// Placeholders for a sealed value that can't be opened: wrong or missing key, or a row that
// was tampered with or moved. The token still works and still alerts.
const (
	LabelUnreadable = "(sealed label: cannot open)"
	MemoUnreadable  = "(sealed memo: cannot open)"
)

// SealLabels turns on sealing for labels and memos written from now on, and seals any that
// are still plaintext. Call it once at startup, before serving. It returns how many tokens
// it sealed.
func (s *Store) SealLabels(ctx context.Context, sl *seal.Sealer) (int, error) {
	if sl == nil {
		return 0, fmt.Errorf("store: SealLabels needs a sealer")
	}
	s.labels.Store(sl)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx,
		`SELECT id, tenant_id, label, memo FROM tokens
		  WHERE substr(label, 1, ?) != ? OR (memo != '' AND substr(memo, 1, ?) != ?)`,
		len(sealedPrefix), sealedPrefix, len(sealedPrefix), sealedPrefix)
	if err != nil {
		return 0, err
	}
	type plain struct{ id, tid, label, memo string }
	var todo []plain
	for rows.Next() {
		var p plain
		if err := rows.Scan(&p.id, &p.tid, &p.label, &p.memo); err != nil {
			rows.Close()
			return 0, err
		}
		todo = append(todo, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, p := range todo {
		label, err := s.sealField(p.tid, p.id, "label", p.label)
		if err != nil {
			return 0, err
		}
		memo, err := s.sealField(p.tid, p.id, "memo", p.memo)
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE tokens SET label = ?, memo = ? WHERE id = ?`, label, memo, p.id); err != nil {
			return 0, err
		}
	}
	return len(todo), tx.Commit()
}

// sealField seals v when sealing is on. Already-sealed values and empty memos are left as
// they are.
func (s *Store) sealField(tenantID, tokenID, field, v string) (string, error) {
	sl := s.labels.Load()
	if sl == nil || v == "" || strings.HasPrefix(v, sealedPrefix) {
		return v, nil
	}
	b, err := sl.Seal([]byte(v), tenantID, "token-"+field+":"+tokenID)
	if err != nil {
		return "", err
	}
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(b), nil
}

// openField returns plaintext values unchanged and opens sealed ones. It never fails: a value
// that won't open becomes the placeholder.
func (s *Store) openField(tenantID, tokenID, field, v, unreadable string) string {
	if !strings.HasPrefix(v, sealedPrefix) {
		return v
	}
	sl := s.labels.Load()
	if sl == nil {
		return unreadable
	}
	b, err := base64.RawStdEncoding.DecodeString(v[len(sealedPrefix):])
	if err != nil {
		return unreadable
	}
	pt, err := sl.Open(b, tenantID, "token-"+field+":"+tokenID)
	if err != nil {
		return unreadable
	}
	return string(pt)
}

func (s *Store) openToken(t Token) Token {
	t.Label = s.openField(t.TenantID, t.ID, "label", t.Label, LabelUnreadable)
	t.Memo = s.openField(t.TenantID, t.ID, "memo", t.Memo, MemoUnreadable)
	return t
}
