// Package store persists tokens and tripwire events in SQLite (pure Go driver, no cgo).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("store: not found")

type Token struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`  // e.g. decoy_tool, honey_credential, canary_doc, canary_url
	Label     string    `json:"label"` // human description: where it was planted
	Memo      string    `json:"memo,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Event struct {
	ID       int64     `json:"id"`
	TokenID  string    `json:"token_id"`
	Channel  string    `json:"channel"` // http | dns
	SourceIP string    `json:"source_ip"`
	Detail   string    `json:"detail"` // user agent + path, or DNS query name and type
	At       time.Time `json:"at"`
}

type Store struct{ db *sql.DB }

const schema = `
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
CREATE INDEX IF NOT EXISTS events_token_at ON events(token_id, at);
`

// Open opens (or creates) the database. Use ":memory:" in tests.
func Open(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; one connection also keeps ":memory:" a single database.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateToken(ctx context.Context, t Token) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (id, kind, label, memo, created_at) VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Kind, t.Label, t.Memo, t.CreatedAt.UnixMilli())
	return err
}

func (s *Store) GetToken(ctx context.Context, id string) (Token, error) {
	var t Token
	var ms int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, kind, label, memo, created_at FROM tokens WHERE id = ?`, id).
		Scan(&t.ID, &t.Kind, &t.Label, &t.Memo, &ms)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	t.CreatedAt = time.UnixMilli(ms).UTC()
	return t, err
}

func (s *Store) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, label, memo, created_at FROM tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		var ms int64
		if err := rows.Scan(&t.ID, &t.Kind, &t.Label, &t.Memo, &ms); err != nil {
			return nil, err
		}
		t.CreatedAt = time.UnixMilli(ms).UTC()
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) AddEvent(ctx context.Context, e Event) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO events (token_id, channel, source_ip, detail, at) VALUES (?, ?, ?, ?, ?)`,
		e.TokenID, e.Channel, e.SourceIP, e.Detail, e.At.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListEvents returns the most recent events first. tokenID "" means all tokens.
func (s *Store) ListEvents(ctx context.Context, tokenID string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT id, token_id, channel, source_ip, detail, at FROM events`
	args := []any{}
	if tokenID != "" {
		q += ` WHERE token_id = ?`
		args = append(args, tokenID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ms int64
		if err := rows.Scan(&e.ID, &e.TokenID, &e.Channel, &e.SourceIP, &e.Detail, &ms); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(ms).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
