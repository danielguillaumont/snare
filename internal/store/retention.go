package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Event retention (docs/M4f-distribution.md §2). An event is purgeable when it was recorded
// before the cutoff, somebody has closed it (or it is muted, so nobody ever will), and no
// alert for it is still waiting in the outbox: until then the row is the only copy.
const purgeable = `at < ? AND (status != 'open' OR muted = 1)
	AND NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.event_id = events.id AND d.state = 'pending')`

// PurgeEvents deletes purgeable events recorded before cutoff, with their delivery rows. Each
// tenant that lost events gets one events.purge audit record, by system, in the same
// transaction as its deletion. It returns the number of events deleted.
func (s *Store) PurgeEvents(ctx context.Context, cutoff time.Time) (int, error) {
	ctx = WithActor(ctx, "system") // a timer, never the caller's key
	ms := cutoff.UnixMilli()
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM events WHERE `+purgeable, ms)
	if err != nil {
		return 0, err
	}
	var tenants []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return 0, err
		}
		tenants = append(tenants, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	total := 0
	for _, tid := range tenants {
		var n int64
		err := inTxDetail(ctx, s.db, tid, ActEventsPurge, "events", func(tx *sql.Tx) (string, error) {
			// Recomputed inside the transaction: a triage since the scan above may have reopened one.
			if _, err := tx.ExecContext(ctx, `DELETE FROM deliveries WHERE event_id IN
				(SELECT id FROM events WHERE tenant_id = ? AND `+purgeable+`)`, tid, ms); err != nil {
				return "", err
			}
			res, err := tx.ExecContext(ctx, `DELETE FROM events WHERE tenant_id = ? AND `+purgeable, tid, ms)
			if err != nil {
				return "", err
			}
			n, _ = res.RowsAffected()
			return fmt.Sprintf("cutoff=%s events=%d", cutoff.UTC().Format(time.RFC3339), n), nil
		})
		if err != nil {
			return total, err
		}
		total += int(n)
	}
	return total, nil
}

// OpenExpired counts open, unmuted events older than cutoff: the ones retention keeps
// because nobody has triaged them yet.
func (s *Store) OpenExpired(ctx context.Context, cutoff time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE at < ? AND status = 'open' AND muted = 0`, cutoff.UnixMilli()).Scan(&n)
	return n, err
}
