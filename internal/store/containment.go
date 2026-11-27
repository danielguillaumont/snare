package store

// Containment records (docs/M8-containment.md).

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

// Containment actions a gateway reports with a touch.
const (
	ContainBlocked = "blocked"
	ContainFrozen  = "frozen"
)

// ReleaseSession records that an admin released a contained gateway session, with a note
// saying why. The session must have a contained touch in this tenant; otherwise it is
// ErrNotFound, exactly like another tenant's session. It returns how many contained
// touches the session had. The release itself happens on the agent's machine, where
// snare gateway release deletes the freeze only after this succeeds.
func (v *tenantView) ReleaseSession(ctx context.Context, session, note string) (int, error) {
	if session == "" || len(session) > maxSession || note == "" || len(note) > MaxTriageNote {
		return 0, ErrInvalid
	}
	var n int
	err := inTxDetail(ctx, v.db, v.tid, ActSessionRelease, session, func(tx *sql.Tx) (string, error) {
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM events WHERE tenant_id = ? AND session_id = ? AND containment != ''`,
			v.tid, session).Scan(&n); err != nil {
			return "", err
		}
		if n == 0 {
			return "", ErrNotFound
		}
		return fmt.Sprintf("contained_touches=%d note=%s", n, strconv.Quote(note)), nil
	})
	return n, err
}
