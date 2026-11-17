package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Querier is what Find reads with: a *sql.DB (store.DB.Reader) or a *sql.Tx.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// Row is one stored line of core_audit as Find returns it (Detail is "" when the line has none).
type Row struct {
	TS, User, Action, Target, Detail string
}

// maxFind bounds one Find.
const maxFind = 1000

// Find reads, oldest first, at most limit lines (1 to 1000) of one of actions on target whose time is in [from, to] (timestamps as the
// log stores them, store.FormatTS; both ends included). It is read-only: a module that must tell from the log what happened to its
// own rows (a start-up correction of rows an older version stored) reads it here, never the table.
func Find(ctx context.Context, q Querier, actions []string, target, from, to string, limit int) ([]Row, error) {
	if len(actions) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(actions)+4)
	args = append(args, target, from, to)
	for _, a := range actions {
		args = append(args, a)
	}
	args = append(args, max(1, min(maxFind, limit)))
	rows, err := q.QueryContext(ctx, `SELECT ts, user, action, target, coalesce(detail, '') FROM core_audit
		WHERE target = ? AND ts >= ? AND ts <= ? AND action IN (?`+strings.Repeat(", ?", len(actions)-1)+`) ORDER BY ts, seq LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: find: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.TS, &r.User, &r.Action, &r.Target, &r.Detail); err != nil {
			return nil, fmt.Errorf("audit: find: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: find: %w", err)
	}
	return out, nil
}
