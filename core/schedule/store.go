package schedule

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/store"
)

// DefaultOrgZone is the organization's zone before first-run setup has written one: the column default of core_org.timezone
// (modules/core checks the two stay equal).
const DefaultOrgZone = "Asia/Ho_Chi_Minh"

// querier is a transaction or a database handle.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// orgZoneName reads the organization's time zone (core_org.timezone, Settings, General).
func orgZoneName(ctx context.Context, q querier) (string, error) {
	var tz string
	err := q.QueryRowContext(ctx, `SELECT COALESCE((SELECT timezone FROM core_org WHERE id = 1), ?)`, DefaultOrgZone).Scan(&tz)
	if err != nil {
		return "", fmt.Errorf("schedule: read the organization's time zone: %w", err)
	}
	return tz, nil
}

// zoneOf is the zone a rule is read in. A zone this box cannot load (an organization zone saved by an older version) reads as UTC,
// the same for every reader, so the stored next due time and the self-check agree.
func zoneOf(tz, org string) *time.Location {
	loc, err := LoadZone(tz, org)
	if err != nil {
		return time.UTC
	}
	return loc
}

// row is a core_schedule row.
type row struct {
	ID, OwnerModule, OwnerKey string
	Enabled                   bool
	PausedUntil               *time.Time
	Rule                      Rule
	NextDueAt, LastDueAt      *time.Time
	LastRunID                 *string
	LastSkipReason            *string
	LastSkipAt                *time.Time
	UpdatedBy                 string
	UpdatedAt                 time.Time
}

// Reference is the time a schedule's next due time counts from: the latest of when it last came due, when a person last changed
// it, and the end of its pause.
func Reference(lastDue *time.Time, updated time.Time, pausedUntil *time.Time) time.Time {
	ref := updated
	if lastDue != nil && lastDue.After(ref) {
		ref = *lastDue
	}
	if pausedUntil != nil && pausedUntil.After(ref) {
		ref = *pausedUntil
	}
	return ref
}

// firstInWindow holds the owner names (Owner.FirstInWindow) whose schedule that never came due is due at once. It is a registry of the
// process because next_due_at is also recomputed outside a Service (Recompute, when the organization's zone changes).
var firstInWindow sync.Map

func ownerName(key string) string { n, _, _ := strings.Cut(key, ":"); return n }

// due is the next due time the row must have: nil while it is off or never comes due again.
func (r row) due(org string) *time.Time {
	if !r.Enabled {
		return nil
	}
	if _, ok := firstInWindow.Load(ownerName(r.OwnerKey)); ok && r.LastDueAt == nil && r.Rule.Window == WindowGlobal {
		t := Reference(nil, r.UpdatedAt, r.PausedUntil).Truncate(time.Millisecond) // never ran: due at once, the scan window holds it
		return &t
	}
	t := Due(r.Rule, r.LastDueAt, r.UpdatedAt, r.PausedUntil, zoneOf(r.Rule.TZ, org))
	if t.IsZero() {
		return nil
	}
	t = t.Truncate(time.Millisecond)
	return &t
}

const rowColumns = `id, owner_module, owner_key, enabled, paused_until, freq, every_minutes, at_time, weekdays, month_day, once_at, tz,
	window_mode, window_days, window_from, window_to, next_due_at, last_due_at, last_run_id, last_skip_reason, last_skip_at, updated_by, updated_at`

func parseTS(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("schedule: bad time %q: %w", s, err)
	}
	return t, nil
}

func parseNullTS(s sql.NullString) (*time.Time, error) {
	if !s.Valid {
		return nil, nil //nolint:nilnil // NULL is no time
	}
	t, err := parseTS(s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func nullString(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}

func nullInt(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func intList(s sql.NullString) ([]int, error) {
	if !s.Valid {
		return nil, nil
	}
	var out []int
	if err := json.Unmarshal([]byte(s.String), &out); err != nil {
		return nil, fmt.Errorf("schedule: bad day list %q: %w", s.String, err)
	}
	return out, nil
}

type scanner interface{ Scan(dest ...any) error }

func scanRow(sc scanner) (row, error) {
	var (
		r                                                           row
		enabled                                                     int
		paused, at, weekdays, onceAt, wdays, wfrom, wto, next, last sql.NullString
		lastRun, skipReason, skipAt                                 sql.NullString
		every, monthDay                                             sql.NullInt64
		freq, tz, mode, updatedAt                                   string
	)
	err := sc.Scan(&r.ID, &r.OwnerModule, &r.OwnerKey, &enabled, &paused, &freq, &every, &at, &weekdays, &monthDay, &onceAt, &tz,
		&mode, &wdays, &wfrom, &wto, &next, &last, &lastRun, &skipReason, &skipAt, &r.UpdatedBy, &updatedAt)
	if err != nil {
		return row{}, err
	}
	r.Enabled = enabled == 1
	r.Rule = Rule{Freq: Freq(freq), EveryMinutes: nullInt(every), At: nullString(at), MonthDay: nullInt(monthDay), TZ: tz,
		Window: WindowMode(mode), WindowFrom: nullString(wfrom), WindowTo: nullString(wto)}
	if r.Rule.Weekdays, err = intList(weekdays); err != nil {
		return row{}, err
	}
	if r.Rule.WindowDays, err = intList(wdays); err != nil {
		return row{}, err
	}
	if r.Rule.OnceAt, err = parseNullTS(onceAt); err != nil {
		return row{}, err
	}
	if r.PausedUntil, err = parseNullTS(paused); err != nil {
		return row{}, err
	}
	if r.NextDueAt, err = parseNullTS(next); err != nil {
		return row{}, err
	}
	if r.LastDueAt, err = parseNullTS(last); err != nil {
		return row{}, err
	}
	if r.LastSkipAt, err = parseNullTS(skipAt); err != nil {
		return row{}, err
	}
	if r.UpdatedAt, err = parseTS(updatedAt); err != nil {
		return row{}, err
	}
	r.LastRunID, r.LastSkipReason = nullString(lastRun), nullString(skipReason)
	return r, nil
}

// errNoRow is a key without a row.
var errNoRow = errors.New("schedule: no row")

func getRow(ctx context.Context, q querier, key string) (row, error) {
	r, err := scanRow(q.QueryRowContext(ctx, `SELECT `+rowColumns+` FROM core_schedule WHERE owner_key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return row{}, errNoRow
	}
	if err != nil {
		return row{}, fmt.Errorf("schedule: read %s: %w", key, err)
	}
	return r, nil
}

func listRows(ctx context.Context, q querier, where string, args ...any) ([]row, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+rowColumns+` FROM core_schedule `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("schedule: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("schedule: list: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func ts(t *time.Time) any {
	if t == nil {
		return nil
	}
	return store.FormatTS(*t)
}

func jsonList(xs []int) any {
	if xs == nil {
		return nil
	}
	b, _ := json.Marshal(xs) //nolint:errchkjson // a list of ints always marshals
	return string(b)
}

// upsert writes a row whole, with its next due time computed here: the one writer of next_due_at.
func upsert(ctx context.Context, tx *sql.Tx, r row, org string) error {
	r.NextDueAt = r.due(org)
	rl := r.Rule
	_, err := tx.ExecContext(ctx, `INSERT INTO core_schedule (`+rowColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (owner_key) DO UPDATE SET enabled = excluded.enabled, paused_until = excluded.paused_until, freq = excluded.freq,
			every_minutes = excluded.every_minutes, at_time = excluded.at_time, weekdays = excluded.weekdays,
			month_day = excluded.month_day, once_at = excluded.once_at, tz = excluded.tz, window_mode = excluded.window_mode,
			window_days = excluded.window_days, window_from = excluded.window_from, window_to = excluded.window_to,
			next_due_at = excluded.next_due_at, last_due_at = excluded.last_due_at, last_run_id = excluded.last_run_id,
			last_skip_reason = excluded.last_skip_reason, last_skip_at = excluded.last_skip_at, updated_by = excluded.updated_by,
			updated_at = excluded.updated_at`,
		r.ID, r.OwnerModule, r.OwnerKey, r.Enabled, ts(r.PausedUntil), string(rl.Freq), rl.EveryMinutes, rl.At, jsonList(rl.Weekdays),
		rl.MonthDay, ts(rl.OnceAt), rl.TZ, string(rl.Window), jsonList(rl.WindowDays), rl.WindowFrom, rl.WindowTo,
		ts(r.NextDueAt), ts(r.LastDueAt), r.LastRunID, r.LastSkipReason, ts(r.LastSkipAt), r.UpdatedBy, store.FormatTS(r.UpdatedAt))
	if err != nil {
		return fmt.Errorf("schedule: save %s: %w", r.OwnerKey, err)
	}
	return nil
}

// Recompute writes the next due time of every schedule again, inside the caller's transaction. Call it in the transaction that
// changes the organization's time zone (the rules in tz "org" move with it); the service also runs it at start, so a next due
// time written by another version of Next is brought up to date.
func Recompute(ctx context.Context, tx *sql.Tx) (int, error) {
	org, err := orgZoneName(ctx, tx)
	if err != nil {
		return 0, err
	}
	rows, err := listRows(ctx, tx, ``)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, r := range rows {
		want := r.due(org)
		if sameTime(want, r.NextDueAt) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE core_schedule SET next_due_at = ? WHERE id = ?`, ts(want), r.ID); err != nil {
			return changed, fmt.Errorf("schedule: recompute %s: %w", r.OwnerKey, err)
		}
		changed++
	}
	return changed, nil
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
