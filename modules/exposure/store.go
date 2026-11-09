package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/store"
)

// querier is what both *sql.DB (reads) and *sql.Tx (inside a write) offer.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface{ Scan(dest ...any) error }

const targetColumns = `id, kind, value, coalesce(method, ''), token, verified_at, last_check, commitment_by, commitment_at, created_at, last_scan_at`

func parseTS(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp: %w", err)
	}
	return t, nil
}

func optTS(s sql.NullString) (time.Time, error) {
	if !s.Valid {
		return time.Time{}, nil
	}
	return parseTS(s.String)
}

func tsOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return store.FormatTS(t)
}

func scanTarget(s scanner) (Target, error) {
	var (
		t                                  Target
		kind                               string
		verified, check, by, byAt, scanned sql.NullString
		created                            string
	)
	if err := s.Scan(&t.ID, &kind, &t.Value, &t.Method, &t.Token, &verified, &check, &by, &byAt, &created, &scanned); err != nil {
		return Target{}, err
	}
	t.Kind = Kind(kind)
	var err error
	if t.VerifiedAt, err = optTS(verified); err != nil {
		return Target{}, err
	}
	if t.CreatedAt, err = parseTS(created); err != nil {
		return Target{}, err
	}
	if t.LastScanAt, err = optTS(scanned); err != nil {
		return Target{}, err
	}
	if check.Valid {
		t.LastCheck = new(Check)
		if err := json.Unmarshal([]byte(check.String), t.LastCheck); err != nil {
			return Target{}, fmt.Errorf("last_check: %w", err)
		}
	}
	if by.Valid && byAt.Valid {
		t.Commitment = &Commitment{By: by.String, At: byAt.String}
	}
	return t, nil
}

func loadTarget(ctx context.Context, q querier, id string) (Target, error) {
	t, err := scanTarget(q.QueryRowContext(ctx, `SELECT `+targetColumns+` FROM exp_target WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	if err != nil {
		return Target{}, fmt.Errorf("target %s: %w", id, err)
	}
	return t, nil
}

func loadTargetByValue(ctx context.Context, q querier, value string) (Target, bool, error) {
	t, err := scanTarget(q.QueryRowContext(ctx, `SELECT `+targetColumns+` FROM exp_target WHERE value = ?`, value))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, false, nil
	}
	if err != nil {
		return Target{}, false, fmt.Errorf("target %s: %w", value, err)
	}
	return t, true, nil
}

func listTargets(ctx context.Context, q querier) ([]Target, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+targetColumns+` FROM exp_target ORDER BY created_at, rowid`)
	if err != nil {
		return nil, fmt.Errorf("targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, fmt.Errorf("targets: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func countTargets(ctx context.Context, q querier) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM exp_target`).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting targets: %w", err)
	}
	return n, nil
}

// latestCounts returns the counts of the newest snapshot of every target that has one.
func latestCounts(ctx context.Context, q querier) (map[string]Counts, error) {
	rows, err := q.QueryContext(ctx, `SELECT s.target_id, s.counts FROM exp_snapshot s
		WHERE s.date = (SELECT max(date) FROM exp_snapshot WHERE target_id = s.target_id)`)
	if err != nil {
		return nil, fmt.Errorf("latest counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]Counts{}
	for rows.Next() {
		var id, doc string
		var c Counts
		if err := rows.Scan(&id, &doc); err != nil {
			return nil, fmt.Errorf("latest counts: %w", err)
		}
		if err := json.Unmarshal([]byte(doc), &c); err != nil {
			return nil, fmt.Errorf("latest counts of %s: %w", id, err)
		}
		out[id] = c
	}
	return out, rows.Err()
}

func insertTarget(ctx context.Context, tx *sql.Tx, t Target) error {
	check, err := checkDoc(t.LastCheck)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO exp_target (id, kind, value, method, token, verified_at, last_check, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, string(t.Kind), t.Value, nullString(t.Method), t.Token, tsOrNil(t.VerifiedAt), check, store.FormatTS(t.CreatedAt))
	if err != nil {
		return fmt.Errorf("inserting target %s: %w", t.Value, err)
	}
	return nil
}

// updateCheck records a check and, when verifiedAt is not zero, the verification time and method.
func updateCheck(ctx context.Context, tx *sql.Tx, id string, c Check, verifiedAt time.Time, method string) error {
	doc, err := checkDoc(&c)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE exp_target SET last_check = ?, verified_at = coalesce(?, verified_at), method = coalesce(?, method) WHERE id = ?`,
		doc, tsOrNil(verifiedAt), nullString(method), id)
	if err != nil {
		return fmt.Errorf("updating target %s: %w", id, err)
	}
	return nil
}

func checkDoc(c *Check) (any, error) {
	if c == nil {
		return nil, nil
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encoding check: %w", err)
	}
	return string(b), nil
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// renewIP sets the last sighting of an IP: verified_at is the time, and with it the 30 days (INV-4).
func renewIP(ctx context.Context, tx *sql.Tx, id string, now time.Time, msg string) error {
	return updateCheck(ctx, tx, id, Check{At: store.FormatTS(now), OK: true, Message: msg}, now, methodBoxEgress)
}

func deleteTarget(ctx context.Context, tx *sql.Tx, id string) error {
	res, err := tx.ExecContext(ctx, `DELETE FROM exp_target WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting target %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func setCommitment(ctx context.Context, tx *sql.Tx, id, by string, at time.Time) error {
	_, err := tx.ExecContext(ctx, `UPDATE exp_target SET commitment_by = ?, commitment_at = ? WHERE id = ?`, by, store.FormatTS(at), id)
	if err != nil {
		return fmt.Errorf("recording the commitment of %s: %w", id, err)
	}
	return nil
}

// ---- snapshots ----

func snapshotDocs(c Content, counts Counts) (hosts, ports, admin, certs, cnt string, err error) {
	var docs [5][]byte
	for i, v := range []any{nz(c.Hosts), nz(c.Ports), nz(c.AdminPanels), nz(c.Certs), counts} {
		if docs[i], err = json.Marshal(v); err != nil {
			return "", "", "", "", "", fmt.Errorf("encoding snapshot: %w", err)
		}
	}
	return string(docs[0]), string(docs[1]), string(docs[2]), string(docs[3]), string(docs[4]), nil
}

// nz makes a nil slice encode as [] and not as null.
func nz[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// upsertSnapshot stores the result of a scan; a second scan on the same day replaces the first (INV-8).
func upsertSnapshot(ctx context.Context, tx *sql.Tx, targetID string, snap Snapshot) error {
	hosts, ports, admin, certs, counts, err := snapshotDocs(snap.Content, snap.Counts)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM exp_snapshot WHERE target_id = ? AND date = ?`, targetID, snap.Date); err != nil {
		return fmt.Errorf("replacing snapshot: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO exp_snapshot (id, target_id, date, scanned_at, hosts, ports, admin_panels, certs, counts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snap.ID, targetID, snap.Date, snap.ScannedAt, hosts, ports, admin, certs, counts)
	if err != nil {
		return fmt.Errorf("inserting snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET last_scan_at = ? WHERE id = ?`, snap.ScannedAt, targetID); err != nil {
		return fmt.Errorf("updating last scan: %w", err)
	}
	return nil
}

func listSnapshotMetas(ctx context.Context, q querier, targetID string) ([]SnapshotMeta, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, date, scanned_at, counts FROM exp_snapshot WHERE target_id = ? ORDER BY date DESC`, targetID)
	if err != nil {
		return nil, fmt.Errorf("snapshots: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []SnapshotMeta{}
	for rows.Next() {
		var m SnapshotMeta
		var doc string
		if err := rows.Scan(&m.ID, &m.Date, &m.ScannedAt, &doc); err != nil {
			return nil, fmt.Errorf("snapshots: %w", err)
		}
		if err := json.Unmarshal([]byte(doc), &m.Counts); err != nil {
			return nil, fmt.Errorf("snapshot %s counts: %w", m.ID, err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// loadSnapshot returns the snapshot of one day, or ok=false when there is none.
func loadSnapshot(ctx context.Context, q querier, targetID, date string) (Snapshot, bool, error) {
	var s Snapshot
	var hosts, ports, admin, certs, counts string
	err := q.QueryRowContext(ctx, `SELECT id, date, scanned_at, hosts, ports, admin_panels, certs, counts FROM exp_snapshot WHERE target_id = ? AND date = ?`, targetID, date).
		Scan(&s.ID, &s.Date, &s.ScannedAt, &hosts, &ports, &admin, &certs, &counts)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("snapshot %s: %w", date, err)
	}
	for _, d := range []struct {
		doc string
		to  any
	}{{hosts, &s.Hosts}, {ports, &s.Ports}, {admin, &s.AdminPanels}, {certs, &s.Certs}, {counts, &s.Counts}} {
		if err := json.Unmarshal([]byte(d.doc), d.to); err != nil {
			return Snapshot{}, false, fmt.Errorf("snapshot %s: %w", s.ID, err)
		}
	}
	s.Content = Content{Hosts: nz(s.Hosts), Ports: nz(s.Ports), AdminPanels: nz(s.AdminPanels), Certs: nz(s.Certs)}
	return s, true, nil
}

// ---- attempts ----

// recentAttempts returns the times of the attempts of the last hour, oldest first, after dropping
// every attempt older than 24 hours.
func recentAttempts(ctx context.Context, tx *sql.Tx, now time.Time) ([]time.Time, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM exp_attempt WHERE ts < ?`, store.FormatTS(now.Add(-24*time.Hour))); err != nil {
		return nil, fmt.Errorf("pruning attempts: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT ts FROM exp_attempt WHERE ts > ? ORDER BY ts`, store.FormatTS(now.Add(-time.Hour)))
	if err != nil {
		return nil, fmt.Errorf("attempts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []time.Time
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("attempts: %w", err)
		}
		t, err := parseTS(s)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ---- settings ----

func loadBoxIP(ctx context.Context, q querier) (BoxIP, error) {
	var b BoxIP
	var auto int
	var at, msg sql.NullString
	var ok sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT auto, interval_min, last_run_at, last_run_ok, last_run_message FROM exp_setting WHERE id = 1`).Scan(&auto, &b.IntervalMin, &at, &ok, &msg)
	if err != nil {
		return BoxIP{}, fmt.Errorf("auto-detect settings: %w", err)
	}
	b.Auto = auto == 1
	if at.Valid {
		b.LastRun = &LastRun{At: at.String, OK: ok.Int64 == 1, Message: msg.String}
	}
	return b, nil
}

func saveSettings(ctx context.Context, tx *sql.Tx, auto bool, interval int) error {
	a := 0
	if auto {
		a = 1
	}
	if _, err := tx.ExecContext(ctx, `UPDATE exp_setting SET auto = ?, interval_min = ? WHERE id = 1`, a, interval); err != nil {
		return fmt.Errorf("saving auto-detect settings: %w", err)
	}
	return nil
}

// saveRun records the last detection; deep marks a full check, which also moves last_deep_at (the light checks of a
// short interval do not, so a full check still runs once an hour).
func saveRun(ctx context.Context, tx *sql.Tx, at time.Time, ok bool, message string, deep bool) error {
	if len(message) > 1000 {
		message = message[:1000]
	}
	o, d := 0, 0
	if ok {
		o = 1
	}
	if deep {
		d = 1
	}
	ts := store.FormatTS(at)
	if _, err := tx.ExecContext(ctx, `UPDATE exp_setting SET last_run_at = ?, last_run_ok = ?, last_run_message = ?, last_deep_at = CASE WHEN ? = 1 THEN ? ELSE last_deep_at END WHERE id = 1`, ts, o, message, d, ts); err != nil {
		return fmt.Errorf("saving the last detection: %w", err)
	}
	return nil
}

// loadLastDeep returns when the last full check ran; the zero time when none did.
func loadLastDeep(ctx context.Context, q querier) (time.Time, error) {
	var s sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT last_deep_at FROM exp_setting WHERE id = 1`).Scan(&s); err != nil {
		return time.Time{}, fmt.Errorf("last full check: %w", err)
	}
	return optTS(s)
}
