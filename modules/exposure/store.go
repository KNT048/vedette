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

const targetColumns = `id, kind, value, coalesce(method, ''), token, verified_at, last_check, commitment_by, commitment_at, commitment_version, commitment_sentence, commitment_user_id, commitment_method, created_at, last_scan_at`

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
		t                                                                      Target
		kind                                                                   string
		verified, check, by, byAt, noticeVer, noticeText, uid, method, scanned sql.NullString
		created                                                                string
	)
	if err := s.Scan(&t.ID, &kind, &t.Value, &t.Method, &t.Token, &verified, &check, &by, &byAt, &noticeVer, &noticeText, &uid, &method, &created, &scanned); err != nil {
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
		if noticeVer.Valid && noticeText.Valid {
			t.Commitment.Version, t.Commitment.Sentence = &noticeVer.String, &noticeText.String
			t.Commitment.UserID, t.Commitment.Method = uid.String, method.String
		}
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

// latestResult is what the target list shows of a target's newest snapshot: its counts and its first open ports.
type latestResult struct {
	Counts Counts
	Ports  []PortRow
}

// latestResults returns the counts and the first MaxOpenPorts open ports of the newest snapshot of every target that has one.
func latestResults(ctx context.Context, q querier) (map[string]latestResult, error) {
	rows, err := q.QueryContext(ctx, `SELECT s.target_id, s.counts, s.ports FROM exp_snapshot s
		WHERE s.date = (SELECT max(date) FROM exp_snapshot WHERE target_id = s.target_id)`)
	if err != nil {
		return nil, fmt.Errorf("latest counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]latestResult{}
	for rows.Next() {
		var id, doc, ports string
		var r latestResult
		if err := rows.Scan(&id, &doc, &ports); err != nil {
			return nil, fmt.Errorf("latest counts: %w", err)
		}
		if err := json.Unmarshal([]byte(doc), &r.Counts); err != nil {
			return nil, fmt.Errorf("latest counts of %s: %w", id, err)
		}
		if err := json.Unmarshal([]byte(ports), &r.Ports); err != nil {
			return nil, fmt.Errorf("latest ports of %s: %w", id, err)
		}
		if len(r.Ports) > MaxOpenPorts {
			r.Ports = r.Ports[:MaxOpenPorts]
		}
		out[id] = r
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

func setCommitment(ctx context.Context, tx *sql.Tx, id, by string, at time.Time, n Notice, uid, method string) error {
	_, err := tx.ExecContext(ctx, `UPDATE exp_target SET commitment_by = ?, commitment_at = ?, commitment_version = ?, commitment_sentence = ?, commitment_user_id = ?, commitment_method = ? WHERE id = ?`,
		by, store.FormatTS(at), n.Version, n.Text, nullIf(uid), nullIf(method), id)
	if err != nil {
		return fmt.Errorf("recording the commitment of %s: %w", id, err)
	}
	return nil
}

// ---- snapshots ----

// snapshotDocs encodes the JSON columns of a snapshot, in the order of the INSERT of upsertSnapshot.
func snapshotDocs(c Content, counts Counts) ([9]string, error) {
	var docs [9]string
	for i, v := range []any{nz(c.Hosts), nz(c.Ports), nz(c.AdminPanels), nz(c.Certs), counts, nz(c.Services), nz(c.Checks), nz(c.NotChecked), nz(c.WebFindings)} {
		b, err := json.Marshal(v)
		if err != nil {
			return docs, fmt.Errorf("encoding snapshot: %w", err)
		}
		docs[i] = string(b)
	}
	return docs, nil
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
	d, err := snapshotDocs(snap.Content, snap.Counts)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM exp_snapshot WHERE target_id = ? AND date = ?`, targetID, snap.Date); err != nil {
		return fmt.Errorf("replacing snapshot: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO exp_snapshot (id, target_id, date, scanned_at, hosts, ports, admin_panels, certs, counts, services, checks, not_checked, web_findings)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snap.ID, targetID, snap.Date, snap.ScannedAt, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8])
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
	var hosts, ports, admin, certs, counts, services, checks, notChecked, web string
	err := q.QueryRowContext(ctx, `SELECT id, date, scanned_at, hosts, ports, admin_panels, certs, counts, services, checks, not_checked, web_findings FROM exp_snapshot WHERE target_id = ? AND date = ?`, targetID, date).
		Scan(&s.ID, &s.Date, &s.ScannedAt, &hosts, &ports, &admin, &certs, &counts, &services, &checks, &notChecked, &web)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("snapshot %s: %w", date, err)
	}
	for _, d := range []struct {
		doc string
		to  any
	}{{hosts, &s.Hosts}, {ports, &s.Ports}, {admin, &s.AdminPanels}, {certs, &s.Certs}, {counts, &s.Counts},
		{services, &s.Services}, {checks, &s.Checks}, {notChecked, &s.NotChecked}, {web, &s.WebFindings}} {
		if err := json.Unmarshal([]byte(d.doc), d.to); err != nil {
			return Snapshot{}, false, fmt.Errorf("snapshot %s: %w", s.ID, err)
		}
	}
	s.Content = Content{Hosts: nz(s.Hosts), Ports: nz(s.Ports), AdminPanels: nz(s.AdminPanels), Certs: nz(s.Certs),
		Services: nz(s.Services), Checks: nz(s.Checks), NotChecked: nz(s.NotChecked), WebFindings: nz(s.WebFindings)}
	return s, true, nil
}

// previousSnapshot returns the newest snapshot of `date` or an earlier day (the last observation: a scan earlier today counts), or
// ok=false when there is none.
func previousSnapshot(ctx context.Context, q querier, targetID, date string) (Snapshot, bool, error) {
	var d string
	err := q.QueryRowContext(ctx, `SELECT date FROM exp_snapshot WHERE target_id = ? AND date <= ? ORDER BY date DESC LIMIT 1`, targetID, date).Scan(&d)
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, false, nil
	}
	if err != nil {
		return Snapshot{}, false, fmt.Errorf("previous snapshot: %w", err)
	}
	return loadSnapshot(ctx, q, targetID, d)
}

// ---- attempts ----

// recentAttempts returns the times of the attempts of the last hour, oldest first, after dropping
// every attempt older than 24 hours.
func recentAttempts(ctx context.Context, tx *sql.Tx, now time.Time) ([]time.Time, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM exp_attempt WHERE ts < ?`, store.FormatTS(now.Add(-24*time.Hour))); err != nil {
		return nil, fmt.Errorf("pruning attempts: %w", err)
	}
	return attemptsInLastHour(ctx, tx, now)
}

// attemptsInLastHour reads the times of the attempts of the last hour, oldest first, without writing.
func attemptsInLastHour(ctx context.Context, q querier, now time.Time) ([]time.Time, error) {
	rows, err := q.QueryContext(ctx, `SELECT ts FROM exp_attempt WHERE ts > ? ORDER BY ts`, store.FormatTS(now.Add(-time.Hour)))
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
// short interval do not, so a full check still runs once an hour). answered says the services agreed on an address:
// only a full check that was answered moves last_full_ok_at, the fact that makes an IP show as paused (INV-13).
func saveRun(ctx context.Context, tx *sql.Tx, at time.Time, ok bool, message string, deep, answered bool) error {
	if len(message) > 1000 {
		message = message[:1000]
	}
	o, d, f := 0, 0, 0
	if ok {
		o = 1
	}
	if deep {
		d = 1
		if answered {
			f = 1
		}
	}
	ts := store.FormatTS(at)
	if _, err := tx.ExecContext(ctx, `UPDATE exp_setting SET last_run_at = ?, last_run_ok = ?, last_run_message = ?,
		last_deep_at = CASE WHEN ? = 1 THEN ? ELSE last_deep_at END, last_full_ok_at = CASE WHEN ? = 1 THEN ? ELSE last_full_ok_at END WHERE id = 1`, ts, o, message, d, ts, f, ts); err != nil {
		return fmt.Errorf("saving the last detection: %w", err)
	}
	return nil
}

// loadLastFullOK returns when the last full check that got an answer ran; the zero time when none did.
func loadLastFullOK(ctx context.Context, q querier) (time.Time, error) {
	var s sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT last_full_ok_at FROM exp_setting WHERE id = 1`).Scan(&s); err != nil {
		return time.Time{}, fmt.Errorf("last answered full check: %w", err)
	}
	return optTS(s)
}

// loadLastDeep returns when the last full check ran; the zero time when none did.
func loadLastDeep(ctx context.Context, q querier) (time.Time, error) {
	var s sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT last_deep_at FROM exp_setting WHERE id = 1`).Scan(&s); err != nil {
		return time.Time{}, fmt.Errorf("last full check: %w", err)
	}
	return optTS(s)
}

// ---- the Ignored list (D-79 (3), INV-14) ----

// loadIgnored returns the Ignored list, newest first.
func loadIgnored(ctx context.Context, q querier) ([]IgnoredIP, error) {
	rows, err := q.QueryContext(ctx, `SELECT value, ignored_by, ignored_at FROM exp_ignored ORDER BY ignored_at DESC, value`)
	if err != nil {
		return nil, fmt.Errorf("ignored list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []IgnoredIP{}
	for rows.Next() {
		var x IgnoredIP
		if err := rows.Scan(&x.Value, &x.IgnoredBy, &x.IgnoredAt); err != nil {
			return nil, fmt.Errorf("ignored list: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// ignoredSet is the Ignored list as a set of addresses.
func ignoredSet(ctx context.Context, q querier) (map[string]bool, error) {
	l, err := loadIgnored(ctx, q)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(l))
	for _, x := range l {
		set[x.Value] = true
	}
	return set, nil
}

func countIgnored(ctx context.Context, q querier) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM exp_ignored`).Scan(&n); err != nil {
		return 0, fmt.Errorf("counting ignored IPs: %w", err)
	}
	return n, nil
}

func insertIgnored(ctx context.Context, tx *sql.Tx, ip, by string, at time.Time) error {
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO exp_ignored (value, ignored_by, ignored_at) VALUES (?, ?, ?)`, ip, by, store.FormatTS(at)); err != nil {
		return fmt.Errorf("ignoring %s: %w", ip, err)
	}
	return nil
}

// deleteIgnored removes an IP from the list; false when it was not there.
func deleteIgnored(ctx context.Context, tx *sql.Tx, ip string) (bool, error) {
	res, err := tx.ExecContext(ctx, `DELETE FROM exp_ignored WHERE value = ?`, ip)
	if err != nil {
		return false, fmt.Errorf("restoring %s: %w", ip, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// nullIf stores an empty string as NULL (a commitment without a person behind it, which only tests make).
func nullIf(s string) any {
	if s == "" {
		return nil
	}
	return s
}
