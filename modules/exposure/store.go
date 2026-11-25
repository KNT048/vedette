package exposure

import (
	"cmp"
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

// targetColumns are the columns of a target as scanTarget reads them, from exp_target t with its two consents (c: the scan
// confirmation, r: the testing terms) and the start of its newest run.
const targetColumns = `t.id, t.kind, t.value, coalesce(t.method, t.proof_method, ''), CASE WHEN t.kind = 'ip' AND t.origin = 'person' THEN coalesce(t.ip_token, '') ELSE t.token END,
	t.verified_at, t.last_check, t.created_at, t.origin, t.parent_id, t.scope_mode, t.enabled,
	c.by_name, c.at, c.version, c.text, c.user_id, c.method,
	r.version, r.by_name, r.at, r.text, r.user_id, r.method, coalesce(r.disruptive, 0),
	(SELECT max(started_at) FROM core_run WHERE module = 'exposure' AND subject_kind = 'target' AND subject_id = t.id)`

// targetFrom is the FROM of targetColumns.
const targetFrom = ` FROM exp_target t LEFT JOIN exp_consent c ON c.target_id = t.id AND c.kind = 'commitment'
	LEFT JOIN exp_consent r ON r.target_id = t.id AND r.kind = 'terms'`

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

// optText is a nullable text column as a pointer: nil for NULL.
func optText(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}

func tsOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return store.FormatTS(t)
}

func scanTarget(s scanner) (Target, error) {
	var (
		t                                            Target
		kind, origin, created                        string
		verified, check, parent, scope, scanned      sql.NullString
		by, byAt, noticeVer, noticeText, uid, method sql.NullString
		tVer, tBy, tAt, tText, tUID, tMethod         sql.NullString
		enabled, tDisruptive                         int
	)
	if err := s.Scan(&t.ID, &kind, &t.Value, &t.Method, &t.Token, &verified, &check, &created, &origin, &parent, &scope, &enabled,
		&by, &byAt, &noticeVer, &noticeText, &uid, &method, &tVer, &tBy, &tAt, &tText, &tUID, &tMethod, &tDisruptive, &scanned); err != nil {
		return Target{}, err
	}
	t.Kind, t.Origin, t.Enabled = Kind(kind), Origin(origin), enabled == 1
	t.Typed = t.Kind == KindIP && t.Origin == OriginPerson
	t.ParentID, t.ScopeMode = parent.String, ScopeMode(scope.String)
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
		doc := storedCheck{Check: t.LastCheck}
		if err := json.Unmarshal([]byte(check.String), &doc); err != nil {
			return Target{}, fmt.Errorf("last_check: %w", err)
		}
		t.LastCheck.Covers = doc.Covers
		t.LastCheck.Via = doc.Via
	}
	if by.Valid && byAt.Valid && noticeVer.Valid && noticeText.Valid {
		t.Commitment = &Commitment{By: by.String, At: byAt.String, Version: &noticeVer.String, Sentence: &noticeText.String,
			UserID: uid.String, Method: method.String}
	}
	if tVer.Valid && tBy.Valid && tAt.Valid && tText.Valid {
		t.Terms = &Terms{Version: tVer.String, By: tBy.String, At: tAt.String, Text: tText.String, UserID: tUID.String, Method: tMethod.String, Disruptive: tDisruptive == 1}
	}
	return t, nil
}

func loadTarget(ctx context.Context, q querier, id string) (Target, error) {
	t, err := scanTarget(q.QueryRowContext(ctx, `SELECT `+targetColumns+targetFrom+` WHERE t.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, ErrNotFound
	}
	if err != nil {
		return Target{}, fmt.Errorf("target %s: %w", id, err)
	}
	return t, nil
}

func loadTargetByValue(ctx context.Context, q querier, value string) (Target, bool, error) {
	t, err := scanTarget(q.QueryRowContext(ctx, `SELECT `+targetColumns+targetFrom+` WHERE t.value = ?`, value))
	if errors.Is(err, sql.ErrNoRows) {
		return Target{}, false, nil
	}
	if err != nil {
		return Target{}, false, fmt.Errorf("target %s: %w", value, err)
	}
	return t, true, nil
}

func listTargets(ctx context.Context, q querier) ([]Target, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+targetColumns+targetFrom+` ORDER BY t.created_at, t.rowid`)
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

func insertTarget(ctx context.Context, tx *sql.Tx, t Target) error {
	check, err := checkDoc(t.LastCheck)
	if err != nil {
		return err
	}
	origin := t.Origin
	if origin == "" {
		origin = OriginPerson
	}
	token, ipToken := t.Token, any(nil)
	method, proofMethod := t.Method, ""
	if t.Kind == KindIP && origin == OriginPerson { // a typed IP keeps its token and its proof in their own columns
		token, ipToken = "", nullString(t.Token)
		method, proofMethod = "", t.Method
	}
	var scope any
	if t.Kind == KindDomain {
		scope = string(cmp.Or(t.ScopeMode, ScopeAll))
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO exp_target (id, parent_id, kind, value, origin, scope_mode, enabled, method, token, verified_at, last_check, ip_token, proof_method, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, nullString(t.ParentID), string(t.Kind), t.Value, string(origin), scope, nullString(method), token, tsOrNil(t.VerifiedAt), check,
		ipToken, nullString(proofMethod), store.FormatTS(t.CreatedAt))
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

// withdrawProof records check c and clears the proof of target id (verified_at, method): it is unproved from now (INV-1).
func withdrawProof(ctx context.Context, tx *sql.Tx, id string, c Check) error {
	doc, err := checkDoc(&c)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET last_check = ?, verified_at = NULL, method = NULL WHERE id = ?`, doc, id); err != nil {
		return fmt.Errorf("withdrawing the proof of target %s: %w", id, err)
	}
	return nil
}

func checkDoc(c *Check) (any, error) {
	if c == nil {
		return nil, nil
	}
	b, err := json.Marshal(storedCheck{Check: c, Covers: c.Covers, Via: c.Via})
	if err != nil {
		return nil, fmt.Errorf("encoding check: %w", err)
	}
	return string(b), nil
}

// storedCheck is the column's JSON: the check as the API shows it, plus Covers, which only the box reads.
type storedCheck struct {
	*Check
	Covers bool   `json:"covers,omitempty"`
	Via    string `json:"via,omitempty"`
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// renewIP sets the last sighting of an IP: verified_at is the time, and with it the ValidDays (INV-4). An IP a person typed in that the
// box sees as its own egress address becomes the box's: that proof is the stronger one.
func renewIP(ctx context.Context, tx *sql.Tx, id string, now time.Time, msg string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET origin = 'box', ip_token = NULL, proof_method = NULL WHERE id = ? AND kind = 'ip' AND origin = 'person'`, id); err != nil {
		return fmt.Errorf("renewing target %s: %w", id, err)
	}
	return updateCheck(ctx, tx, id, Check{At: store.FormatTS(now), OK: true, Message: msg}, now, methodBoxEgress)
}

// recordIPProof records a check of a typed IP's proof: the check, and when it passed (verifiedAt not zero) the time the ValidDays run
// from and how it was proved.
func recordIPProof(ctx context.Context, tx *sql.Tx, id string, c Check, verifiedAt time.Time, method string) error {
	doc, err := checkDoc(&c)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE exp_target SET last_check = ?, verified_at = coalesce(?, verified_at), proof_method = coalesce(?, proof_method) WHERE id = ? AND kind = 'ip' AND origin = 'person'`,
		doc, tsOrNil(verifiedAt), nullString(method), id)
	if err != nil {
		return fmt.Errorf("recording the proof of target %s: %w", id, err)
	}
	return nil
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
	return putConsent(ctx, tx, id, consentCommitment, consentRow{Version: n.Version, Text: n.Text, By: by, UserID: uid, Method: method, At: at})
}

// The kinds of exp_consent.
const (
	consentCommitment = "commitment"
	consentTerms      = "terms"
)

// consentRow is one row of exp_consent.
type consentRow struct {
	Version, Text, By, UserID, Method string
	Disruptive                        bool
	At                                time.Time
}

// putConsent records what a person accepted for a target, replacing the earlier one of the same kind.
func putConsent(ctx context.Context, tx *sql.Tx, id, kind string, c consentRow) error {
	d := 0
	if c.Disruptive {
		d = 1
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO exp_consent (target_id, kind, version, text, by_name, user_id, method, disruptive, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (target_id, kind) DO UPDATE SET version = excluded.version, text = excluded.text, by_name = excluded.by_name,
		user_id = excluded.user_id, method = excluded.method, disruptive = excluded.disruptive, at = excluded.at`,
		id, kind, c.Version, c.Text, c.By, nullIf(c.UserID), nullIf(c.Method), d, store.FormatTS(c.At))
	if err != nil {
		return fmt.Errorf("recording the %s of %s: %w", kind, id, err)
	}
	return nil
}

// dropConsent removes what a person accepted for a target (a withdrawal).
func dropConsent(ctx context.Context, tx *sql.Tx, id, kind string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM exp_consent WHERE target_id = ? AND kind = ?`, id, kind); err != nil {
		return fmt.Errorf("withdrawing the %s of %s: %w", kind, id, err)
	}
	return nil
}

// nz makes a nil slice encode as [] and not as null.
func nz[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
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
	var at, msg sql.NullString
	var ok sql.NullInt64
	err := q.QueryRowContext(ctx, `SELECT last_run_at, last_run_ok, last_run_message FROM exp_setting WHERE id = 1`).Scan(&at, &ok, &msg)
	if err != nil {
		return BoxIP{}, fmt.Errorf("auto-detect settings: %w", err)
	}
	// On or off and how often are the detection's schedule (core_schedule, exposure.public_ip).
	if b.Auto, b.IntervalMin, _, err = autoSetting(ctx, q); err != nil {
		return BoxIP{}, fmt.Errorf("auto-detect schedule: %w", err)
	}
	if at.Valid {
		b.LastRun = &LastRun{At: at.String, OK: ok.Int64 == 1, Message: msg.String}
	}
	return b, nil
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

// ---- the Ignored list (INV-14) ----

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
