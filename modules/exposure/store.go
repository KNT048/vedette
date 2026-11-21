package exposure

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// querier is what both *sql.DB (reads) and *sql.Tx (inside a write) offer.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface{ Scan(dest ...any) error }

const targetColumns = `id, kind, value, coalesce(method, proof_method, ''), CASE WHEN typed = 1 THEN coalesce(ip_token, '') ELSE token END, verified_at, last_check, commitment_by, commitment_at, commitment_version, commitment_sentence, commitment_user_id, commitment_method, created_at, last_scan_at, terms_version, terms_by, terms_at, terms_text, terms_user_id, terms_method, terms_disruptive, typed`

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
		t                                                                      Target
		kind                                                                   string
		verified, check, by, byAt, noticeVer, noticeText, uid, method, scanned sql.NullString
		tVer, tBy, tAt, tText, tUID, tMethod                                   sql.NullString
		tDisruptive, typed                                                     int
		created                                                                string
	)
	if err := s.Scan(&t.ID, &kind, &t.Value, &t.Method, &t.Token, &verified, &check, &by, &byAt, &noticeVer, &noticeText, &uid, &method, &created, &scanned, &tVer, &tBy, &tAt, &tText, &tUID, &tMethod, &tDisruptive, &typed); err != nil {
		return Target{}, err
	}
	t.Kind, t.Typed = Kind(kind), typed == 1
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
	if by.Valid && byAt.Valid {
		t.Commitment = &Commitment{By: by.String, At: byAt.String}
		if noticeVer.Valid && noticeText.Valid {
			t.Commitment.Version, t.Commitment.Sentence = &noticeVer.String, &noticeText.String
			t.Commitment.UserID, t.Commitment.Method = uid.String, method.String
		}
	}
	if tVer.Valid && tBy.Valid && tAt.Valid && tText.Valid {
		t.Terms = &Terms{Version: tVer.String, By: tBy.String, At: tAt.String, Text: tText.String, UserID: tUID.String, Method: tMethod.String, Disruptive: tDisruptive == 1}
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

// latestResult is what the target list shows of a target's newest snapshot: its counts and its first open ports, each with the
// appliance it names (appliance.go; the devices are added by the service).
type latestResult struct {
	Counts     Counts
	Ports      []PortRow
	FinishedAt *string // when the newest scan ended; nil while its OpenVAS step runs or when not known
}

// latestResults returns the counts and the first MaxOpenPorts open ports of the newest snapshot of every target that has one.
func latestResults(ctx context.Context, q querier) (map[string]latestResult, error) {
	rows, err := q.QueryContext(ctx, `SELECT s.target_id, s.counts, s.ports, s.admin_panels, s.services, s.finished_at FROM exp_snapshot s
		WHERE s.date = (SELECT max(date) FROM exp_snapshot WHERE target_id = s.target_id)`)
	if err != nil {
		return nil, fmt.Errorf("latest counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]latestResult{}
	for rows.Next() {
		var id, doc, ports, admin, services string
		var fin sql.NullString
		var r latestResult
		if err := rows.Scan(&id, &doc, &ports, &admin, &services, &fin); err != nil {
			return nil, fmt.Errorf("latest counts: %w", err)
		}
		if err := json.Unmarshal([]byte(doc), &r.Counts); err != nil {
			return nil, fmt.Errorf("latest result of %s: %w", id, err)
		}
		svc, err := recountAdmin(&r.Counts, admin, ports, services, &r.Ports)
		if err != nil {
			return nil, fmt.Errorf("latest result of %s: %w", id, err)
		}
		if len(r.Ports) > MaxOpenPorts {
			r.Ports = r.Ports[:MaxOpenPorts]
		}
		nameAppliances(r.Ports, nil, svc)
		r.FinishedAt = optText(fin)
		out[id] = r
	}
	return out, rows.Err()
}

func insertTarget(ctx context.Context, tx *sql.Tx, t Target) error {
	check, err := checkDoc(t.LastCheck)
	if err != nil {
		return err
	}
	token, ipToken, typed := t.Token, any(nil), 0
	if t.Typed { // a typed IP keeps its token in its own column: the token column of an IP stays empty
		token, ipToken, typed = "", t.Token, 1
	}
	method, proofMethod := t.Method, ""
	if t.Typed {
		method, proofMethod = "", t.Method
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO exp_target (id, kind, value, method, token, verified_at, last_check, created_at, typed, ip_token, proof_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, string(t.Kind), t.Value, nullString(method), token, tsOrNil(t.VerifiedAt), check, store.FormatTS(t.CreatedAt), typed, ipToken, nullString(proofMethod))
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

// renewIP sets the last sighting of an IP: verified_at is the time, and with it the 30 days (INV-4). An IP a person typed in that the
// box sees as its own egress address becomes the box's: that proof is the stronger one.
func renewIP(ctx context.Context, tx *sql.Tx, id string, now time.Time, msg string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET typed = 0, ip_token = NULL, proof_method = NULL WHERE id = ? AND typed = 1`, id); err != nil {
		return fmt.Errorf("renewing target %s: %w", id, err)
	}
	return updateCheck(ctx, tx, id, Check{At: store.FormatTS(now), OK: true, Message: msg}, now, methodBoxEgress)
}

// recordIPProof records a check of a typed IP's proof: the check, and when it passed (verifiedAt not zero) the time the 30 days run
// from and how it was proved.
func recordIPProof(ctx context.Context, tx *sql.Tx, id string, c Check, verifiedAt time.Time, method string) error {
	doc, err := checkDoc(&c)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE exp_target SET last_check = ?, verified_at = coalesce(?, verified_at), proof_method = coalesce(?, proof_method) WHERE id = ? AND typed = 1`,
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
	_, err := tx.ExecContext(ctx, `UPDATE exp_target SET commitment_by = ?, commitment_at = ?, commitment_version = ?, commitment_sentence = ?, commitment_user_id = ?, commitment_method = ? WHERE id = ?`,
		by, store.FormatTS(at), n.Version, n.Text, nullIf(uid), nullIf(method), id)
	if err != nil {
		return fmt.Errorf("recording the commitment of %s: %w", id, err)
	}
	return nil
}

// ---- snapshots ----

// snapshotDocs encodes the JSON columns of a snapshot, in the order of the INSERT of upsertSnapshot.
func snapshotDocs(c Content, counts Counts) ([11]string, error) {
	var docs [11]string
	for i, v := range []any{nz(c.Hosts), nz(c.Ports), nz(c.AdminPanels), nz(c.Certs), counts, storedServices(c), nz(c.Checks), nz(c.NotChecked), nz(c.WebFindings), nz(c.Greenbone),
		nz(c.Scripts)} {
		b, err := json.Marshal(v)
		if err != nil {
			return docs, fmt.Errorf("encoding snapshot: %w", err)
		}
		docs[i] = string(b)
	}
	return docs, nil
}

// storedService is a service as the services column keeps it: with the safe templates that ran on it (INV-23), so the column is
// the one place a snapshot's service evidence lives.
type storedService struct {
	ServiceRow
	Templates []TemplateRow `json:"templates"`
}

func storedServices(c Content) []storedService {
	out := make([]storedService, 0, len(c.Services))
	for _, x := range c.Services {
		row := storedService{ServiceRow: x, Templates: []TemplateRow{}}
		for _, t := range c.Templates {
			if t.IP == x.IP && t.Port == x.Port {
				row.Templates = append(row.Templates, t)
			}
		}
		out = append(out, row)
	}
	return out
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
	run, err := json.Marshal(snap.GreenboneRun)
	if err != nil {
		return fmt.Errorf("encoding snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM exp_snapshot WHERE target_id = ? AND date = ?`, targetID, snap.Date); err != nil {
		return fmt.Errorf("replacing snapshot: %w", err)
	}
	started := cmp.Or(snap.StartedAt, snap.ScannedAt)
	_, err = tx.ExecContext(ctx, `INSERT INTO exp_snapshot (id, target_id, date, scanned_at, hosts, ports, admin_panels, certs, counts, services, checks, not_checked, web_findings, greenbone, scripts, greenbone_run, started_at, finished_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snap.ID, targetID, snap.Date, snap.ScannedAt, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8], d[9], d[10], string(run), started, snap.FinishedAt)
	if err != nil {
		return fmt.Errorf("inserting snapshot: %w", err)
	}
	// "Last scanned" is the start of the newest scan, the time every page names a scan by
	if _, err := tx.ExecContext(ctx, `UPDATE exp_target SET last_scan_at = ? WHERE id = ?`, started, targetID); err != nil {
		return fmt.Errorf("updating last scan: %w", err)
	}
	return nil
}

// recountAdmin sets counts.AdminPanels as loadSnapshot counts it (INV-33: an admin page a port names counts when the snapshot is
// read, also in a snapshot stored before the fingerprint existed), from the stored admin, ports and services columns. It returns the
// service rows, and the port rows into ports when it is not nil.
func recountAdmin(counts *Counts, admin, ports, services string, into *[]PortRow) ([]ServiceRow, error) {
	var admins []AdminRow
	var rows []PortRow
	var stored []storedService
	for _, d := range []struct {
		doc string
		to  any
	}{{admin, &admins}, {ports, &rows}, {services, &stored}} {
		if err := json.Unmarshal([]byte(d.doc), d.to); err != nil {
			return nil, err
		}
	}
	svc := make([]ServiceRow, 0, len(stored))
	for _, x := range stored {
		svc = append(svc, x.ServiceRow)
	}
	counts.AdminPanels += len(applianceAdmins(admins, rows, svc)) - len(admins) // the rows it adds; the stored ones are counted
	if into != nil {
		*into = rows
	}
	return svc, nil
}

func listSnapshotMetas(ctx context.Context, q querier, targetID string) ([]SnapshotMeta, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, date, scanned_at, coalesce(started_at, scanned_at), finished_at, counts, admin_panels, ports, services FROM exp_snapshot WHERE target_id = ? ORDER BY date DESC`, targetID)
	if err != nil {
		return nil, fmt.Errorf("snapshots: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []SnapshotMeta{}
	for rows.Next() {
		var m SnapshotMeta
		var doc, admin, ports, services string
		var fin sql.NullString
		if err := rows.Scan(&m.ID, &m.Date, &m.ScannedAt, &m.StartedAt, &fin, &doc, &admin, &ports, &services); err != nil {
			return nil, fmt.Errorf("snapshots: %w", err)
		}
		if err := json.Unmarshal([]byte(doc), &m.Counts); err != nil {
			return nil, fmt.Errorf("snapshot %s counts: %w", m.ID, err)
		}
		if _, err := recountAdmin(&m.Counts, admin, ports, services, nil); err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", m.ID, err)
		}
		m.FinishedAt = optText(fin)
		out = append(out, m)
	}
	return out, rows.Err()
}

// loadSnapshot returns the snapshot of one day, or ok=false when there is none.
func loadSnapshot(ctx context.Context, q querier, targetID, date string) (Snapshot, bool, error) {
	var s Snapshot
	var hosts, ports, admin, certs, counts, services, checks, notChecked, web, gb, scripts, gbRun string
	var fin sql.NullString
	var stored []storedService
	err := q.QueryRowContext(ctx, `SELECT id, date, scanned_at, coalesce(started_at, scanned_at), finished_at, hosts, ports, admin_panels, certs, counts, services, checks, not_checked, web_findings, greenbone, scripts, greenbone_run FROM exp_snapshot WHERE target_id = ? AND date = ?`, targetID, date).
		Scan(&s.ID, &s.Date, &s.ScannedAt, &s.StartedAt, &fin, &hosts, &ports, &admin, &certs, &counts, &services, &checks, &notChecked, &web, &gb, &scripts, &gbRun)
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
		{services, &stored}, {checks, &s.Checks}, {notChecked, &s.NotChecked}, {web, &s.WebFindings}, {gb, &s.Greenbone}, {scripts, &s.Scripts},
		{gbRun, &s.GreenboneRun}} {
		if err := json.Unmarshal([]byte(d.doc), d.to); err != nil {
			return Snapshot{}, false, fmt.Errorf("snapshot %s: %w", s.ID, err)
		}
	}
	s.Services, s.Templates = []ServiceRow{}, []TemplateRow{}
	for _, x := range stored {
		s.Services = append(s.Services, x.ServiceRow)
		s.Templates = append(s.Templates, x.Templates...)
	}
	s.Content = Content{Hosts: nz(s.Hosts), Ports: nz(s.Ports), AdminPanels: nz(s.AdminPanels), Certs: nz(s.Certs),
		Services: s.Services, Templates: s.Templates, Checks: nz(s.Checks), NotChecked: nz(s.NotChecked), WebFindings: nz(s.WebFindings), Greenbone: nz(s.Greenbone),
		Scripts: nz(s.Scripts)}
	s.FinishedAt = optText(fin)
	// An appliance's admin page that a snapshot of an older release (or an older rule) did not list counts when it is read.
	listed := len(s.AdminPanels)
	s.AdminPanels = applianceAdmins(s.AdminPanels, s.Ports, s.Services)
	s.Counts.AdminPanels += len(s.AdminPanels) - listed
	s.GreenboneRun = storedGreenboneRun(s.GreenboneRun, s.Content)
	if s.GreenboneRun.State == GBRunStopped { // the waiting line, or the cut line of an older version, says why it stopped
		s.NotChecked = gbCutOffWith(s.NotChecked, gbStoppedLine(s.GreenboneRun.Stop, false))
	}
	return s, true, nil
}

// storedGreenboneRun is the state of a stored OpenVAS step, checked: a state that is not one, a start that is not a
// time, or an address that is not one is not believed. A snapshot older than the column ('{}') gets the state its lines say (a
// domain's lines carry the address in front): a check row is done; the old waiting line or the stop line is stopped (nothing
// runs it any more); a failure line is failed; else it did not run.
// A stopped step stored before stop reasons were kept gets the one its line proves (oldStop).
func storedGreenboneRun(r GreenboneRun, c Content) GreenboneRun {
	r = storedGreenboneState(r, c)
	if r.State == GBRunStopped && r.Stop == nil {
		r.Stop = oldStop(c.NotChecked)
	}
	return r
}

// oldStop is the reason of a stopped OpenVAS step stored before the reason was kept, when its line proves one; nil otherwise.
// Older versions stored two lines for five causes. The waiting line (gbPending, or the older "OpenVAS started at …") or the line
// start-up put in its place (notGBCutOff) means no running Vedette ended the step: it stopped or crashed while OpenVAS ran and found the
// step still running when it started again, which is StopRestart (a shutdown that outlasted its wait included). notGBStopped and
// notGBStoppedSome were written by a running Vedette for a Stop, a shutdown, the module switched off and the terms withdrawn alike,
// so they prove none of them: nil, and the page says the reason was not recorded.
func oldStop(rows []NotCheckedRow) *GreenboneStop {
	if slices.ContainsFunc(rows, func(n NotCheckedRow) bool { return n.Kind == "greenbone" && cutLine(n.Text) }) {
		return &GreenboneStop{Reason: StopRestart}
	}
	return nil
}

// storedGreenboneState is storedGreenboneRun without the reason of an older stop.
func storedGreenboneState(r GreenboneRun, c Content) GreenboneRun {
	r.StartedAt, r.EndedAt = storedTS(r.StartedAt), storedTS(r.EndedAt)
	if r.Stop != nil && (r.State != GBRunStopped || !slices.Contains(stopReasons, r.Stop.Reason)) {
		r.Stop = nil
	}
	addrs := []GreenboneAddr{}
	for _, a := range r.Addresses {
		if ip, err := netip.ParseAddr(a.IP); err == nil && ip.String() == a.IP && slices.Contains(gbRunStates, a.State) && len(addrs) < maxGBAddrs {
			addrs = append(addrs, a)
		}
	}
	r.Addresses = addrs
	if slices.Contains(gbRunStates, r.State) {
		return r
	}
	r.State = GBRunNotRun
	for _, n := range c.NotChecked {
		switch {
		case n.Kind != "greenbone":
		case strings.Contains(n.Text, "OpenVAS started at "), strings.HasSuffix(n.Text, notGBStopped):
			r.State = GBRunStopped
		case r.State == GBRunStopped:
		case strings.HasSuffix(n.Text, notGBFail), strings.HasSuffix(n.Text, notGBUnread), strings.HasSuffix(n.Text, notGBSlowAnswer), strings.HasSuffix(n.Text, notGBSlowOld):
			r.State = GBRunFailed
		}
	}
	if r.State != GBRunStopped && slices.ContainsFunc(c.Checks, func(k CheckRow) bool { return k.Kind == "greenbone" }) {
		r.State = GBRunDone
	}
	return r
}

// storedTS is a stored time of the OpenVAS state, checked: one that is not a time is not believed (nil).
func storedTS(v *string) *string {
	if v == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, *v)
	if err != nil {
		return nil
	}
	at := store.FormatTS(t)
	return &at
}

// maxGBAddrs bounds the addresses of a stored OpenVAS state (a domain's run reaches at most MaxDeepIPs).
const maxGBAddrs = 16

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

// ScanRecord is one stored scan of a public target (one per target and day: a rescan the same day replaces it), for Settings ›
// Scanning › History.
type ScanRecord struct {
	TargetID, Target, ScannedAt string
	Date                        string  // the snapshot's day (one per target and day): with TargetID, the scan's identity
	StartedAt                   string  // when the scan started (ScannedAt on a snapshot older than the column)
	FinishedAt                  *string // when its last step ended; nil while OpenVAS runs or when not known
	Counts                      Counts
	NotChecked                  int    // steps the scan stored as not checked (OpenVAS off, a page ZAP could not scan, …)
	Greenbone                   string // the OpenVAS run's state as stored (done, partial, failed, stopped, not_run); "" when none
}

// RecentScans lists the newest stored scans of every target, newest first, at most limit (1..500). Read only. Only a scan that
// reached its snapshot is stored: one that failed before has no row (the run lives in memory, INV-8).
func (s *Service) RecentScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	live := s.gbLive() // before the read, as SnapshotOf: a step "running" that no run scans was cut by a restart and reads as stopped
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT s.id, s.date, s.target_id, t.value, s.scanned_at, coalesce(s.started_at, s.scanned_at), s.finished_at, s.counts,
  coalesce(json_array_length(s.not_checked), 0), coalesce(json_extract(s.greenbone_run, '$.state'), ''), s.admin_panels, s.ports, s.services
FROM exp_snapshot s JOIN exp_target t ON t.id = s.target_id ORDER BY coalesce(s.started_at, s.scanned_at) DESC LIMIT ?`, max(1, min(500, limit)))
	if err != nil {
		return nil, fmt.Errorf("exposure: recent scans: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ScanRecord{}
	for rows.Next() {
		var r ScanRecord
		var id, doc, admin, ports, services string
		var fin sql.NullString
		if err := rows.Scan(&id, &r.Date, &r.TargetID, &r.Target, &r.ScannedAt, &r.StartedAt, &fin, &doc, &r.NotChecked, &r.Greenbone, &admin, &ports, &services); err != nil {
			return nil, fmt.Errorf("exposure: recent scans: %w", err)
		}
		if err := json.Unmarshal([]byte(doc), &r.Counts); err != nil {
			return nil, fmt.Errorf("exposure: recent scan of %s: %w", r.TargetID, err)
		}
		if _, err := recountAdmin(&r.Counts, admin, ports, services, nil); err != nil {
			return nil, fmt.Errorf("exposure: recent scan of %s: %w", r.TargetID, err)
		}
		r.FinishedAt = optText(fin)
		if r.Greenbone == GBRunRunning && id != live {
			r.Greenbone = GBRunStopped
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
