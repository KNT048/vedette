package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// What a scan finds new is told once: a service open now that was not before (new, or open again after a scan closed it) and an issue
// open now that was not before (writeScan's opened and newIssues, the OpenVAS step's new issues). Only an issue that carries a CVE
// exploited in the wild (Config.Exploited, the rule a finding's alert follows) goes to the alert channels at once; every other new row
// is counted in the daily summary (NewSince). A service
// missed once and seen again was never closed, a handled issue stays handled, and a row that moved with its name to the target that
// scans it now is new only when it was new to that target: so nothing is announced twice. The first scan of a target is its baseline and
// announces nothing.
//
// Each alert names the target that holds the rows (the asset, as external attack-surface products name it): a port the scan of a domain
// found on a name that its child target took over while the scan ran is announced on the child, with the scan that found it.

// Alert is one message for the alert channels: what one scan found new on one target. cmd/vedette sends it through notify's system
// notice path. Severity is critical, high or medium.
type Alert struct {
	ID       string // stable per scan, target and step, so a resend is recognised
	TargetID string
	Severity string
	Title    string
	Text     string
}

// The severities of an Alert (notify's names).
const (
	AlertCritical = "critical"
	AlertHigh     = "high"
	AlertMedium   = "medium"
)

// maxAlertLines bounds the lines of one alert; the rest are counted.
const maxAlertLines = 20

// OpenedService is a service a scan found open that was not before, with the target that holds its row now.
type OpenedService struct {
	TargetID string `json:"target_id"`
	PortRow
}

// NewIssue is an issue a scan found open that was not before, with the target that holds it now.
type NewIssue struct {
	ID       string `json:"id"`
	TargetID string `json:"target_id"`
	// Again is how a person had marked it (patched or mitigated) when the scan found it again; "" for an issue new to the target.
	Again string `json:"again,omitempty"`
}

// holders reads, in tx, the target that holds each service row of ids now (the scanned target when a row is gone).
func holders(ctx context.Context, tx *sql.Tx, scanned string, ports []PortRow, ids []string) ([]OpenedService, error) {
	out := make([]OpenedService, 0, len(ports))
	for i, p := range ports {
		at := scanned
		if i < len(ids) && ids[i] != "" {
			err := tx.QueryRowContext(ctx, `SELECT target_id FROM exp_service WHERE id = ?`, ids[i]).Scan(&at)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("the holder of a service: %w", err)
			}
		}
		out = append(out, OpenedService{TargetID: at, PortRow: p})
	}
	return out, nil
}

// issueHolders reads, in tx, the target that holds each issue of ids now; an issue no longer there (merged into another) is left out.
// again says how a person had marked the ones a scan opened again.
func issueHolders(ctx context.Context, tx *sql.Tx, ids []string, again map[string]string) ([]NewIssue, error) {
	out := make([]NewIssue, 0, len(ids))
	for _, id := range ids {
		var at string
		err := tx.QueryRowContext(ctx, `SELECT target_id FROM exp_issue WHERE id = ? AND state = 'open'`, id).Scan(&at)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("the holder of an issue: %w", err)
		}
		out = append(out, NewIssue{ID: id, TargetID: at, Again: again[id]})
	}
	return out, nil
}

// alertLine is one line of an alert with its rank (0 medium, 1 high, 2 critical); quiet lines (a port, an issue whose CVEs nobody is
// known to exploit) are only counted: they are in the daily summary.
type alertLine struct {
	rank  int
	quiet bool
	text  string
}

var severityRank = map[string]int{"critical": 2, "high": 1, "medium": 0}

// alertNews sends what a scan of scanned (run runID, step: "" for the scan, "openvas" for its OpenVAS step) found new: one alert per
// target that holds new rows. Nothing for the baseline, nothing new, or no Alert wired; a failure is logged, the rows stay stored.
func (s *Service) alertNews(ctx context.Context, scanned Target, runID, step string, first bool, opened []OpenedService, issues []NewIssue) {
	if s.cfg.Alert == nil || first || (len(opened) == 0 && len(issues) == 0) {
		return
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	for _, a := range s.alertsOf(actx, scanned, runID, step, opened, issues) {
		if err := s.cfg.Alert(actx, a); err != nil {
			s.cfg.Log.WarnContext(actx, "exposure: sending what a scan found new failed", "target", a.TargetID, "error", err)
		}
	}
}

// alertsOf builds the alerts of a scan's new rows, one per holding target, in the order the targets first appear.
func (s *Service) alertsOf(ctx context.Context, scanned Target, runID, step string, opened []OpenedService, issues []NewIssue) []Alert {
	lines := map[string][]alertLine{}
	var order []string
	add := func(target string, l alertLine) {
		if _, ok := lines[target]; !ok {
			order = append(order, target)
		}
		lines[target] = append(lines[target], l)
	}
	for _, p := range opened {
		text := fmt.Sprintf("New open port: %s:%d", p.IP, p.Port)
		if what := strings.TrimPrefix(strings.TrimSuffix(ServiceLabel(p.PortRow)+", "+p.Product, ", "), ", "); what != "" {
			text += " (" + what + ")"
		}
		add(p.TargetID, alertLine{rank: 1, quiet: true, text: text}) // a port carries no CVE: the daily summary counts it
	}
	db := s.cfg.DB.Reader()
	for _, i := range issues {
		var title, sev, where, cves string
		err := db.QueryRowContext(ctx, `SELECT i.title, i.severity, coalesce(x.ip || ':' || x.port, ''), i.cves FROM exp_issue i
			LEFT JOIN exp_service x ON x.id = i.service_id WHERE i.id = ?`, i.ID).Scan(&title, &sev, &where, &cves)
		if err != nil {
			continue // handled or gone since: nothing to announce
		}
		hit, err := s.exploitedOf(ctx, cves)
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "exposure: reading whether a CVE is exploited failed; the issue waits for the daily summary", "issue", i.ID, "error", err)
		}
		text := "New " + sev + " issue: " + title
		if i.Again != "" {
			text = "Found again although marked " + strings.ReplaceAll(i.Again, "_", " ") + ": " + title + " (" + sev + ")"
		}
		if where != "" {
			text += " on " + where
		}
		if hit != "" && !strings.Contains(text, hit) {
			text += " (" + hit + ", exploited in the wild)"
		} else if hit != "" {
			text += " (exploited in the wild)"
		}
		add(i.TargetID, alertLine{rank: severityRank[sev], quiet: hit == "", text: text})
	}
	var out []Alert
	for _, target := range order {
		value := target
		if t, err := loadTarget(ctx, db, target); err == nil {
			value = t.Value
		}
		if a, ok := alertOf(value, target, scanned, runID, step, lines[target]); ok {
			out = append(out, a)
		}
	}
	return out
}

// alertOf is the one alert of a target's new lines; ok is false when every line is quiet.
func alertOf(value, target string, scanned Target, runID, step string, ls []alertLine) (Alert, bool) {
	slices.SortStableFunc(ls, func(a, b alertLine) int { return b.rank - a.rank })
	quiet := 0
	var loud []string
	for _, l := range ls {
		if l.quiet {
			quiet++
			continue
		}
		loud = append(loud, l.text)
	}
	if len(loud) == 0 {
		return Alert{}, false
	}
	shown := make([]string, 0, min(len(loud), maxAlertLines)+2)
	for _, l := range loud[:min(len(loud), maxAlertLines)] {
		shown = append(shown, "- "+l)
	}
	if n := len(loud) - maxAlertLines; n > 0 {
		shown = append(shown, fmt.Sprintf("- and %d more", n))
	}
	if quiet > 0 {
		shown = append(shown, fmt.Sprintf("- and %s with no CVE exploited in the wild: they are in the daily summary", plural(quiet, "other new thing")))
	}
	by := "A scan of " + value
	if target != scanned.ID {
		by = "The scan of " + scanned.Value + " (which " + value + " is under)"
	}
	if step == stepOpenVAS {
		by += ", in its OpenVAS step,"
	}
	text := fmt.Sprintf("%s found %s since the scan before:\n%s\nOpen External exposure in Vedette and choose %s to see them.",
		by, plural(len(loud), "new thing"), strings.Join(shown, "\n"), value)
	id := "exp-" + runID + "-" + target
	if step != "" {
		id += "-" + step
	}
	// what is exploited in the wild is critical, as a finding's alert is (an exploited flaw is critical whatever its score)
	return Alert{ID: id, TargetID: target, Severity: AlertCritical, Title: value + ": an exploited flaw is exposed", Text: text}, true
}

// stepOpenVAS names the OpenVAS step of a scan in an alert's id.
const stepOpenVAS = "openvas"

// exploitedOf is the first CVE of an issue's cves (a JSON array) that is exploited in the wild (Config.Exploited); "" for none, or when
// the rule is not wired.
func (s *Service) exploitedOf(ctx context.Context, raw string) (string, error) {
	var cves []string
	if err := json.Unmarshal([]byte(raw), &cves); err != nil || len(cves) == 0 || s.cfg.Exploited == nil {
		return "", nil
	}
	hit, err := s.cfg.Exploited(ctx, cves)
	if err != nil {
		return "", err
	}
	for _, c := range cves {
		if hit[c] {
			return c, nil
		}
	}
	return "", nil
}

// NewSince counts what external scans found new in [from, to) that did not alert (the daily summary of notify): the issues first seen
// then, still open, with no CVE exploited in the wild, and the services first seen then, still open.
func (s *Service) NewSince(ctx context.Context, from, to time.Time) (issues, ports int, err error) {
	db := s.cfg.DB.Reader()
	f, t := store.FormatTS(from), store.FormatTS(to)
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM exp_service WHERE state = 'open' AND first_seen >= ? AND first_seen < ?`, f, t).Scan(&ports); err != nil {
		return 0, 0, fmt.Errorf("exposure: new since: %w", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT cves FROM exp_issue WHERE state = 'open' AND first_seen >= ? AND first_seen < ?`, f, t)
	if err != nil {
		return 0, 0, fmt.Errorf("exposure: new since: %w", err)
	}
	var all []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			_ = rows.Close()
			return 0, 0, fmt.Errorf("exposure: new since: %w", err)
		}
		all = append(all, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, 0, fmt.Errorf("exposure: new since: %w", err)
	}
	for _, c := range all {
		hit, err := s.exploitedOf(ctx, c)
		if err != nil {
			return 0, 0, err
		}
		if hit == "" {
			issues++
		}
	}
	return issues, ports, nil
}
