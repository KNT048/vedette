package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/coredb"
)

// The reporting window (INV-34). The box reports, and its catalogue keeps, the CVEs published in the last windowDays days, and an older
// CVE only while there is evidence that it is exploited in the wild: an exploited-list entry (the CISA list, VulnCheck KEV, a custom
// list) or an exploited signal (a vendor or a research team says it is exploited), of any age. Old flaws on those lists are what
// attackers use most, so they never age out. A public exploit keeps an older CVE only while it appeared inside the window: a new exploit
// of an old flaw renews its risk, an old one does not. Only a date that means the exploit appeared counts: Exploit-DB's publication day
// and a proof of concept's repository date (datedSignalSources, first_seen). Metasploit's index dates a module by its last change
// (mod_time), never by its arrival, and the scan template index gives no date at all (first_seen is the day this box first read it):
// for those, the day this box first stored the entry (stored_at) counts, and only once the box has held entries of that source since
// before the window. Before that, every entry is "new" to the box (a new box reads every index the same day). An administrator may
// report CVEs of every age instead (core_setting windowSettingKey): the catalogue then keeps every CVE NVD and the CVE Program publish.

// windowSettingKey is the core_setting row of the reporting window.
const windowSettingKey = "feeds.cve_window"

// datedSignalSources are the public-exploit sources whose first_seen is the day the exploit appeared: Exploit-DB's date_published, a
// proof of concept's repository creation (or the day it began to qualify). Any other source's first_seen is a change date (Metasploit's
// mod_time) or this box's first read (the scan templates), never the exploit's arrival.
var datedSignalSources = []string{exploitDBFeedID, pocGitHubFeedID}

// windowSetting is the stored value of windowSettingKey.
type windowSetting struct {
	EveryAge  bool      `json:"every_age"`
	ChangedAt time.Time `json:"changed_at"`
	ChangedBy string    `json:"changed_by"`
}

// Window is the reporting window at a time.
type Window struct {
	Cutoff   time.Time // a CVE published since is inside
	EveryAge bool      // an administrator reports CVEs of every age: every CVE is inside
	// Since is when the setting was last changed (zero: never): a read of NVD's whole set or of the CVE Program's whole list that
	// started before an every-age switch did not store the older CVEs.
	Since time.Time
	By    string // who changed it last ("" never)
}

// windowOf reads the reporting window at now.
func windowOf(ctx context.Context, q coredb.DBTX, now time.Time) (Window, error) {
	w := Window{Cutoff: now.AddDate(0, 0, -windowDays)}
	raw, err := coredb.New(q).GetSetting(ctx, windowSettingKey)
	if errors.Is(err, sql.ErrNoRows) {
		return w, nil
	}
	if err != nil {
		return w, fmt.Errorf("feeds: read the reporting window: %w", err)
	}
	var v windowSetting
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return w, nil // an unreadable row: the default window (the next save writes a good one)
	}
	w.EveryAge, w.Since, w.By = v.EveryAge, v.ChangedAt, v.ChangedBy
	return w, nil
}

// saveWindow stores the every-age setting.
func saveWindow(ctx context.Context, tx *sql.Tx, everyAge bool, by string, now time.Time) error {
	b, err := json.Marshal(windowSetting{EveryAge: everyAge, ChangedAt: now.UTC(), ChangedBy: by})
	if err != nil {
		return fmt.Errorf("feeds: save the reporting window: %w", err)
	}
	if err := coredb.New(tx).UpsertSetting(ctx, coredb.UpsertSettingParams{Key: windowSettingKey, Value: string(b), UpdatedAt: store.FormatTS(now), UpdatedBy: by}); err != nil {
		return fmt.Errorf("feeds: save the reporting window: %w", err)
	}
	return nil
}

// since is the window's start as an SQL literal: store.FormatTS writes digits and the separators "-:.TZ" only.
func (w Window) since() string { return "'" + store.FormatTS(w.Cutoff) + "'" }

// keptSignalsSQL is the CVEs of the feeds_signal rows that keep their CVE whatever its age: a qualifying exploited signal; an intrusion
// alert of this network that named it in the window (SignalAttackedHere, by its latest alert); a qualifying
// public exploit of a dated source whose first_seen is inside the window; a qualifying signal of another source that this box first
// stored inside the window (stored_at) while it has held entries of that source since before it (the source's oldest stored_at). Every
// qualifying signal while every age is reported. sources, when not empty, limits the rows to those sources (constants of this package).
func (w Window) keptSignalsSQL(sources []string) string {
	only := ""
	if len(sources) > 0 {
		only = ` AND s.source IN ('` + strings.Join(sources, `', '`) + `')`
	}
	if w.EveryAge {
		return `SELECT s.cve FROM feeds_signal s WHERE s.qualifies = 1` + only
	}
	c, dated := w.since(), `('`+strings.Join(datedSignalSources, `', '`)+`')`
	return `SELECT s.cve FROM feeds_signal s JOIN (SELECT source, min(stored_at) AS watched FROM feeds_signal GROUP BY source) b ON b.source = s.source
WHERE s.qualifies = 1` + only + ` AND (s.kind = '` + SignalExploited + `'
 OR s.kind = '` + SignalAttackedHere + `' AND s.last_seen >= ` + c + `
 OR s.kind = '` + SignalPublicExploit + `' AND s.source IN ` + dated + ` AND s.first_seen >= ` + c + `
 OR s.kind = '` + SignalPublicExploit + `' AND s.source NOT IN ` + dated + ` AND s.stored_at >= ` + c + ` AND b.watched < ` + c + `)`
}

// keptSQL is the CVEs the window keeps whatever their publication day: an exploited-list entry, an exploited signal, a public exploit
// that appeared inside the window (keptSignalsSQL). Pinned CVEs are added by the caller.
func (w Window) keptSQL() string {
	return `SELECT cve FROM feeds_kev UNION ` + w.keptSignalsSQL(nil)
}

// publicListedSQL is the kept CVEs a public source names: the CISA list, VulnCheck KEV and the kept signals of publicSignalSources (the
// sources are constants of this package). They are the only CVEs Vedette ever asks a source for by ID (an NVD record, a CVE record):
// the same request goes from every box that loads the same public list, so it says nothing about the customer. A custom list's CVE, a
// signal a box builds from what it sees, or a finding's CVE is never asked for by ID. A CVE the window does not keep is not asked for:
// it would be dropped again at once.
func (w Window) publicListedSQL() string {
	return missingKEVSQL + ` UNION ` + w.keptSignalsSQL(publicSignalSources)
}

// Window is the reporting window now.
func (s *Store) Window(ctx context.Context, now time.Time) (Window, error) {
	return windowOf(ctx, s.db.Reader(), now)
}

// OutsideWindow says which of cves are outside the reporting window at now: published before the window (NVD's date; a CVE the
// catalogue has no date of counts as recent) and kept by no exploited-list entry, exploited signal or public exploit dated inside it.
// An open finding's pin keeps a CVE's data in the catalogue, never inside the window. None while every age is reported.
func (s *Store) OutsideWindow(ctx context.Context, cves []string, now time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	if len(cves) == 0 {
		return out, nil
	}
	w, err := s.Window(ctx, now)
	if err != nil || w.EveryAge {
		return out, err
	}
	ids, err := json.Marshal(cves)
	if err != nil {
		return nil, fmt.Errorf("feeds: the reporting window: %w", err)
	}
	got, err := stringSet(ctx, s.db.Reader(), `SELECT c.cve FROM feeds_cve c WHERE c.cve IN (SELECT value FROM json_each(?))
AND c.published IS NOT NULL AND c.published < ? AND c.cve NOT IN (`+w.keptSQL()+`)`, string(ids), store.FormatTS(w.Cutoff))
	if err != nil {
		return nil, fmt.Errorf("feeds: the reporting window: %w", err)
	}
	return got, nil
}

// Kept says which of cves the reporting window keeps whatever their publication day (keptSQL): an exploited-list entry, a qualifying
// exploited signal, an intrusion alert of this network inside the window, a public exploit dated inside it; while every age is reported,
// any qualifying signal. The one reading of "an exploitation signal keeps it" for a reader outside feeds (findings' older-build group).
func (s *Store) Kept(ctx context.Context, cves []string, now time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	if len(cves) == 0 {
		return out, nil
	}
	w, err := s.Window(ctx, now)
	if err != nil {
		return nil, err
	}
	ids, err := json.Marshal(cves)
	if err != nil {
		return nil, fmt.Errorf("feeds: the reporting window: %w", err)
	}
	got, err := stringSet(ctx, s.db.Reader(), `SELECT value FROM json_each(?) WHERE value IN (`+w.keptSQL()+`)`, string(ids))
	if err != nil {
		return nil, fmt.Errorf("feeds: the reporting window: %w", err)
	}
	return got, nil
}

// unsupportedMark is how a CVE record's description carries the CVE Program's unsupported-when-assigned tag: the program has the
// description of a tagged record begin with it.
const unsupportedMark = "** UNSUPPORTED WHEN ASSIGNED **"

// UnsupportedWhenAssigned says which of cves have a record that states the product unsupported by its vendor when the CVE was assigned
// (unsupportedMark in its description, any case). findings groups the other undecided CVEs of a line such a record covers under the
// move to a supported release (findings P-13).
func (s *Store) UnsupportedWhenAssigned(ctx context.Context, cves []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(cves) == 0 {
		return out, nil
	}
	ids, err := json.Marshal(cves)
	if err != nil {
		return nil, fmt.Errorf("feeds: records tagged unsupported: %w", err)
	}
	got, err := stringSet(ctx, s.db.Reader(), `SELECT cve FROM feeds_cve WHERE cve IN (SELECT value FROM json_each(?))
AND instr(upper(description), ?) > 0`, string(ids), unsupportedMark)
	if err != nil {
		return nil, fmt.Errorf("feeds: records tagged unsupported: %w", err)
	}
	return got, nil
}

// ExploitationSignalled says which of cves any exploitation signal names, whatever its age or the reporting window: an exploited-list
// entry, or a signal row that passes its source's quality rule (exploited, a public exploit or scan template, an intrusion alert here).
// findings never groups such a CVE under an update its line needs (findings P-13). Each CVE is one lookup of the two primary keys.
func (s *Store) ExploitationSignalled(ctx context.Context, cves []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(cves) == 0 {
		return out, nil
	}
	ids, err := json.Marshal(cves)
	if err != nil {
		return nil, fmt.Errorf("feeds: exploitation signals: %w", err)
	}
	got, err := stringSet(ctx, s.db.Reader(), `SELECT j.value FROM json_each(?) j
WHERE EXISTS (SELECT 1 FROM feeds_kev k WHERE k.cve = j.value) OR EXISTS (SELECT 1 FROM feeds_signal g WHERE g.cve = j.value AND g.qualifies = 1)`, string(ids))
	if err != nil {
		return nil, fmt.Errorf("feeds: exploitation signals: %w", err)
	}
	return got, nil
}

// SignalAttackedHere is the kind of the signal this box builds from its own intrusion alerts: an alert named the CVE (source
// attackedHereSource). first_seen and last_seen are the first and the latest alert that named it, kept here so the reporting window
// never depends on how long the alerts themselves are kept. It keeps the CVE inside the window until 12 months after last_seen.
const SignalAttackedHere = "attacked_here"

// attackedHereSource is the source of SignalAttackedHere: this box's intrusion alerts. Never a public list: never asked for by ID.
const attackedHereSource = "intrusion-alerts"

// attackedHereName is the name the CVE page gives the source.
const attackedHereName = "This network's intrusion alerts"

// attackNoteSpan is how far back the pull job's maintenance reads the alerts at each check (Deps.Attacked): a box off for a few days
// still notes what came in meanwhile, and a note never moves a date back.
const attackNoteSpan = 30 * 24 * time.Hour

// AttackSeen is a CVE the box's intrusion alerts named, and when the first and the latest of them fired.
type AttackSeen struct {
	CVE         string
	First, Last time.Time
}

// noteAttacks keeps the alerts' CVEs as SignalAttackedHere signals: a new CVE gets its first and latest alert, a known one the earlier
// first and the later latest. A name that is not a CVE ID is skipped.
func noteAttacks(ctx context.Context, tx *sql.Tx, seen []AttackSeen, now time.Time) error {
	stamp := store.FormatTS(now)
	for _, a := range seen {
		if !cveRE.MatchString(a.CVE) || a.First.IsZero() || a.Last.IsZero() {
			continue
		}
		f, l := a.First, a.Last
		if l.After(now) {
			l = now // an alert dated in the future
		}
		if f.After(l) {
			f = l
		}
		first, last := store.FormatTS(f), store.FormatTS(l)
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies, url)
VALUES (?, ?, ?, ?, ?, ?, 1, '')
ON CONFLICT(cve, kind, source) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)`,
			a.CVE, SignalAttackedHere, attackedHereSource, first, stamp, last); err != nil {
			return fmt.Errorf("feeds: note an attacked CVE: %w", err)
		}
	}
	return nil
}

// noteAlerts reads the CVEs the intrusion alerts named in the last attackNoteSpan (Deps.Attacked) and keeps them (noteAttacks).
func (s *Service) noteAlerts(ctx context.Context, now time.Time) error {
	if s.Attacked == nil {
		return nil
	}
	seen, err := s.Attacked(ctx, now.Add(-attackNoteSpan))
	if err != nil || len(seen) == 0 {
		return err
	}
	return s.DB.Write(ctx, func(tx *sql.Tx) error { return noteAttacks(ctx, tx, seen, now) })
}
