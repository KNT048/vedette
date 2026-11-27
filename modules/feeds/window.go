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
// attackers use most, so they never age out. A public exploit (Exploit-DB, Metasploit, a proof of concept) keeps an older CVE only
// while its source dates it inside the window: a new exploit of an old flaw renews its risk, an old one does not. The scan template
// index gives no date (its first_seen is when this box first read it, the same day for every template on a new box), so it renews
// nothing. An administrator may report CVEs of every age instead (core_setting windowSettingKey): the catalogue then keeps every CVE
// NVD and the CVE Program publish.

// windowSettingKey is the core_setting row of the reporting window.
const windowSettingKey = "feeds.cve_window"

// undatedSignalSources are the signal sources whose first_seen is when this box first read the entry, not a date the source gives.
var undatedSignalSources = []string{nucleiFeedID}

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

// signalKeeps is the condition on a feeds_signal row (alias s) under which it keeps its CVE whatever the CVE's age.
func (w Window) signalKeeps(s string) string {
	if w.EveryAge {
		return s + `.qualifies = 1`
	}
	return s + `.qualifies = 1 AND (` + s + `.kind = '` + SignalExploited + `' OR ` + s + `.first_seen >= ` + w.since() + ` AND ` + s +
		`.source NOT IN ('` + strings.Join(undatedSignalSources, `', '`) + `'))`
}

// keptSQL is the CVEs the window keeps whatever their publication day: an exploited-list entry, an exploited signal, a public exploit
// dated inside the window (every qualifying signal while every age is reported). Pinned CVEs are added by the caller.
func (w Window) keptSQL() string {
	return `SELECT cve FROM feeds_kev UNION SELECT s.cve FROM feeds_signal s WHERE ` + w.signalKeeps("s")
}

// publicListedSQL is the kept CVEs a public source names: the CISA list, VulnCheck KEV and the kept signals of publicSignalSources (the
// sources are constants of this package). They are the only CVEs Vedette ever asks a source for by ID (an NVD record, a CVE record):
// the same request goes from every box that loads the same public list, so it says nothing about the customer. A custom list's CVE, a
// signal a box builds from what it sees, or a finding's CVE is never asked for by ID. A CVE the window does not keep is not asked for:
// it would be dropped again at once.
func (w Window) publicListedSQL() string {
	return missingKEVSQL + ` UNION SELECT s.cve FROM feeds_signal s WHERE ` + w.signalKeeps("s") + ` AND s.source IN ('` +
		strings.Join(publicSignalSources, `', '`) + `')`
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
