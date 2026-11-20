package feeds

import (
	"database/sql"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

// countSaysItself are the built-in feeds whose count needs no words: the entries of a list, or the indicators or scores it gives.
// Every other built-in feed has a heldNotes entry; a new feed must be put in one of the two.
var countSaysItself = map[string]string{
	"cisa-kev":         "entries of the CISA list",
	epssAllFeedID:      "scores of every CVE; its note names the day of the scores",
	recentFeedID:       "CVEs of the last 12 months; its note says how many have affected versions",
	vulnCheckFeedID:    "entries of VulnCheck KEV",
	"nuclei-templates": "CVEs with a check template",
	metasploitFeedID:   "CVEs with a Metasploit module",
	exploitDBFeedID:    "CVEs with an Exploit-DB entry",
	msrcFeedID:         "CVEs Microsoft flags exploited",
	ciscoFeedID:        "CVEs Cisco says are exploited",
	fortinetFeedID:     "CVEs Fortinet says are exploited",
	"ipsum":            "indicators",
	"et-open":          "indicators",
	"abusech-feodo":    "indicators",
	"tor-exit":         "indicators",
	"hagezi-tif":       "indicators",
}

// The class of a count shown with no words: measured over every built-in feed, each is decided once.
func TestHeldNotes_EveryBuiltinFeedIsDecided(t *testing.T) {
	t.Parallel()
	ids := map[string]bool{}
	for _, s := range BuiltinSources() {
		ids[s.ID] = true
		_, held := heldNotes[s.ID]
		_, plain := countSaysItself[s.ID]
		if held == plain {
			t.Errorf("%s: held note %v, count says itself %v: exactly one", s.ID, held, plain)
		}
	}
	for _, id := range slices.Concat(slices.Collect(maps.Keys(heldNotes)), slices.Collect(maps.Keys(countSaysItself))) {
		if !ids[id] {
			t.Errorf("%s is not a built-in feed", id)
		}
	}
}

// Each held note on an empty box, and on one the CISA list filled: a count of 0 is never left without words.
func TestHeldNotes_EmptyAndFilled(t *testing.T) {
	t.Parallel()
	e, _ := pullEnv(t)
	held := func(id string) string {
		t.Helper()
		var got string
		write(t, e.db, func(tx *sql.Tx) (err error) {
			got, err = heldNotes[id](t.Context(), tx)
			return err
		})
		return got
	}
	empty := map[string]string{
		cveOrgFeedID:    "No CVE record read yet: the CVE Program's records of the catalogue's CVEs load at the next check.",
		nvdFeedID:       "",
		winRelFeedID:    "",
		ubuntuOSVFeedID: "",
	}
	for id, want := range empty {
		if got := held(id); got != want {
			t.Errorf("empty box, %s: %q, want %q", id, got, want)
		}
	}
	applyV(t, e.db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-0001", "Acme", "Gateway", "2026-11-01")}, false)
	write(t, e.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_winrel (build, server, product, display, line, ga, ga_rev) VALUES (26100, 1, 'windows_server_2025', 'Windows Server 2025', 26100, '2024-11-01', 2314)`); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_winrel_update (build, server, rev, kb, day) VALUES (26100, 1, 2894, 'KB5050001', '2026-01-14'), (26100, 1, 4652, 'KB5060001', '2026-11-11')`)
		return err
	})
	filled := map[string]string{
		cveOrgFeedID: "No CVE record read yet: the CVE Program's records of the catalogue's CVEs load at the next check. Exploited: 1 without affected versions from NVD, 0 of them with versions from the record.",
		winRelFeedID: "1 Windows release on Microsoft's release information pages, with 2 monthly updates, the newest of 11 Nov 2026.",
	}
	for id, want := range filled {
		if got := held(id); got != want {
			t.Errorf("filled box, %s: %q, want %q", id, got, want)
		}
	}
	// read, nothing comparable: one CVE is "it"; NVD gives versions for every exploited CVE: CVE.org has nothing to do
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_cve SET record_at = '2026-11-05T12:00:00.000Z' WHERE cve = 'CVE-2026-0001'`)
		return err
	})
	if got, want := held(cveOrgFeedID), "1 of 1 catalogue CVEs have their record read; 1 without affected versions from NVD, 0 of them with versions from the record. Exploited: 1 without affected versions from NVD, 0 of them with versions from the record."; got != want {
		t.Errorf("one CVE read: %q, want %q", got, want)
	}
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := applyAffected(t.Context(), tx, map[string][]AffectedRow{"CVE-2026-0001": {{CPE: "cpe:2.3:o:acme:gateway:*:*:*:*:*:*:*:*", EndExcl: "2.0"}}}, false, epoch0)
		return err
	})
	if got, want := held(cveOrgFeedID), "1 of 1 catalogue CVEs have their record read; 0 without affected versions from NVD, 0 of them with versions from the record."; got != want {
		t.Errorf("NVD covers all: %q, want %q", got, want)
	}
}

// fillHeld puts data behind every feed of heldNotes: two exploited CVEs (NVD gives versions for one), the rows of each distribution
// feed for one of them and for another CVE, and a Windows release.
func fillHeld(t *testing.T, db *store.DB) {
	t.Helper()
	applyV(t, db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-0001", "Acme", "Gateway", "2026-11-01"), vuln("CVE-2026-0002", "Acme", "Portal", "2026-11-02")}, false)
	write(t, db, func(tx *sql.Tx) error {
		if _, err := applyAffected(t.Context(), tx, map[string][]AffectedRow{"CVE-2026-0002": {{CPE: "cpe:2.3:a:acme:portal:*:*:*:*:*:*:*:*", EndExcl: "3.0"}}}, false, epoch0); err != nil {
			return err
		}
		for _, id := range []string{ubuntuOSVFeedID, ubuntuVEXFeedID, debianTrackerFeedID, alpineOSVFeedID} {
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version) VALUES
(?1, 'debian', '12', 'openssh', 'CVE-2026-0001', 'fixed', '1.1'), (?1, 'debian', '13', 'openssh', 'CVE-2026-0001', 'fixed', '1.2'), (?1, 'debian', '12', 'curl', 'CVE-2025-1111', 'fixed', '8.0')`, id); err != nil {
				return err
			}
		}
		if err := applyPublicSignals(t.Context(), tx, epoch0, pocGitHubFeedID, []publicSignal{{CVE: "CVE-2026-0001", Date: epoch0, Qualifies: true, Rule: epoch0},
			{CVE: "CVE-2026-0002", Date: epoch0}}); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_winrel (build, server, product, display, line, ga, ga_rev) VALUES (26100, 1, 'windows_server_2025', 'Windows Server 2025', 26100, '2024-11-01', 2314)`)
		return err
	})
}

// heldShown checks every feed of heldNotes as GET /feeds/sources shows it: what a count of the stored data gives now, then the note
// its last pull stored. It returns the feeds whose good row shows its count with no word of what it holds.
func (e *env) heldShown(t *testing.T) (bare []string) {
	t.Helper()
	c, b := e.get("/feeds/sources")
	if c != 200 {
		t.Fatalf("list: %d", c)
	}
	for _, it := range b["items"].([]any) {
		m := it.(map[string]any)
		id := m["id"].(string)
		count := heldNotes[id]
		if count == nil {
			continue
		}
		var held string
		write(t, e.db, func(tx *sql.Tx) (err error) {
			held, err = count(t.Context(), tx)
			return err
		})
		line, _ := m["error"].(string)
		if want := withHeld(held, orEmpty(e.feed(id).Error)); m["status"] != "ok" || line != want {
			t.Errorf("%s: %v %q, want ok %q", id, m["status"], line, want)
		}
		if held == "" || !strings.HasPrefix(line, held) {
			bare = append(bare, id)
		}
	}
	return bare
}

// After an update, before any feed pulled again: the rows were stored by a version that wrote no sentence of what the feed holds
// (no note, or only its pull's own). Every feed of heldNotes says what it holds the moment the page is read.
func TestHeldNotes_ShownRightAfterAnUpdate(t *testing.T) {
	t.Parallel()
	e, _ := pullEnv(t)
	fillHeld(t, e.db)
	for _, stored := range []string{"", "2 of 10 rows were rejected. Most often: x. A few bad lines in a public list are normal; they are skipped."} {
		var note any
		if stored != "" {
			note = stored
		}
		for id := range heldNotes {
			execSQL(t, e.db, fmt.Sprintf(`UPDATE feeds_source SET status = 'ok', last_fetch = '2026-11-05T11:06:00.000Z', last_success = '2026-11-05T11:06:00.000Z', records = 0, error = %s WHERE id = '%s'`,
				map[bool]string{true: "NULL", false: "'" + stored + "'"}[note == nil], id))
		}
		if bare := e.heldShown(t); len(bare) > 0 {
			t.Errorf("stored note %q: %d of %d feeds show a bare count: %v", stored, len(bare), len(heldNotes), bare)
		}
		if _, line := e.fetchList(t, cveOrgFeedID); line != withHeld("No CVE record read yet: the CVE Program's records of the catalogue's CVEs load at the next check. Exploited: 1 without affected versions from NVD, 0 of them with versions from the record.", stored) {
			t.Errorf("CVE.org, stored %q: %q", stored, line)
		}
	}
	// a feed that failed shows its error alone; one never pulled says so (the GUI's "first fetch")
	execSQL(t, e.db, `UPDATE feeds_source SET status = 'error', error = 'NVD answered HTTP 503.' WHERE id = 'nvd-kev'`)
	execSQL(t, e.db, `UPDATE feeds_source SET status = 'never', error = NULL WHERE id = 'windows-releases'`)
	for id, want := range map[string][2]string{nvdFeedID: {"error", "NVD answered HTTP 503."}, winRelFeedID: {"never", ""}} {
		if st, line := e.fetchList(t, id); st != want[0] || line != want[1] {
			t.Errorf("%s: %s %q, want %v", id, st, line, want)
		}
	}
}

// The sentence follows the data whichever feed changed it: the CISA list (cve-org, the distribution feeds), VulnCheck KEV,
// NVD (nvd-kev, cve-org), and each feed's own pull. A pull is its data and its recorded outcome in one transaction, as pullOne writes.
func TestHeldNotes_FollowTheData(t *testing.T) {
	t.Parallel()
	e, _ := pullEnv(t)
	fillHeld(t, e.db)
	pulled := func(id string, fn func(tx *sql.Tx) error) {
		t.Helper()
		e.setNow(e.clock().Add(time.Minute))
		write(t, e.db, func(tx *sql.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return recordOutcome(t.Context(), tx, id, outcome{Started: e.clock(), Finished: e.clock(), OK: true, NotModified: true})
		})
	}
	for id := range heldNotes {
		pulled(id, func(*sql.Tx) error { return nil })
	}
	e.heldShown(t) // counted once: the next reads use what changed since
	insert := func(q string, args ...any) func(tx *sql.Tx) error {
		return func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q, args...); return err }
	}
	steps := []struct {
		name, feed string
		data       func(tx *sql.Tx) error
		shows      map[string]string // a few lines in full; heldShown checks every feed
	}{
		{"the CISA list adds the other CVE of the distribution rows", kevFeedID, func(tx *sql.Tx) error {
			_, _, err := applyVulns(t.Context(), tx, epoch0, kevFeedID, []Vuln{vuln("CVE-2025-1111", "Haxx", "curl", "2026-11-03")}, false)
			return err
		}, map[string]string{
			cveOrgFeedID:    "No CVE record read yet: the CVE Program's records of the catalogue's CVEs load at the next check. Exploited: 2 without affected versions from NVD, 0 of them with versions from the record.",
			ubuntuOSVFeedID: "Counts one record per package, release and CVE: 2 exploited CVEs.",
		}},
		{"VulnCheck KEV adds a CVE NVD has no versions for", vulnCheckFeedID, func(tx *sql.Tx) error {
			_, _, err := applyVulns(t.Context(), tx, epoch0, vulnCheckFeedID, []Vuln{vuln("CVE-2026-0003", "Acme", "Router", "2026-11-04")}, false)
			return err
		}, map[string]string{cveOrgFeedID: "No CVE record read yet: the CVE Program's records of the catalogue's CVEs load at the next check. Exploited: 3 without affected versions from NVD, 0 of them with versions from the record."}},
		{"NVD gives versions for another CVE", nvdFeedID, func(tx *sql.Tx) error {
			_, err := applyAffected(t.Context(), tx, map[string][]AffectedRow{"CVE-2026-0001": {{CPE: "cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*", EndExcl: "2.0"}}}, false, epoch0)
			return err
		}, map[string]string{
			nvdFeedID:    "NVD records of 2 exploited CVEs; 2 of them name affected versions.",
			cveOrgFeedID: "No CVE record read yet: the CVE Program's records of the catalogue's CVEs load at the next check. Exploited: 2 without affected versions from NVD, 0 of them with versions from the record.",
		}},
		{"CVE.org reads one", cveOrgFeedID, insert(`UPDATE feeds_cve SET record_at = '2026-11-05T12:00:00.000Z' WHERE cve = 'CVE-2025-1111'`),
			map[string]string{cveOrgFeedID: "1 of 4 catalogue CVEs have their record read; 2 without affected versions from NVD, 0 of them with versions from the record. Exploited: 2 without affected versions from NVD, 0 of them with versions from the record."}},
		{"Debian drops its rows of the other CVE", debianTrackerFeedID, insert(`DELETE FROM feeds_distro_fix WHERE source_id = 'debian-tracker' AND release = '13'`),
			map[string]string{debianTrackerFeedID: "Counts one record per package, release and CVE: 2 exploited CVEs."}},
		{"Ubuntu VEX, Alpine and Ubuntu OSV each keep one row", ubuntuVEXFeedID, insert(`DELETE FROM feeds_distro_fix WHERE source_id = 'ubuntu-vex' AND package = 'openssh'`),
			map[string]string{ubuntuVEXFeedID: "Counts one record per package, release and CVE: 1 exploited CVE."}},
		{"Alpine", alpineOSVFeedID, insert(`DELETE FROM feeds_distro_fix WHERE source_id = 'alpine-osv' AND package = 'curl'`), nil},
		{"Ubuntu OSV", ubuntuOSVFeedID, insert(`DELETE FROM feeds_distro_fix WHERE source_id = 'ubuntu-osv' AND package = 'curl'`), nil},
		{"Microsoft's pages add a monthly update", winRelFeedID, insert(`INSERT INTO feeds_winrel_update (build, server, rev, kb, day) VALUES (26100, 1, 4652, 'KB5060001', '2026-11-11')`),
			map[string]string{winRelFeedID: "1 Windows release on Microsoft's release information pages, with 1 monthly update, the newest of 11 Nov 2026."}},
	}
	for _, s := range steps {
		pulled(s.feed, s.data)
		if bare := e.heldShown(t); len(bare) > 0 {
			t.Errorf("%s: bare counts %v", s.name, bare)
		}
		for id, want := range s.shows {
			if _, line := e.fetchList(t, id); line != want {
				t.Errorf("%s, %s: %q, want %q", s.name, id, line, want)
			}
		}
	}
	// every feed of heldNotes names where its data comes from, and each names itself
	for id := range heldNotes {
		if !slices.Contains(heldFrom[id], id) {
			t.Errorf("%s: heldFrom %v leaves the feed out", id, heldFrom[id])
		}
	}
}
