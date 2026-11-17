package feeds

import (
	"database/sql"
	"maps"
	"slices"
	"testing"
)

// countSaysItself are the built-in feeds whose count needs no words: the entries of a list, or the indicators or scores it gives.
// Every other built-in feed has a heldNotes entry; a new feed must be put in one of the two.
var countSaysItself = map[string]string{
	"cisa-kev":         "entries of the CISA list",
	epssAllFeedID:      "scores of every CVE; its note names the day of the scores",
	recentFeedID:       "CVEs of the last 12 months; its note says how many have affected versions",
	vulnCheckFeedID:    "entries of VulnCheck KEV",
	"nuclei-templates": "CVEs with a check template",
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
			got, err = withHeld(t.Context(), tx, id, "")
			return err
		})
		return got
	}
	empty := map[string]string{
		"first-epss":    "No score yet: the exploited CVEs are scored once the CISA list is on the box.",
		cveOrgFeedID:    "Nothing to read yet: CVE.org is read for the exploited CVEs NVD gives no affected versions for, once the CISA list is on the box.",
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
		"first-epss": "Scores of 0 of the 1 exploited CVE on the CISA list, today's and a week ago's.",
		cveOrgFeedID: "1 exploited CVE has no affected versions from NVD; 1 not read from CVE.org yet.",
		winRelFeedID: "1 Windows release on Microsoft's release information pages, with 2 monthly updates, the newest of 11 Nov 2026.",
	}
	for id, want := range filled {
		if got := held(id); got != want {
			t.Errorf("filled box, %s: %q, want %q", id, got, want)
		}
	}
	// read, nothing comparable: one CVE is "it"; NVD gives versions for every exploited CVE: CVE.org has nothing to do
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cveorg_checked (cve, checked_at) VALUES ('CVE-2026-0001', '2026-11-05T12:00:00.000Z')`)
		return err
	})
	if got, want := held(cveOrgFeedID), "1 exploited CVE has no affected versions from NVD, and CVE.org gives none Vedette can compare for it either; it is asked again every 12 hours."; got != want {
		t.Errorf("one CVE read: %q, want %q", got, want)
	}
	write(t, e.db, func(tx *sql.Tx) error {
		_, _, err := applyAffected(t.Context(), tx, map[string][]AffectedRow{"CVE-2026-0001": {{CPE: "cpe:2.3:o:acme:gateway:*:*:*:*:*:*:*:*", EndExcl: "2.0"}}}, false, epoch0)
		return err
	})
	if got, want := held(cveOrgFeedID), "Read only for exploited CVEs NVD gives no affected versions for, and NVD gives them for every one now."; got != want {
		t.Errorf("NVD covers all: %q, want %q", got, want)
	}
	if got, err := func() (got string, err error) {
		write(t, e.db, func(tx *sql.Tx) error {
			got, err = withHeld(t.Context(), tx, "ipsum", "A note of the pull.")
			return nil
		})
		return got, err
	}(); err != nil || got != "A note of the pull." {
		t.Errorf("a feed whose count says itself keeps its pull's note alone: %q %v", got, err)
	}
}
