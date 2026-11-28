package feeds

import (
	"bytes"
	"database/sql"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/store"
)

// The statements here are written for these tests about a made-up source package (quillpad): no distribution data is copied.

// vexPocketDoc states, for one CVE each, what Canonical's VEX writes for a universe package of an LTS release: the release is named only
// under its Ubuntu Pro pocket (esm-apps/noble). A fips pocket and a binary product are other builds and are never read.
func vexPocketDoc(status string) string {
	return `{"statements":[{"status":"` + status + `","products":[
  {"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3?arch=source&distro=esm-apps/noble"},
  {"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3?arch=amd64&distro=esm-apps/noble"},
  {"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3+fips1?arch=source&distro=fips/noble"}]}]}`
}

// A pocket's not_affected, affected and under_investigation statements are kept for the release, marked Pro (Ubuntu tracks the package
// there only in Ubuntu Pro); a plain release's statement of the same status is public; a "fixed" statement keeps no row.
func TestParseUbuntuVEXReadsTheUbuntuProPockets(t *testing.T) {
	t.Parallel()
	data := xzTar(t,
		[2]string{"vex/cve/2026/CVE-2026-71001.json", vexPocketDoc("not_affected")},
		[2]string{"vex/cve/2026/CVE-2026-71002.json", vexPocketDoc("under_investigation")},
		[2]string{"vex/cve/2026/CVE-2026-71003.json", vexPocketDoc("affected")},
		[2]string{"vex/cve/2026/CVE-2026-71004.json", vexPocketDoc("fixed")},
		[2]string{"vex/cve/2026/CVE-2026-71005.json", `{"statements":[{"status":"affected","products":[
  {"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3?arch=source&distro=esm-apps/resolute"},
  {"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3?arch=source&distro=resolute"}]}]}`},
	)
	want := DistroWant{Tier: map[string]bool{"CVE-2026-71001": true, "CVE-2026-71002": true, "CVE-2026-71003": true, "CVE-2026-71004": true, "CVE-2026-71005": true},
		Packages: map[string]bool{"quillpad": true}, Releases: map[string]bool{"24.04": true, "26.04": true}}
	res, err := ParseUbuntuVEX(bytes.NewReader(data), want)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(res.Rows, func(a, b DistroFix) int { return strings.Compare(a.CVE, b.CVE) })
	q := func(cve, release, status string, pro bool) DistroFix {
		return DistroFix{Distro: "ubuntu", Release: release, Package: "quillpad", CVE: cve, Status: status, Pro: pro}
	}
	exp := []DistroFix{q("CVE-2026-71001", "24.04", DistroNotAffected, true), q("CVE-2026-71002", "24.04", DistroTriage, true),
		q("CVE-2026-71003", "24.04", DistroOpen, true), q("CVE-2026-71005", "26.04", DistroOpen, false)}
	if !slices.Equal(res.Rows, exp) {
		t.Fatalf("rows\n%+v\nwant\n%+v", res.Rows, exp)
	}
	if res.Accepted != 5 || res.Rejected != 0 {
		t.Fatalf("stats %+v", res.Stats)
	}
}

// One CVE file may state several statuses for one source package of one release (a plain release and its pockets): the row is the
// most cautious one, so a "not affected" never closes a package the same file calls affected, triaged or fixed. A status outside the
// OpenVEX table rejects the file whole.
func TestParseUbuntuVEXKeepsTheMostCautiousStatusOfAPackage(t *testing.T) {
	t.Parallel()
	two := func(a, b string) string {
		return `{"statements":[
 {"status":"` + a + `","products":[{"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3ubuntu0.1?arch=source&distro=noble"}]},
 {"status":"` + b + `","products":[{"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3ubuntu0.1+esm1?arch=source&distro=esm-infra/noble"}]}]}`
	}
	data := xzTar(t,
		[2]string{"vex/cve/2026/CVE-2026-71011.json", two("not_affected", "affected")},
		[2]string{"vex/cve/2026/CVE-2026-71012.json", two("not_affected", "under_investigation")},
		[2]string{"vex/cve/2026/CVE-2026-71013.json", two("not_affected", "fixed")},
		[2]string{"vex/cve/2026/CVE-2026-71014.json", two("not_affected", "not_affected")},
		[2]string{"vex/cve/2026/CVE-2026-71015.json", two("not_affected", "will_not_fix")},
	)
	cves := map[string]bool{}
	for _, c := range []string{"CVE-2026-71011", "CVE-2026-71012", "CVE-2026-71013", "CVE-2026-71014", "CVE-2026-71015"} {
		cves[c] = true
	}
	res, err := ParseUbuntuVEX(bytes.NewReader(data), DistroWant{KEV: cves})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range res.Rows {
		got[r.CVE] = r.Status
		if r.Pro != (r.CVE == "CVE-2026-71011" || r.CVE == "CVE-2026-71012") {
			t.Errorf("%s: Pro %v", r.CVE, r.Pro)
		}
	}
	exp := map[string]string{"CVE-2026-71011": DistroOpen, "CVE-2026-71012": DistroTriage, "CVE-2026-71014": DistroNotAffected}
	if !maps.Equal(got, exp) {
		t.Fatalf("rows %v, want %v", got, exp)
	}
	if res.Accepted != 4 || res.Rejected != 1 || !strings.Contains(res.Reasons[0].Example, "will_not_fix") {
		t.Fatalf("stats %+v", res.Stats)
	}
}

// Debian's undetermined is its "not triaged yet": kept as a triage row of the release, never as fixed or not affected.
func TestParseDebianTrackerKeepsUndeterminedAsTriage(t *testing.T) {
	t.Parallel()
	doc := `{"quillpad": {"CVE-2026-71021": {"releases": {"trixie": {"status": "undetermined"}, "sid": {"status": "undetermined"},
  "bookworm": {"status": "resolved", "fixed_version": "0"}}}}}`
	res, err := ParseDebianTracker(strings.NewReader(doc), DistroWant{KEV: map[string]bool{"CVE-2026-71021": true}})
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(res.Rows, func(a, b DistroFix) int { return strings.Compare(a.Release, b.Release) })
	exp := []DistroFix{{Distro: "debian", Release: "12", Package: "quillpad", CVE: "CVE-2026-71021", Status: DistroNotAffected},
		{Distro: "debian", Release: "13", Package: "quillpad", CVE: "CVE-2026-71021", Status: DistroTriage}}
	if !slices.Equal(res.Rows, exp) {
		t.Fatalf("rows %+v", res.Rows)
	}
}

// The distribution feeds keep their rows for the very CVEs the match pass reads: every CVE of the catalogue the reporting window does
// not set aside (OutsideWindow), whether NVD has analysed it or not, and whatever its age when an exploitation signal or an exploited
// list keeps it. A CVE the window sets aside is not kept; with every age reported, every one is.
func TestDistroTierCVEsAreTheCVEsTheMatcherReads(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.clock()
	seedTierData(t, e, now)
	ts := func(m int) any {
		if m == 0 {
			return nil
		}
		return store.FormatTS(now.AddDate(0, m, 0))
	}
	write(t, e.db, func(tx *sql.Tx) error {
		for _, c := range []struct {
			cve      string
			months   int
			analysed bool
		}{
			{"CVE-2026-71031", -1, false},  // recent, NVD has not analysed it yet
			{"CVE-2023-71032", -30, true},  // old, an exploited signal keeps it
			{"CVE-2023-71033", -30, true},  // old, nothing keeps it: outside the window
			{"CVE-2026-71034", 0, false},   // no publication day yet: counts as recent
			{"CVE-2026-71035", -13, false}, // just older than the window, not analysed
			{"CVE-2021-71037", -60, true},  // old, on a custom exploited list
		} {
			var nvdAt any
			if c.analysed {
				nvdAt = store.FormatTS(now)
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES (?, ?, ?, 'Analyzed', ?, ?)`,
				c.cve, ts(c.months), store.FormatTS(now), nvdAt, store.FormatTS(now)); err != nil {
				return err
			}
		}
		if err := putSignal(t.Context(), tx, "CVE-2023-71032", SignalExploited, msrcFeedID, store.FormatTS(now.AddDate(-2, 0, 0)), store.FormatTS(now), true, ""); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, date_added, updated_at)
VALUES ('CVE-2021-71037', 'custom', 'cisa-kev', 'Acme', 'Quillpad', 'x', '2026-01-02', ?)`, store.FormatTS(now))
		return err
	})
	every, err := stringSet(t.Context(), e.db.Reader(), `SELECT cve FROM feeds_cve`)
	if err != nil {
		t.Fatal(err)
	}
	ids := slices.Sorted(maps.Keys(every))
	outside, err := e.svc.st.OutsideWindow(t.Context(), ids, now)
	if err != nil {
		t.Fatal(err)
	}
	read := map[string]bool{}
	for _, c := range ids {
		if !outside[c] {
			read[c] = true
		}
	}
	if !outside["CVE-2023-71033"] || !outside["CVE-2026-71035"] || len(outside) != 2 {
		t.Fatalf("the window's own answer changed: %v", outside)
	}
	tier, ready, err := e.svc.st.tierCVEs(t.Context(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !ready || !maps.Equal(tier, read) {
		t.Fatalf("the pull keeps %v\nthe matcher reads %v", slices.Sorted(maps.Keys(tier)), slices.Sorted(maps.Keys(read)))
	}
	if has, err := e.svc.st.hasTierCVEs(t.Context(), now); err != nil || !has {
		t.Fatalf("has tier CVEs: %v %v", has, err)
	}
	write(t, e.db, func(tx *sql.Tx) error { return saveWindow(t.Context(), tx, true, "admin@example.test", now) })
	if tier, _, err = e.svc.st.tierCVEs(t.Context(), now); err != nil || !maps.Equal(tier, every) {
		t.Fatalf("every age: %v %v", slices.Sorted(maps.Keys(tier)), err)
	}
}

// A VEX statement is about its own vulnerability: one that names another CVE than its file's is rejected (counted), never attributed
// to the file's CVE. A statement with no vulnerability name is read as its file's.
func TestParseUbuntuVEXRejectsAStatementOfAnotherCVE(t *testing.T) {
	t.Parallel()
	doc := `{"statements":[
 {"vulnerability":{"name":"CVE-2026-71099"},"status":"not_affected","products":[{"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3?arch=source&distro=noble"}]},
 {"vulnerability":{"name":"CVE-2026-71041"},"status":"affected","products":[{"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3?arch=source&distro=resolute"}]},
 {"status":"under_investigation","products":[{"@id":"pkg:deb/ubuntu/quillpad@2.4.1-3?arch=source&distro=questing"}]}]}`
	res, err := ParseUbuntuVEX(bytes.NewReader(xzTar(t, [2]string{"vex/cve/2026/CVE-2026-71041.json", doc})), DistroWant{KEV: map[string]bool{"CVE-2026-71041": true}})
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(res.Rows, func(a, b DistroFix) int { return strings.Compare(a.Release, b.Release) })
	exp := []DistroFix{{Distro: "ubuntu", Release: "25.10", Package: "quillpad", CVE: "CVE-2026-71041", Status: DistroTriage},
		{Distro: "ubuntu", Release: "26.04", Package: "quillpad", CVE: "CVE-2026-71041", Status: DistroOpen}}
	if !slices.Equal(res.Rows, exp) || res.Rejected != 1 || !strings.Contains(res.Reasons[0].Example, "CVE-2026-71099") {
		t.Fatalf("rows %+v stats %+v", res.Rows, res.Stats)
	}
}

// A Debian release status outside resolved, open and undetermined is counted as a reject (a format change shows on the Feeds page),
// never read as any status.
func TestParseDebianTrackerCountsAnUnknownStatus(t *testing.T) {
	t.Parallel()
	doc := `{"quillpad": {"CVE-2026-71051": {"releases": {"trixie": {"status": "pending-review"}, "bookworm": {"status": "open"}}}}}`
	res, err := ParseDebianTracker(strings.NewReader(doc), DistroWant{KEV: map[string]bool{"CVE-2026-71051": true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0].Release != "12" || res.Rejected != 1 || !strings.Contains(res.Reasons[0].Example, "pending-review") {
		t.Fatalf("rows %+v stats %+v", res.Rows, res.Stats)
	}
}

// A good pull replaces a feed's triage rows with its other rows: a triage the file no longer states is gone, as a fix it no longer
// states is.
func TestApplyDistroPrunesTriageRowsTheFileNoLongerStates(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	q := func(status string) DistroFix {
		return DistroFix{Distro: "ubuntu", Release: "24.04", Package: "quillpad", CVE: "CVE-2026-71061", Status: status}
	}
	apply := func(rows ...DistroFix) (changed []string) {
		write(t, db, func(tx *sql.Tx) error {
			var err error
			changed, _, err = applyDistro(t.Context(), tx, ubuntuVEXFeedID, rows)
			return err
		})
		return changed
	}
	apply(q(DistroTriage))
	if n := rowsOf(t, db, "feeds_distro_triage"); n != 1 {
		t.Fatalf("%d triage rows", n)
	}
	if ch := apply(q(DistroOpen)); rowsOf(t, db, "feeds_distro_triage") != 0 || rowsOf(t, db, "feeds_distro_fix") != 1 || !slices.Equal(ch, []string{"CVE-2026-71061"}) {
		t.Fatalf("the triage stayed, or the change went unnoticed: %v", ch)
	}
}

// While nvd-recent is not loaded yet, the pull keeps its rows for every CVE the catalogue holds now (never fewer than the match pass
// reads), and says it is not ready, so the pull after the load keeps them again in full.
func TestDistroTierCVEsBeforeTheWindowIsReady(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.clock()
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES ('CVE-2026-71071', ?, ?, 'Analyzed', ?, ?)`,
			store.FormatTS(now.AddDate(0, -1, 0)), store.FormatTS(now), store.FormatTS(now), store.FormatTS(now))
		return err
	})
	tier, ready, err := e.svc.st.tierCVEs(t.Context(), now)
	if err != nil || ready || !tier["CVE-2026-71071"] {
		t.Fatalf("before the window is ready: %v ready %v %v", tier, ready, err)
	}
}

// A pull while nvd-recent is not loaded keeps the rows of the CVEs the catalogue holds for the devices' packages (the window never
// shrinks to the exploited list), records no packages so the pull after the load runs in full, and the Feeds page says so.
func TestDistroPullBeforeTheWindowKeepsTheCatalogueAndSaysSo(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(debianTrackerFeedID)
	e.mirror(debianTrackerFeedID, o.url("/tracker.json"))
	o.body("/tracker.json", `"v1"`, debianTierJSON)
	e.loadKEV()
	now := e.clock()
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, modified, nvd_status, nvd_at, updated_at) VALUES ('CVE-2026-0001', ?, ?, 'Analyzed', NULL, ?)`,
			store.FormatTS(now.AddDate(0, -2, 0)), store.FormatTS(now), store.FormatTS(now))
		return err
	})
	e.svc.Inventory = &distroInv{got: map[string]map[string]bool{DistroDebian: {"sudo": true}}}
	if err := e.svc.Fetch(t.Context(), debianTrackerFeedID); err != nil {
		t.Fatal(err)
	}
	if n, _ := stringSet(t.Context(), e.db.Reader(), `SELECT release FROM feeds_distro_fix WHERE cve = 'CVE-2026-0001' AND package = 'sudo'`); len(n) != 2 {
		t.Fatalf("the catalogue's CVE was not kept for the device's package: %v", n)
	}
	if kept, _ := e.svc.st.distroKept(t.Context(), debianTrackerFeedID); kept != nil {
		t.Fatalf("recorded %v before the window loaded", kept)
	}
	if st, line := e.fetchList(t, debianTrackerFeedID); st != "ok" || !strings.Contains(line, distroWindowNote) {
		t.Fatalf("%s %q", st, line)
	}
}
