package feeds

import (
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// TestMain makes an indicator chunk 200 rows instead of 2000: the chunk tests need lists of several chunks, and under -race
// every SQLite row costs milliseconds. The chunking logic does not depend on the size.
func TestMain(m *testing.M) {
	iocChunkRows = 200
	os.Exit(m.Run())
}

var epoch0 = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)

// newStore opens a real database with core's and the feeds migrations and seeds the built-in feeds.
func newStore(t testing.TB) (*Store, *store.DB) {
	t.Helper()
	db := migratedDB(t)
	s := NewStore(db)
	if err := s.SeedBuiltins(t.Context(), epoch0); err != nil {
		t.Fatal(err)
	}
	return s, db
}

// migratedDB is a copy of a database that core's and the feeds migrations were applied to once (#409), with no feed seeded.
func migratedDB(t testing.TB) *store.DB {
	t.Helper()
	return storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "feeds", FS: Migrations})
}

func write(t testing.TB, db *store.DB, fn func(tx *sql.Tx) error) {
	t.Helper()
	if err := db.Write(t.Context(), fn); err != nil {
		t.Fatal(err)
	}
}

func count(t testing.TB, db *store.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.Reader().QueryRowContext(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func addCustom(t testing.TB, db *store.DB, id, name string, kind Kind) {
	t.Helper()
	p := DefaultParser(kind, FormatLines)
	if kind == KindVulnerabilities {
		p = DefaultParser(kind, FormatCSV)
	}
	write(t, db, func(tx *sql.Tx) error {
		return insertCustom(t.Context(), tx, sourceRow{ID: id, Name: name, Kind: kind, Format: p.Format, URL: "https://feed.example.net/x", Enabled: true,
			IntervalHours: 6, Auth: AuthNone, Parser: &p, CreatedAt: epoch0})
	})
}

func TestContract_SYS_MigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, "feeds", Migrations, "feeds_", storetest.Migration{Module: "core", FS: core.Migrations})
}

func TestSeedBuiltinsMergesAndKeepsAdminChoices(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	rows, err := s.sources(t.Context())
	if err != nil || len(rows) != len(BuiltinSources()) {
		t.Fatalf("%d rows, %v", len(rows), err)
	}
	for i, b := range BuiltinSources() {
		r := rows[i]
		if r.ID != b.ID || !r.Builtin || !r.Enabled || r.IntervalHours != b.IntervalHours || r.URL != b.URL || r.DefaultURL == nil || *r.DefaultURL != b.URL || r.Status != "never" || r.Parser != nil {
			t.Errorf("row %d = %+v", i, r)
		}
	}
	// The admin turns a feed off, changes its schedule and sets a mirror on another one.
	write(t, db, func(tx *sql.Tx) error {
		if err := updateSettings(t.Context(), tx, "ipsum", false, 12, "", false); err != nil {
			return err
		}
		return updateSettings(t.Context(), tx, "et-open", true, 6, "https://mirror.example.net/et.txt", true)
	})
	// A new release moves the default address of both feeds.
	write(t, db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET default_url = 'https://old.example/x', url = CASE id WHEN 'ipsum' THEN 'https://old.example/x' ELSE url END WHERE id IN ('ipsum', 'et-open')`)
		return err
	})
	if err := s.SeedBuiltins(t.Context(), epoch0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ipsum, _ := s.source(t.Context(), "ipsum")
	et, _ := s.source(t.Context(), "et-open")
	b, _ := BuiltinByID("ipsum")
	e, _ := BuiltinByID("et-open")
	if ipsum.Enabled || ipsum.IntervalHours != 12 || ipsum.URL != b.URL || *ipsum.DefaultURL != b.URL {
		t.Errorf("ipsum: %+v", ipsum)
	}
	if !et.Enabled || et.URL != "https://mirror.example.net/et.txt" || *et.DefaultURL != e.URL {
		t.Errorf("et-open keeps its mirror: %+v", et)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_source`); n != len(BuiltinSources()) {
		t.Errorf("seeding twice left %d rows", n)
	}
}

func vuln(cve, vendor, product, added string) Vuln {
	return Vuln{CVE: cve, Vendor: vendor, Product: product, Name: vendor + " " + product + " flaw", Description: "d", RequiredAction: "patch",
		Links: []string{"https://example.com/" + cve}, DateAdded: added, DueDate: "2026-12-01"}
}

func applyV(t testing.TB, db *store.DB, at time.Time, source string, vs []Vuln, replace bool) (fresh []VulnRow, updated []string) {
	t.Helper()
	write(t, db, func(tx *sql.Tx) (err error) {
		fresh, updated, err = applyVulns(t.Context(), tx, at, source, vs, replace)
		return err
	})
	return fresh, updated
}

func TestApplyVulnsNewUpdatedAndOwner(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	addCustom(t, db, "cf-v", "Partner advisories", KindVulnerabilities)
	a, b := vuln("CVE-2026-0001", "Synology", "DiskStation Manager", "2026-11-03"), vuln("CVE-2026-0002", "Fortinet", "FortiOS", "2026-11-02")

	fresh, upd := applyV(t, db, epoch0, "cisa-kev", []Vuln{a, b}, false)
	if len(fresh) != 2 || len(upd) != 0 {
		t.Fatalf("first pull: %d new, %v updated", len(fresh), upd)
	}
	fresh, upd = applyV(t, db, epoch0, "cisa-kev", []Vuln{a, b}, false)
	if len(fresh) != 0 || len(upd) != 0 {
		t.Fatalf("same data again: %d new, %v updated", len(fresh), upd)
	}
	a2 := a
	a2.Ransomware = true
	c := vuln("CVE-2026-0003", "QNAP", "QTS", "2026-11-04")
	fresh, upd = applyV(t, db, epoch0, "cisa-kev", []Vuln{a2, b, c}, false)
	if len(fresh) != 1 || fresh[0].CVE != "CVE-2026-0003" || len(upd) != 1 || upd[0] != "CVE-2026-0001" {
		t.Fatalf("changed pull: new %v updated %v", fresh, upd)
	}
	// A CVE that left the catalog stays (history).
	applyV(t, db, epoch0, "cisa-kev", []Vuln{a2}, false)
	if n := count(t, db, `SELECT count(*) FROM feeds_vuln`); n != 3 {
		t.Errorf("%d rows after a smaller catalog, want 3", n)
	}
	// A custom feed cannot take over a KEV row, and a new row of its own keeps the date it was first seen.
	mine := vuln("CVE-2026-0001", "Other", "Thing", "2020-01-01")
	own := Vuln{CVE: "CVE-2026-0900", Vendor: "Unknown", Product: "Unknown", Name: "CVE-2026-0900"}
	fresh, upd = applyV(t, db, epoch0, "cf-v", []Vuln{mine, own}, true)
	if len(fresh) != 1 || fresh[0].DateAdded != "2026-11-09" || len(upd) != 0 {
		t.Fatalf("custom pull: new %v updated %v", fresh, upd)
	}
	got, _, _ := s.VulnByCVE(t.Context(), "CVE-2026-0001")
	if got.SourceID != "cisa-kev" || got.Vendor != "Synology" || !got.Ransomware {
		t.Errorf("custom feed touched a KEV row: %+v", got)
	}
	// The custom feed replaces its rows: its CVE leaves when it is no longer listed.
	applyV(t, db, epoch0.Add(48*time.Hour), "cf-v", []Vuln{}, true)
	if _, found, _ := s.VulnByCVE(t.Context(), "CVE-2026-0900"); found {
		t.Error("a CVE the custom feed dropped is still stored")
	}
	// KEV takes over a custom feed's CVE.
	applyV(t, db, epoch0, "cf-v", []Vuln{own}, true)
	kev := own
	kev.Vendor, kev.Product, kev.DateAdded = "Acme", "Box", "2026-11-05"
	fresh, upd = applyV(t, db, epoch0, "cisa-kev", []Vuln{kev}, false) // its first sighting as KEV: new, not updated
	got, _, _ = s.VulnByCVE(t.Context(), "CVE-2026-0900")
	if len(fresh) != 1 || len(upd) != 0 || got.SourceID != "cisa-kev" || got.Key() != "acme|box" {
		t.Errorf("KEV did not take the CVE: %v %v %+v", fresh, upd, got)
	}
	keys, _ := s.VulnsByProductKey(t.Context(), "synology|diskstation manager")
	pairs, _ := s.KevPairs(t.Context())
	if len(keys) != 1 || len(pairs) != 4 {
		t.Errorf("by key %d, pairs %d", len(keys), len(pairs))
	}
}

func TestApplyVulnsWritesNothingWhenTheTransactionFails(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	boom := errors.New("boom")
	err := db.Write(t.Context(), func(tx *sql.Tx) error {
		if _, _, err := applyVulns(t.Context(), tx, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-0001", "A", "B", "2026-11-03")}, false); err != nil {
			return err
		}
		if err := upsertIOCs(t.Context(), tx, store.FormatTS(epoch0), "ipsum", []iocInput{{Kind: "ip", Value: "185.220.101.47"}}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if v, i := count(t, db, `SELECT count(*) FROM feeds_vuln`), count(t, db, `SELECT count(*) FROM feeds_ioc`); v != 0 || i != 0 {
		t.Errorf("rolled back pull left %d vulnerabilities and %d indicators", v, i)
	}
}

func TestApplyTemplatesAndEPSS(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	// Nuclei is pulled first: the CVE reaches KEV later and still gets has_template at once.
	write(t, db, func(tx *sql.Tx) error {
		_, err := applyTemplates(t.Context(), tx, []string{"CVE-2026-0001"})
		return err
	})
	fresh, _ := applyV(t, db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-0001", "A", "B", "2026-11-03"), vuln("CVE-2026-0002", "C", "D", "2026-11-03")}, false)
	if !fresh[0].HasTemplate || fresh[1].HasTemplate {
		t.Errorf("new rows: %+v", fresh)
	}
	var changed []string
	write(t, db, func(tx *sql.Tx) (err error) {
		changed, err = applyTemplates(t.Context(), tx, []string{"CVE-2026-0002"})
		return err
	})
	a, _, _ := s.VulnByCVE(t.Context(), "CVE-2026-0001")
	b, _, _ := s.VulnByCVE(t.Context(), "CVE-2026-0002")
	if len(changed) != 2 || a.HasTemplate || !b.HasTemplate {
		t.Errorf("changed %v, a %v b %v", changed, a.HasTemplate, b.HasTemplate)
	}
	if ok, _ := s.HasTemplate(t.Context(), "CVE-2026-0002"); !ok {
		t.Error("HasTemplate")
	}

	var n int
	write(t, db, func(tx *sql.Tx) (err error) {
		n, err = applyEPSS(t.Context(), tx, map[string]float64{"CVE-2026-0001": 0.9, "CVE-2026-0002": 0.2, "CVE-2026-7777": 0.5}, map[string]float64{"CVE-2026-0001": 0.4})
		return err
	})
	a, _, _ = s.VulnByCVE(t.Context(), "CVE-2026-0001")
	b, _, _ = s.VulnByCVE(t.Context(), "CVE-2026-0002")
	if n != 2 || *a.EPSS != 0.9 || *a.EPSS7dAgo != 0.4 || *b.EPSS != 0.2 || b.EPSS7dAgo != nil {
		t.Errorf("n=%d a=%v/%v b=%v/%v", n, a.EPSS, a.EPSS7dAgo, b.EPSS, b.EPSS7dAgo)
	}
}

func listed(t testing.TB, db *store.DB, source string) int {
	return count(t, db, `SELECT count(*) FROM feeds_ioc_source WHERE source_id = ?`, source)
}

func applyI(t testing.TB, db *store.DB, at time.Time, source string, recs []iocInput) (added, removed int) {
	t.Helper()
	src, err := NewStore(db).source(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	added, removed, stale, err := applyIOCs(t.Context(), db, at, src, recs, nil, func(*sql.Tx, int, int) error { return nil })
	if err != nil || stale {
		t.Fatalf("apply: stale=%v err=%v", stale, err)
	}
	return added, removed
}

func TestApplyIOCsMergesFeedsAndCountsChanges(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	ip := func(v string) iocInput { return iocInput{Kind: "ip", Value: v} }
	conf := 0.9
	added, removed := applyI(t, db, epoch0, "ipsum", []iocInput{ip("185.220.101.47"), ip("45.148.10.95"), {Kind: "domain", Value: "bad.example.net", Confidence: &conf, FirstSeen: "2026-10-01"}})
	if added != 3 || removed != 0 {
		t.Fatalf("first pull +%d -%d", added, removed)
	}
	added, removed = applyI(t, db, epoch0.Add(6*time.Hour), "et-open", []iocInput{ip("185.220.101.47")})
	if added != 1 || removed != 0 || count(t, db, `SELECT count(*) FROM feeds_ioc`) != 3 {
		t.Fatalf("second feed +%d -%d", added, removed)
	}
	rec, found, err := s.IOCLookup(t.Context(), "ip", "185.220.101.47")
	if err != nil || !found || len(rec.Sightings) != 2 || !rec.FirstSeen.Equal(epoch0) || !rec.LastSeen.Equal(epoch0.Add(6*time.Hour)) {
		t.Fatalf("lookup %+v %v %v", rec, found, err)
	}
	dom, _, _ := s.IOCLookup(t.Context(), "domain", "bad.example.net")
	if dom.FirstSeen.Format("2006-01-02") != "2026-10-01" || dom.Sightings[0].Confidence != 0.9 || dom.Sightings[0].SourceName != "IPsum" {
		t.Errorf("domain: %+v", dom)
	}
	// ipsum drops the domain and one address, and adds a new one.
	added, removed = applyI(t, db, epoch0.Add(12*time.Hour), "ipsum", []iocInput{ip("185.220.101.47"), ip("103.75.190.12")})
	if added != 1 || removed != 2 || listed(t, db, "ipsum") != 2 {
		t.Fatalf("third pull +%d -%d, %d listed", added, removed, listed(t, db, "ipsum"))
	}
	// The same pull again changes nothing.
	if added, removed = applyI(t, db, epoch0.Add(13*time.Hour), "ipsum", []iocInput{ip("185.220.101.47"), ip("103.75.190.12")}); added != 0 || removed != 0 {
		t.Errorf("repeat +%d -%d", added, removed)
	}
	// An indicator nobody lists is kept for 30 days, then removed.
	if _, found, _ := s.IOCLookup(t.Context(), "domain", "bad.example.net"); !found {
		t.Fatal("unlisted indicator was removed at once")
	}
	if err := s.maintain(t.Context(), epoch0.Add(12*time.Hour+iocGrace+time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.IOCLookup(t.Context(), "domain", "bad.example.net"); found {
		t.Error("unlisted indicator survived the grace period")
	}
	if _, found, _ := s.IOCLookup(t.Context(), "ip", "185.220.101.47"); !found {
		t.Error("a listed indicator was pruned")
	}
}

// IOCListed (logs' digest): true only while a switched-on feed lists an indicator.
func TestIOCListedNeedsASwitchedOnFeedWithListings(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	if ok, err := s.IOCListed(t.Context()); ok || err != nil {
		t.Fatalf("nothing loaded: %v %v", ok, err)
	}
	applyI(t, db, epoch0, "ipsum", []iocInput{{Kind: "ip", Value: "185.220.101.47"}})
	if ok, err := s.IOCListed(t.Context()); !ok || err != nil {
		t.Fatalf("ipsum lists one: %v %v", ok, err)
	}
	if err := db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET enabled = 0 WHERE id = 'ipsum'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.IOCListed(t.Context()); ok || err != nil {
		t.Fatalf("ipsum off: %v %v", ok, err)
	}
}

func TestDeleteCustomRemovesWhatItLoaded(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	addCustom(t, db, "cf-i", "Partner IOC", KindIOC)
	addCustom(t, db, "cf-v", "Partner CVEs", KindVulnerabilities)
	applyI(t, db, epoch0, "ipsum", []iocInput{{Kind: "ip", Value: "185.220.101.47"}})
	applyI(t, db, epoch0, "cf-i", []iocInput{{Kind: "ip", Value: "185.220.101.47"}, {Kind: "ip", Value: "45.148.10.95"}})
	applyV(t, db, epoch0, "cf-v", []Vuln{{CVE: "CVE-2026-0900", Vendor: "A", Product: "B", Name: "n"}}, true)
	applyV(t, db, epoch0, "cisa-kev", []Vuln{vuln("CVE-2026-0001", "A", "B", "2026-11-03")}, false)
	for _, id := range []string{"cf-i", "cf-v"} {
		write(t, db, func(tx *sql.Tx) error { return deleteCustom(t.Context(), tx, id) })
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_ioc`); n != 1 {
		t.Errorf("%d indicators left, want only the one ipsum lists", n)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_vuln`); n != 1 {
		t.Errorf("%d vulnerabilities left, want the KEV one", n)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_source WHERE builtin = 0`); n != 0 {
		t.Errorf("%d custom feeds left", n)
	}
	// A built-in feed is never deleted by deleteCustom.
	write(t, db, func(tx *sql.Tx) error { return deleteCustom(t.Context(), tx, "ipsum") })
	if n := count(t, db, `SELECT count(*) FROM feeds_source WHERE id = 'ipsum'`); n != 1 {
		t.Error("a built-in feed was deleted")
	}
}

func TestRecordOutcomeUpdatesPullState(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	rec := func(o outcome) {
		write(t, db, func(tx *sql.Tx) error { return recordOutcome(t.Context(), tx, "ipsum", o) })
	}
	rec(outcome{Started: epoch0, Finished: epoch0.Add(time.Second), OK: true, Accepted: 10, Rejected: 2, Records: 10, Note: "2 of 12 rows were rejected.", ETag: `"a"`, Reasons: []Reason{{Reason: "x", Count: 2}}})
	r, _ := s.source(t.Context(), "ipsum")
	if r.Status != "ok" || *r.Records != 10 || r.Failures != 0 || *r.Error != "2 of 12 rows were rejected." || *r.ETag != `"a"` || !r.LastSuccess.Equal(epoch0.Add(time.Second)) {
		t.Errorf("after ok: %+v", r)
	}
	rec(outcome{Started: epoch0.Add(time.Hour), Finished: epoch0.Add(time.Hour), Err: "The source answered HTTP 503."})
	r, _ = s.source(t.Context(), "ipsum")
	if r.Status != "error" || r.Failures != 1 || *r.Records != 10 || *r.Error != "The source answered HTTP 503." || !r.LastSuccess.Equal(epoch0.Add(time.Second)) || !r.LastFetch.Equal(epoch0.Add(time.Hour)) {
		t.Errorf("after error: %+v", r)
	}
	rec(outcome{Started: epoch0.Add(2 * time.Hour), Finished: epoch0.Add(2 * time.Hour), OK: true, NotModified: true, ETag: `"a"`})
	r, _ = s.source(t.Context(), "ipsum")
	if r.Status != "ok" || r.Failures != 0 || *r.Records != 10 || r.Error != nil {
		t.Errorf("after 304: %+v", r)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_fetch_log WHERE source_id = 'ipsum'`); n != 3 {
		t.Errorf("%d log rows", n)
	}
	// Retention: old rows go, the newest ok row stays.
	if err := s.maintain(t.Context(), epoch0.Add(2*time.Hour+fetchLogKeep+time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, `SELECT count(*) FROM feeds_fetch_log WHERE source_id = 'ipsum'`); n != 1 {
		t.Errorf("%d log rows after pruning, want the newest ok row", n)
	}
}
