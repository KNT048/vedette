package feeds

import (
	"database/sql"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
)

// INV-28 (#825): nvd-kev keeps each KEV CVE's CVSS base score from the answer it already reads (no new request); an update replaces the
// score of the CVEs NVD answered for (a score NVD took away goes); CVSSOf falls back to nvd-recent's score for a CVE not on the exploited
// lists. Review r1 L1: only the one-time mark of migration 0015 forces a full pull, never "no score stored".
func TestContract_INV28_CVSSFromNVD(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("nvd-kev")
	e.mirror("nvd-kev", o.url("/nvd"))
	nvdOrigin(o, 3)
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	cves := []string{"CVE-2024-0000", "CVE-2024-0001", "CVE-2024-0002", "CVE-2026-50001", "CVE-2026-50002", "CVE-2099-0001"}
	read := func() map[string]CVSS {
		t.Helper()
		got, err := e.svc.st.CVSSOf(t.Context(), cves)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	nvd75 := CVSS{Score: 7.5, Version: "3.1", Source: "nvd", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
	if got := read(); !maps.Equal(got, map[string]CVSS{"CVE-2024-0000": nvd75, "CVE-2024-0001": nvd75, "CVE-2024-0002": nvd75}) {
		t.Fatalf("after the first pull: %+v", got)
	}
	v4 := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	update := func(want string, body string) {
		t.Helper()
		o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("lastModStartDate") != ""; got != (want == "update") {
				t.Errorf("want a %s pull: %s", want, r.URL.RawQuery)
			}
			_, _ = fmt.Fprint(w, body)
		})
		e.setNow(e.clock().Add(25 * time.Hour))
		if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
			t.Fatal(err)
		}
	}

	// the next day, an update: CVE-2024-0000 now has another scorer's 4.0 score, CVE-2024-0001 lost its score; CVE-2024-0002 was not answered
	update("update", `{"totalResults":2,"vulnerabilities":[
	 {"cve":{"id":"CVE-2024-0000","metrics":{"cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":8.7,"baseSeverity":"HIGH","vectorString":"`+v4+`"}}]},"configurations":[]}},
	 {"cve":{"id":"CVE-2024-0001","metrics":{},"configurations":[]}}]}`)
	if got := read(); !maps.Equal(got, map[string]CVSS{"CVE-2024-0000": {Score: 8.7, Version: "4.0", Source: "cna", Vector: v4}, "CVE-2024-0002": nvd75}) {
		t.Fatalf("after the update: %+v", got)
	}

	// nvd-recent's scores (cvss_* columns) for CVEs not on the exploited lists; nvd-kev's wins for a CVE both hold
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_recent_cve (cve, published, last_modified, status, severity, score, cvss_score, cvss_version, cvss_source, cvss_vector) VALUES
 ('CVE-2026-50001', '2026-08-01T00:00:00.000Z', '2026-08-02T00:00:00.000Z', 'Analyzed', 'MEDIUM', 6.1, 6.1, '3.1', 'cna', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),
 ('CVE-2026-50002', '2026-08-01T00:00:00.000Z', '2026-08-02T00:00:00.000Z', 'Analyzed', 'MEDIUM', 5.3, NULL, NULL, NULL, NULL),
 ('CVE-2024-0002', '2026-08-01T00:00:00.000Z', '2026-08-02T00:00:00.000Z', 'Analyzed', 'CRITICAL', 9.1, 9.1, '3.1', 'nvd', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N')`)
		return err
	})
	want := map[string]CVSS{"CVE-2024-0000": {Score: 8.7, Version: "4.0", Source: "cna", Vector: v4}, "CVE-2024-0002": nvd75,
		"CVE-2026-50001": {Score: 6.1, Version: "3.1", Source: "cna", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}}
	if got := read(); !maps.Equal(got, want) {
		t.Fatalf("with nvd-recent (a row with tier 3's score but no CVSS pick is not a score): %+v", got)
	}

	// L1: data with no score at all never makes the pulls full
	write(t, e.db, func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), `DELETE FROM feeds_cvss`); return err })
	update("update", `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","metrics":{},"configurations":[]}}]}`)
	update("update", `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","metrics":{},"configurations":[]}}]}`)

	// the one-time mark (migration 0015) asks for one full pull, which fills the table and clears the mark
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET full_due = 1 WHERE id = 'nvd-kev'`)
		return err
	})
	update("full", `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},"configurations":[]}},
	 {"cve":{"id":"CVE-2024-0002","metrics":{"cvssMetricV2":[{"type":"Primary","baseSeverity":"HIGH","cvssData":{"version":"2.0","baseScore":10.0,"vectorString":"AV:N/AC:L/Au:N/C:C/I:C/A:C"}}]},"configurations":[]}}]}`)
	if due, _ := e.svc.st.fullDue(t.Context(), nvdFeedID); due {
		t.Fatal("the mark stayed after the full pull")
	}
	if got := read(); got["CVE-2024-0001"] != (CVSS{Score: 9.8, Version: "3.1", Source: "nvd", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}) ||
		got["CVE-2024-0002"] != (CVSS{Score: 10, Version: "2.0", Source: "nvd", Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"}) {
		t.Fatalf("after the full pull: %+v", got)
	}
	update("update", `{"totalResults":0,"vulnerabilities":[]}`)
}

// INV-28: nvd-recent stores its CVSS pick in the cvss_* columns, apart from tier 3's severity/score, so a finding of a CVE not on the
// exploited lists shows it too.
func TestStoreRecentPage_KeepsCVSSVersionAndSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.clock()
	pub := now.AddDate(0, -1, 0).UTC().Format("2006-01-02T15:04:05.000")
	d, err := ParseNVDRecent([]byte(`{"totalResults":2,"vulnerabilities":[
{"cve":{"id":"CVE-2026-0011","published":"` + pub + `","lastModified":"` + pub + `","vulnStatus":"Analyzed",
 "metrics":{"cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":9.3,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]}}},
{"cve":{"id":"CVE-2026-0012","published":"` + pub + `","lastModified":"` + pub + `","vulnStatus":"Awaiting Analysis",
 "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]}}}]}`))
	if err != nil || len(d.Records) != 2 || d.Records[1].Severity != "HIGH" || d.Records[1].CVSS != nil {
		t.Fatalf("parse (tier 3 keeps a score without vector, CVSS does not): %+v %v", d, err)
	}
	write(t, e.db, func(tx *sql.Tx) error { return storeRecentPage(t.Context(), tx, d.Records, now.AddDate(0, 0, -365)) })
	got, err := e.svc.st.CVSSOf(t.Context(), []string{"CVE-2026-0011", "CVE-2026-0012"})
	if err != nil || !maps.Equal(got, map[string]CVSS{"CVE-2026-0011": {Score: 9.3, Version: "4.0", Source: "cna", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}) {
		t.Fatalf("%+v %v", got, err)
	}
}

// Migration 0015 on a box that has data: nvd-kev gets its one-time full-pull mark and pulls at the next check (not a day after its last
// success, review r2 M1); nvd-recent keeps its cursor (no refill, review r2 M2).
func TestMigration0015MarksAFullPullOnly(t *testing.T) {
	t.Parallel()
	before := fstest.MapFS{}
	entries, err := fs.ReadDir(Migrations, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if en.Name() >= "0015" {
			continue
		}
		b, err := fs.ReadFile(Migrations, en.Name())
		if err != nil {
			t.Fatal(err)
		}
		before[en.Name()] = &fstest.MapFile{Data: b}
	}
	db := storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "feeds", FS: before})
	s := &Store{db: db}
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	if err := s.SeedBuiltins(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	execSQL(t, db, `INSERT INTO feeds_recent_cve (cve, published, last_modified, status) VALUES ('CVE-2026-0001', '2026-10-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z', 'Analyzed')`)
	execSQL(t, db, `INSERT INTO feeds_recent_cursor (id, url, mode, win_from, win_to, until, next_index, total) VALUES (1, 'https://x.test/nvd', 'done', '2026-11-14T00:00:00.000Z', '2026-11-14T00:00:00.000Z', '2026-11-14T00:00:00.000Z', 0, 0)`)
	if err := store.Migrate(t.Context(), db, "feeds", Migrations); err != nil {
		t.Fatal(err)
	}
	if due, err := s.fullDue(t.Context(), nvdFeedID); err != nil || !due {
		t.Fatalf("nvd-kev full_due = %v %v", due, err)
	}
	if due, _ := s.fullDue(t.Context(), recentFeedID); due {
		t.Fatal("only nvd-kev is marked")
	}
	if c, err := s.recentCursor(t.Context()); err != nil || c == nil || c.Mode != modeDone {
		t.Fatalf("nvd-recent's cursor must stay: %+v %v", c, err)
	}
}

// Review r2 M1: while the mark is set, nvd-kev is due at the next check even a few minutes after a good pull; a failing feed keeps its
// back-off; once the full pull is stored the feed is back on its 24-hour schedule.
func TestRunPull_FullDuePullsNVDKevAtTheNextCheck(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("nvd-kev")
	e.mirror("nvd-kev", o.url("/nvd"))
	nvdOrigin(o, 3)
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	n := o.count("/nvd")
	e.setNow(e.clock().Add(10 * time.Minute))
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if o.count("/nvd") != n {
		t.Fatal("nvd-kev pulled again 10 minutes after a good pull without the mark")
	}
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET full_due = 1 WHERE id = 'nvd-kev'`)
		return err
	})
	e.setNow(e.clock().Add(5 * time.Minute))
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if o.count("/nvd") == n {
		t.Fatal("the mark did not make nvd-kev due at the next check")
	}
	if due, _ := e.svc.st.fullDue(t.Context(), nvdFeedID); due {
		t.Fatal("the mark stayed after the full pull")
	}
	n = o.count("/nvd")
	e.setNow(e.clock().Add(5 * time.Minute))
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if o.count("/nvd") != n {
		t.Fatal("nvd-kev pulled again after the mark was cleared")
	}
	// a failing feed with the mark waits out its back-off
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE feeds_source SET full_due = 1, failures = 3, status = 'error', last_fetch = ? WHERE id = 'nvd-kev'`, store.FormatTS(e.clock()))
		return err
	})
	e.setNow(e.clock().Add(5 * time.Minute))
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if o.count("/nvd") != n {
		t.Fatal("a failing nvd-kev skipped its back-off")
	}
}
