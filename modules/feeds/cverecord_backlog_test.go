package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// backlogCVE is the i-th old CVE an exploit index names in these tests, and the path of its record.
func backlogCVE(i int) (cve, path string) {
	cve = fmt.Sprintf("CVE-2015-%04d", 1000+i)
	return cve, fmt.Sprintf("/repo/cves/2015/%dxxx/%s.json", (1000+i)/1000, cve)
}

// backlogEnv is a box whose whole list was read before an exploit index named n older CVEs (none of them has a record), with every
// record served.
func backlogEnv(t *testing.T, n int) (*env, *origin) {
	t.Helper()
	e, o, _ := recordEnv(t, false)
	sigs := make([]publicSignal, n)
	for i := range sigs {
		cve, path := backlogCVE(i)
		sigs[i] = publicSignal{CVE: cve, Date: epoch0}
		o.serve(path, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(recordJSON(cve, "2015-06-01", `{"vendor":"Acme","product":"Old","versions":[{"version":"1.0","lessThan":"1.4","status":"affected"}]}`))
		})
	}
	write(t, e.db, func(tx *sql.Tx) error {
		if err := applyPublicSignals(t.Context(), tx, epoch0, exploitDBFeedID, sigs); err != nil {
			return err
		}
		for _, g := range sigs { // the NVD pull brought them into the catalogue after the whole list was read
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, nvd_status, nvd_at, updated_at) VALUES (?, '2015-06-01T00:00:00.000Z', 'Analyzed', ?, ?)
ON CONFLICT(cve) DO NOTHING`, g.CVE, "2026-11-01T00:00:00.000Z", "2026-11-01T00:00:00.000Z"); err != nil {
				return err
			}
		}
		return nil
	})
	return e, o
}

// withoutRecord counts the catalogue's CVEs whose record was never read.
func withoutRecord(t *testing.T, e *env) int {
	t.Helper()
	return count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE record_at IS NULL`)
}

// A CVE that enters the catalogue after the whole list was read gets its record at the next pull, by ID: one published inside the
// window (the change log no longer brings it) and an older one a public exploit index names, with the record's affected versions.
func TestCVERecords_CatalogueCVEWithoutRecordReadAtTheNextPull(t *testing.T) {
	t.Parallel()
	e, o := backlogEnv(t, 1)
	old, _ := backlogCVE(0)
	write(t, e.db, func(tx *sql.Tx) error {
		return storeRecords(t.Context(), tx, []NVDRecord{{CVE: "CVE-2026-7100", Published: e.clock().AddDate(0, -2, 0), LastModified: epoch0, Status: "Received"}}, e.clock())
	})
	o.serve("/repo/cves/2026/7xxx/CVE-2026-7100.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(recordJSON("CVE-2026-7100", "2026-09-01", `{"vendor":"Acme","product":"Hub","versions":[{"version":"2.0","lessThan":"2.6","status":"affected"}]}`))
	})
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	for cve, end := range map[string]string{"CVE-2026-7100": "2.6", old: "1.4"} {
		var got string
		if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT end_excl FROM feeds_cve_range WHERE cve = ? AND origin = 'cna'`, cve).Scan(&got); err != nil || got != end {
			t.Errorf("%s: record range %q %v, want %q", cve, got, err, end)
		}
	}
	if n := withoutRecord(t, e); n != 0 {
		t.Fatalf("%d catalogue CVEs still without a record", n)
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "/releases/") || strings.HasSuffix(h.path, "deltaLog.json") {
			t.Fatalf("a bulk request for a few missing records: %s", h.path)
		}
	}
}

// Hundreds of older CVEs an exploit index names after the whole list was read: they are asked for by ID, the exploited lists' first,
// at most recordIDBudget asks a pull a quarter second apart, never one twice and never a read of the whole list; every pull goes on
// where the last stopped until none is left.
func TestCVERecords_BacklogDrainsByIDWithinTheBudget(t *testing.T) {
	t.Parallel()
	const n = recordIDBudget + 150
	e, o := backlogEnv(t, n)
	before := withoutRecord(t, e)
	asked := func() (total, most int) {
		for i := range n {
			_, path := backlogCVE(i)
			c := o.count(path)
			if c > 0 {
				total++
			}
			most = max(most, c)
		}
		return total, most
	}
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if o.count("/repo/cves/2024/3xxx/CVE-2024-3400.json") != 1 {
		t.Fatal("the exploited list's CVE was not asked first")
	}
	got, most := asked()
	if all := len(o.all()); all > recordIDBudget || got != recordIDBudget-4 || most != 1 { // the 4 CVEs of the CISA list come out of the same budget
		t.Fatalf("first pull: %d requests, %d backlog records (most %d times)", all, got, most)
	}
	for _, w := range e.waited() {
		if w != recordPause && w != recordLeftPause {
			t.Fatalf("a wait of %v between asks", w)
		}
	}
	if left := withoutRecord(t, e); left != before-(recordIDBudget-4)-4 { // the CISA list's 4 are stamped too (two are not published)
		t.Fatalf("after one pull %d of %d without a record", left, before)
	}
	if f := e.feed(cveOrgFeedID); !strings.Contains(deref(f.Error), "154 CVEs of the catalogue still have no record") {
		t.Fatalf("note %q", deref(f.Error))
	}
	e.setNow(e.clock().Add(time.Hour))
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if got, most := asked(); got != n || most != 1 {
		t.Fatalf("after two pulls asked %d of %d (most %d times)", got, n, most)
	}
	if left := withoutRecord(t, e); left != 0 {
		t.Fatalf("%d still without a record", left)
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "/releases/") {
			t.Fatalf("the whole list was read again: %s", h.path)
		}
	}
	t.Logf("catalogue CVEs without a record: %d before, %d after two pulls", before, 0)
}

// A record the source does not have (404) is remembered: the next pulls do not ask it again (an older CVE, or one of the window the
// change log brings once it is published), and a CVE only a finding pins is never asked.
func TestCVERecords_MissingRecordNotAskedEveryPull(t *testing.T) {
	t.Parallel()
	e, o := backlogEnv(t, 1)
	old, oldPath := backlogCVE(0)
	o.serve(oldPath, func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	o.serve("/repo/cves/2026/7xxx/CVE-2026-7101.json", func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	e.svc.Pins = func(context.Context) ([]string, error) { return []string{"CVE-2019-7003"}, nil }
	write(t, e.db, func(tx *sql.Tx) error {
		if err := storeRecords(t.Context(), tx, []NVDRecord{{CVE: "CVE-2026-7101", Published: e.clock().AddDate(0, -1, 0), LastModified: epoch0, Status: "Received"}}, e.clock()); err != nil {
			return err
		}
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_cve (cve, published, nvd_status, updated_at) VALUES ('CVE-2019-7003', '2019-10-01T00:00:00.000Z', 'Analyzed', '2026-11-01T00:00:00.000Z')`)
		return err
	})
	for range 3 {
		if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
			t.Fatal(err)
		}
		e.setNow(e.clock().Add(time.Hour))
		recordsCurrent(t, e, o)
	}
	if a, b := o.count(oldPath), o.count("/repo/cves/2026/7xxx/CVE-2026-7101.json"); a != 1 || b != 1 {
		t.Fatalf("a missing record asked %d and %d times in three pulls", a, b)
	}
	for _, h := range o.all() {
		if strings.Contains(h.path, "CVE-2019-7003") {
			t.Fatalf("a CVE only a finding pins was asked for by ID: %s", h.path)
		}
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE cve IN (?, 'CVE-2026-7101') AND record_at IS NOT NULL`, old); n != 2 {
		t.Fatalf("%d missing records remembered, want 2", n)
	}
}

// A pull stopped half way (the box restarts) keeps what it read, in batches; the next pull goes on with the rest and asks again at most
// the records of the batch it had not written.
func TestCVERecords_BacklogResumesAfterAStop(t *testing.T) {
	t.Parallel()
	const n = 200
	e, o := backlogEnv(t, n)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var asks atomic.Int32
	for i := range n {
		cve, path := backlogCVE(i)
		o.serve(path, func(w http.ResponseWriter, _ *http.Request) {
			if asks.Add(1) == 120 {
				cancel() // the box stops during the 120th ask
			}
			_, _ = w.Write(recordJSON(cve, "2015-06-01", `{"vendor":"Acme","product":"Old","defaultStatus":"affected"}`))
		})
	}
	if _, err := e.svc.buildCVERecords(ctx, e.feed(cveOrgFeedID), pullPlan{}); err == nil {
		t.Fatal("a stopped pull reported no error")
	}
	stored := count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE cve LIKE 'CVE-2015-%' AND record_at IS NOT NULL`)
	if stored < 119-recordBacklogBatch || stored >= 120 {
		t.Fatalf("%d records kept after the stop", stored)
	}
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	twice := 0
	for i := range n {
		_, path := backlogCVE(i)
		switch c := o.count(path); {
		case c == 2:
			twice++
		case c != 1:
			t.Fatalf("%s asked %d times", path, c)
		}
	}
	if twice > recordBacklogBatch {
		t.Fatalf("%d records asked again after the stop", twice)
	}
	if left := withoutRecord(t, e); left != 0 {
		t.Fatalf("%d still without a record", left)
	}
}

// While the whole list is not read yet, nothing is asked for by ID beyond the exploited lists and signals of recordDue: the archive
// brings the rest.
func TestCVERecords_NoBacklogAsksBeforeTheWholeList(t *testing.T) {
	t.Parallel()
	e, o := backlogEnv(t, recordRescanUnread)
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM feeds_nvd_cursor WHERE selector = ?`, selectorRecord)
		return err
	})
	e.svc.DataDir = t.TempDir()
	day := e.clock().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	o.serve("/repo/releases/download/cve_"+day+"_2300Z/"+day+"_all_CVEs_at_midnight.zip.zip", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	_ = e.svc.Fetch(t.Context(), cveOrgFeedID)
	for i := range recordRescanUnread {
		if _, path := backlogCVE(i); o.count(path) != 0 {
			t.Fatalf("%s asked by ID before the whole list was read", path)
		}
	}
}
