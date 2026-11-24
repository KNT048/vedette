package feeds

import (
	"bytes"
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ownEnv is a box whose whole list was read from the archive of 2026-11-19 and whose changes are read up to now (2026-11-21 10:00),
// with a CVE a custom list keeps and one a box-built signal keeps, neither with a record nor published inside the window. The archives
// of 2026-11-20 and 2026-11-21 are served (counted by wholeReads); a by-ID ask for either CVE hits an undeclared path.
func ownEnv(t *testing.T) (*env, *origin) {
	t.Helper()
	e, o, _ := recordEnv(t, true)
	e.setNow(time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC))
	write(t, e.db, func(tx *sql.Tx) error {
		for _, cve := range []string{"CVE-2024-3400", "CVE-2026-0001", "CVE-2026-0004", "CVE-2026-0005"} { // the CISA list's: read by ID before
			if err := ensureCVE(t.Context(), tx, cve, "2026-11-05T00:00:00.000Z"); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(t.Context(), `UPDATE feeds_cve SET record_at = '2026-11-21T09:00:00.000Z'`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_source (id, builtin, name, kind, format, url, parser, created_at)
VALUES ('cf-own', 0, 'Own list', 'vulnerabilities', 'json', 'https://feeds.example.com/x.json', '{}', '2026-11-05T00:00:00.000Z')`); err != nil {
			return err
		}
		if err := addOwnListCVE(t, tx, "CVE-2019-0900"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies)
VALUES ('CVE-2018-0901', 'exploited', 'ids-local', '2026-11-05T00:00:00.000Z', '2026-11-05T00:00:00.000Z', '2026-11-05T00:00:00.000Z', 1)`); err != nil {
			return err
		}
		now := e.clock()
		return saveNVDCursor(t.Context(), tx, selectorRecord, recentCursor{URL: recordCursorURL(o.url("/repo")), Mode: modeDone,
			From: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), To: now, Until: now})
	})
	for _, day := range []string{"2026-11-20", "2026-11-21"} {
		o.serve(wholePath(day), func(w http.ResponseWriter, r *http.Request) {
			http.ServeContent(w, r, "a.zip", time.Time{}, bytes.NewReader(dailyArchive(t, map[string][]byte{
				"cves/2019/0xxx/CVE-2019-0900.json": recordJSON("CVE-2019-0900", "2019-03-01", `{"vendor":"Acme","product":"Old","versions":[{"version":"1.0","lessThan":"1.7","status":"affected"}]}`),
			})))
		})
	}
	return e, o
}

// addOwnListCVE puts cve on the custom list cf-own.
func addOwnListCVE(t *testing.T, tx *sql.Tx, cve string) error {
	t.Helper()
	if err := ensureCVE(t.Context(), tx, cve, "2026-11-05T00:00:00.000Z"); err != nil {
		return err
	}
	_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_kev (cve, list, source_id, vendor, product, name, date_added, updated_at)
VALUES (?, 'custom:cf-own', 'cf-own', 'Acme', 'Old', 'x', '2026-11-05', '2026-11-05T00:00:00.000Z')`, cve)
	return err
}

func wholePath(day string) string {
	return "/repo/releases/download/cve_" + day + "_2300Z/" + day + "_all_CVEs_at_midnight.zip.zip"
}

// wholeReads counts the requests for any day's whole list.
func wholeReads(o *origin) int {
	n := 0
	for _, h := range o.all() {
		if strings.HasSuffix(h.path, "_all_CVEs_at_midnight.zip.zip") {
			n++
		}
	}
	return n
}

// noOwnAsks fails when a CVE only this box's own lists keep was asked for by its ID.
func noOwnAsks(t *testing.T, o *origin) {
	t.Helper()
	for _, h := range o.all() {
		if strings.Contains(h.path, "CVE-2019-09") || strings.Contains(h.path, "CVE-2018-09") {
			t.Fatalf("a CVE only this box's own lists keep was asked for by ID: %s", h.path)
		}
	}
}

// Privacy and freshness: a CVE only a custom list or a box-built signal keeps, without a record, starts a read of the whole list at the
// next pull (not a week later) and is never asked for by ID; the read stores its record and stamps the one the list does not hold, so
// the next pulls start none for them.
func TestCVERecords_OwnListCVEWithoutRecordReadsTheWholeListEarly(t *testing.T) {
	t.Parallel()
	e, o := ownEnv(t)
	if n, err := e.svc.st.recordOwnUnread(t.Context(), e.clock().AddDate(0, 0, -windowDays)); err != nil || n != 2 {
		t.Fatalf("own CVEs without a record = %d %v, want 2", n, err)
	}
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if o.count(wholePath("2026-11-20")) != 1 || wholeReads(o) != 1 {
		t.Fatalf("whole-list reads %d, want one of 2026-11-20: %+v", wholeReads(o), o.all())
	}
	noOwnAsks(t, o)
	var end string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT end_excl FROM feeds_cve_range WHERE cve = 'CVE-2019-0900' AND origin = 'cna'`).Scan(&end); err != nil || end != "1.7" {
		t.Fatalf("the custom list's record: %q %v", end, err)
	}
	if n, err := e.svc.st.recordOwnUnread(t.Context(), e.clock().AddDate(0, 0, -windowDays)); err != nil || n != 0 {
		t.Fatalf("after the read %d own CVEs without a record %v", n, err)
	}
	if f := e.feed(cveOrgFeedID); !strings.Contains(deref(f.Error), "2 CVEs kept only by this box's own lists or signals have no record: reading the whole list again") {
		t.Fatalf("note %q", deref(f.Error))
	}
	// two days later, nothing new without a record: no other read
	e.setNow(time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC))
	recordsCurrentFrom(t, e, o, time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if wholeReads(o) != 1 {
		t.Fatalf("%d whole-list reads, want 1", wholeReads(o))
	}
}

// recordsCurrentFrom says the whole list of from is read and its changes up to now.
func recordsCurrentFrom(t *testing.T, e *env, o *origin, from time.Time) {
	t.Helper()
	write(t, e.db, func(tx *sql.Tx) error {
		now := e.clock()
		return saveNVDCursor(t.Context(), tx, selectorRecord, recentCursor{URL: recordCursorURL(o.url("/repo")), Mode: modeDone, From: from, To: now, Until: now})
	})
}

// At most one early read of the whole list in 24 hours, also when the box restarts between two pulls: a second own CVE without a
// record waits for the day after the first read, then starts the next one.
func TestCVERecords_OwnListEarlyReadAtMostOnceADay(t *testing.T) {
	t.Parallel()
	e, o := ownEnv(t)
	e.setNow(time.Date(2026, 11, 21, 22, 0, 0, 0, time.UTC))
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if wholeReads(o) != 1 {
		t.Fatalf("%d whole-list reads, want 1", wholeReads(o))
	}
	write(t, e.db, func(tx *sql.Tx) error { return addOwnListCVE(t, tx, "CVE-2019-0902") })
	// the box restarts: a new service over the same database
	svc, err := NewService(e.svc.Deps)
	if err != nil {
		t.Fatal(err)
	}
	svc.wait = e.svc.wait
	// 3 hours later the archive of 2026-11-21 is newer than the one read, but the last early read is not 24 hours old
	e.setNow(time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC))
	recordsCurrentFrom(t, e, o, time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	if err := svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if wholeReads(o) != 1 {
		t.Fatalf("a second early read within 24 hours: %d whole-list reads", wholeReads(o))
	}
	e.setNow(time.Date(2026, 11, 22, 22, 30, 0, 0, time.UTC))
	recordsCurrentFrom(t, e, o, time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	if err := svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if o.count(wholePath("2026-11-21")) != 1 || wholeReads(o) != 2 {
		t.Fatalf("after 24 hours: %d whole-list reads (%d of 2026-11-21), want 2", wholeReads(o), o.count(wholePath("2026-11-21")))
	}
	noOwnAsks(t, o)
	if n := count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE cve = 'CVE-2019-0902' AND record_at IS NOT NULL`); n != 1 {
		t.Fatal("the second own CVE is not stamped after the read")
	}
}

// A CVE a public list names, without a record, is asked for by its ID as before: it starts no read of the whole list.
func TestCVERecords_PublicListCVEWithoutRecordAskedByIDNotWholeList(t *testing.T) {
	t.Parallel()
	e, o := ownEnv(t)
	write(t, e.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(t.Context(), `DELETE FROM feeds_kev WHERE source_id = 'cf-own'`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(t.Context(), `DELETE FROM feeds_signal WHERE source = 'ids-local'`); err != nil {
			return err
		}
		return applyPublicSignals(t.Context(), tx, epoch0, exploitDBFeedID, []publicSignal{{CVE: "CVE-2015-1000", Date: epoch0}})
	})
	_, path := backlogCVE(0)
	o.serve(path, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(recordJSON("CVE-2015-1000", "2015-06-01", `{"vendor":"Acme","product":"Old","defaultStatus":"affected"}`))
	})
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if o.count(path) != 1 || wholeReads(o) != 0 {
		t.Fatalf("asked by ID %d times, %d whole-list reads", o.count(path), wholeReads(o))
	}
	if cur, _ := e.svc.st.nvdCursor(t.Context(), selectorRecordOwn); cur != nil {
		t.Fatalf("an early read was marked: %+v", cur)
	}
}

// While a read of the whole list is unfinished, an own CVE without a record starts nothing else: the pull goes on with that read (the
// same day's archive) and marks no early read.
func TestCVERecords_OwnListNoEarlyReadWhileTheWholeListLoads(t *testing.T) {
	t.Parallel()
	e, o := ownEnv(t)
	write(t, e.db, func(tx *sql.Tx) error {
		day := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
		return saveNVDCursor(t.Context(), tx, selectorRecord, recentCursor{URL: recordCursorURL(o.url("/repo")), Mode: modeFill, From: day, To: day, Until: day})
	})
	if err := e.svc.Fetch(t.Context(), cveOrgFeedID); err != nil {
		t.Fatal(err)
	}
	if o.count(wholePath("2026-11-20")) != 1 || wholeReads(o) != 1 {
		t.Fatalf("whole-list reads %+v", o.all())
	}
	if cur, _ := e.svc.st.nvdCursor(t.Context(), selectorRecordOwn); cur != nil {
		t.Fatalf("an early read was marked during a running one: %+v", cur)
	}
	noOwnAsks(t, o)
}
