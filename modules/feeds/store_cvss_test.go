package feeds

import (
	"database/sql"
	"fmt"
	"maps"
	"net/http"
	"testing"
	"time"
)

// INV-28 (#825): nvd-kev keeps each KEV CVE's CVSS base score from the answer it already reads (no new request); an update replaces the
// score of the CVEs NVD answered for (a score NVD took away goes); an empty table makes the next pull a full one; CVSSOf falls back to
// nvd-recent's score for a CVE not on the exploited lists, without a version for a row stored before migration 0015.
func TestContract_INV28_CVSSFromNVD(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("nvd-kev")
	e.mirror("nvd-kev", o.url("/nvd"))
	nvdOrigin(o, 3, "2.0")
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	cves := []string{"CVE-2024-0000", "CVE-2024-0001", "CVE-2024-0002", "CVE-2026-50001", "CVE-2026-50002", "CVE-2026-50003", "CVE-2099-0001"}
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

	// the next day, an update: CVE-2024-0000 now has a CNA 4.0 score, CVE-2024-0001 lost its score; CVE-2024-0002 was not answered
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("lastModStartDate") == "" {
			t.Errorf("full pull the next day: %s", r.URL.RawQuery)
		}
		_, _ = fmt.Fprint(w, `{"totalResults":2,"vulnerabilities":[
		 {"cve":{"id":"CVE-2024-0000","metrics":{"cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":8.7,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N"}}]},"configurations":[]}},
		 {"cve":{"id":"CVE-2024-0001","metrics":{},"configurations":[]}}]}`)
	})
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if got := read(); !maps.Equal(got, map[string]CVSS{"CVE-2024-0000": {Score: 8.7, Version: "4.0", Source: "cna"}, "CVE-2024-0002": nvd75}) {
		t.Fatalf("after the update: %+v", got)
	}

	// nvd-recent's scores for CVEs not on the exploited lists; nvd-kev's wins for a CVE both hold
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO feeds_recent_cve (cve, published, last_modified, status, severity, score, cvss_version, cvss_source, cvss_vector) VALUES
 ('CVE-2026-50001', '2026-08-01T00:00:00.000Z', '2026-08-02T00:00:00.000Z', 'Analyzed', 'MEDIUM', 6.1, '3.1', 'cna', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'),
 ('CVE-2026-50002', '2026-08-01T00:00:00.000Z', '2026-08-02T00:00:00.000Z', 'Analyzed', 'MEDIUM', 5.3, NULL, NULL, NULL),
 ('CVE-2026-50003', '2026-08-01T00:00:00.000Z', '2026-08-02T00:00:00.000Z', 'Awaiting Analysis', NULL, NULL, NULL, NULL, NULL),
 ('CVE-2024-0002', '2026-08-01T00:00:00.000Z', '2026-08-02T00:00:00.000Z', 'Analyzed', 'CRITICAL', 9.1, '3.1', 'nvd', NULL)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]CVSS{"CVE-2024-0000": {Score: 8.7, Version: "4.0", Source: "cna"}, "CVE-2024-0002": nvd75,
		"CVE-2026-50001": {Score: 6.1, Version: "3.1", Source: "cna", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}, "CVE-2026-50002": {Score: 5.3}}
	if got := read(); !maps.Equal(got, want) {
		t.Fatalf("with nvd-recent: %+v", got)
	}

	// a box from before migration 0015 (no score stored): the next pull is a full one, which fills the table
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), `DELETE FROM feeds_cvss`); return err }); err != nil {
		t.Fatal(err)
	}
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("lastModStartDate") != "" {
			t.Errorf("an update while no score is stored: %s", r.URL.RawQuery)
		}
		_, _ = fmt.Fprint(w, `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},"configurations":[]}},
		 {"cve":{"id":"CVE-2024-0002","metrics":{"cvssMetricV2":[{"type":"Primary","baseSeverity":"HIGH","cvssData":{"version":"2.0","baseScore":10.0,"vectorString":"AV:N/AC:L/Au:N/C:C/I:C/A:C"}}]},"configurations":[]}}]}`)
	})
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.svc.st.cvssCount(t.Context()); n != 2 {
		t.Fatalf("scores after the full pull: %d", n)
	}
	if got := read()["CVE-2024-0001"]; got != (CVSS{Score: 9.8, Version: "3.1", Source: "nvd"}) {
		t.Fatalf("CVE-2024-0001 = %+v", got)
	}
	if got := read()["CVE-2024-0002"]; got != (CVSS{Score: 10, Version: "2.0", Source: "nvd", Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"}) {
		t.Fatalf("CVE-2024-0002 (CVSS 2.0 only) = %+v", got)
	}
}

// INV-28: nvd-recent stores the version and source of the score it keeps, so a finding of a CVE not on the exploited lists says them too.
func TestStoreRecentPage_KeepsCVSSVersionAndSource(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	now := e.clock()
	pub := now.AddDate(0, -1, 0).UTC().Format("2006-01-02T15:04:05.000")
	d, err := ParseNVDRecent([]byte(`{"totalResults":2,"vulnerabilities":[
{"cve":{"id":"CVE-2026-0011","published":"` + pub + `","lastModified":"` + pub + `","vulnStatus":"Analyzed",
 "metrics":{"cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":9.3,"baseSeverity":"CRITICAL","vectorString":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]}}},
{"cve":{"id":"CVE-2026-0012","published":"` + pub + `","lastModified":"` + pub + `","vulnStatus":"Awaiting Analysis"}}]}`))
	if err != nil || len(d.Records) != 2 {
		t.Fatalf("parse: %+v %v", d, err)
	}
	write(t, e.db, func(tx *sql.Tx) error { return storeRecentPage(t.Context(), tx, d.Records, now.AddDate(0, 0, -365)) })
	got, err := e.svc.st.CVSSOf(t.Context(), []string{"CVE-2026-0011", "CVE-2026-0012"})
	if err != nil || !maps.Equal(got, map[string]CVSS{"CVE-2026-0011": {Score: 9.3, Version: "4.0", Source: "cna", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}) {
		t.Fatalf("%+v %v", got, err)
	}
}
