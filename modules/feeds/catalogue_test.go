package feeds

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// sampleDay is the day the frozen NVD samples were read (testdata/nvd-sample-*.json.gz: the CVEs NVD marks as exploited, metrics
// only, and 600 CVEs published 1–20 October 2026 with their configurations; public NVD data).
var sampleDay = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func samplePage(t testing.TB, name string) NVDPage {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(fixture(t, name)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseNVD(b)
	if err != nil || d.Rejected != 0 {
		t.Fatalf("%s: %+v %v", name, d.Stats, err)
	}
	return d
}

// Count test, one catalogue: the exploited-list selector (nvd-kev) and the window pull (nvd-recent) used to write two table families,
// and a CVE published inside the window and on the CISA list was stored in both, with two CVSS rules, two date formats and two EPSS
// stores (248 CVEs on a test box on 2026-11-20, and 248 of the frozen sample). Now both pulls write one catalogue: no CVE is held twice,
// and each keeps one set of NVD ranges whichever pull wrote it last.
func TestCount_OneCatalogueFamily(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	kevPage, recentPage := samplePage(t, "nvd-sample-kev.json.gz"), samplePage(t, "nvd-sample-recent.json.gz")
	vs := make([]Vuln, len(kevPage.Records))
	for i, r := range kevPage.Records {
		vs[i] = vuln(r.CVE, "Acme", "Box", "2026-01-01")
	}
	applyV(t, db, sampleDay, "cisa-kev", vs, false)
	// the old model's second family: the KEV CVEs published inside the window
	before := 0
	for _, r := range kevPage.Records {
		if !r.Published.Before(sampleDay.AddDate(0, 0, -windowDays)) {
			before++
		}
	}
	// both pulls, in both orders (the recent records carry configurations; a CVE of both keeps the last pull's ranges once)
	both := slices.Concat(recentPage.Records, kevPage.Records, recentPage.Records)
	write(t, db, func(tx *sql.Tx) error { return storeRecords(t.Context(), tx, both, sampleDay) })
	after := count(t, db, `SELECT count(*) FROM (SELECT cve FROM feeds_cve GROUP BY cve HAVING count(*) > 1)`)
	dupRanges := count(t, db, `SELECT count(*) FROM (SELECT cve, cpe, start_incl, start_excl, end_incl, end_excl FROM feeds_cve_range
GROUP BY cve, origin, cpe, start_incl, start_excl, end_incl, end_excl HAVING count(*) > 1)`)
	t.Logf("CVEs held in two table families: before %d (the old model on this sample), after %d; repeated range rows %d", before, after, dupRanges)
	if before != 248 || after != 0 {
		t.Fatalf("before %d (want 248), after %d (want 0)", before, after)
	}
	held := count(t, db, `SELECT count(*) FROM feeds_cve`)
	if want := len(kevPage.Records) + len(recentPage.Records); held > want || held < len(kevPage.Records) {
		t.Fatalf("catalogue holds %d CVEs for %d records", held, want)
	}
	for _, r := range recentPage.Records {
		if n := count(t, db, `SELECT count(*) FROM feeds_cve_range WHERE cve = ? AND origin = 'nvd'`, r.CVE); n != len(r.Affected) {
			t.Fatalf("%s: %d range rows, want %d", r.CVE, n, len(r.Affected))
		}
	}
}

// One CVSS pick: edge cases of the single choosing rule PickCVSS as findings read it (CVSSOf): CVSS 2.0 when nothing newer exists, a
// 3.1 score without a vector is no score, and CISA's ADP score comes after the CNA's.
func TestCVSSPick_EdgeCases(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setNow(sampleDay)
	edge := `{"totalResults":3,"vulnerabilities":[
{"cve":{"id":"CVE-2026-90001","published":"2026-10-02T00:00:00.000","lastModified":"2026-10-03T00:00:00.000","vulnStatus":"Analyzed",
 "metrics":{"cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","baseSeverity":"HIGH","cvssData":{"baseScore":7.5,"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]},
 "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}},
{"cve":{"id":"CVE-2026-90002","published":"2026-10-02T00:00:00.000","lastModified":"2026-10-03T00:00:00.000","vulnStatus":"Analyzed",
 "metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":""}}],
            "cvssMetricV30":[{"source":"psirt@example.com","type":"Secondary","cvssData":{"baseScore":6.1,"baseSeverity":"MEDIUM","vectorString":"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}}]},
 "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}},
{"cve":{"id":"CVE-2026-90003","published":"2026-10-02T00:00:00.000","lastModified":"2026-10-03T00:00:00.000","vulnStatus":"Analyzed",
 "metrics":{"cvssMetricV31":[{"source":"134c704f-9b21-4f2e-91b3-4a467353bcc0","type":"Secondary","cvssData":{"baseScore":8.8,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}},
                            {"source":"psirt@example.com","type":"Secondary","cvssData":{"baseScore":7.1,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"}}]},
 "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}]}`
	edgePage, err := ParseNVD([]byte(edge))
	if err != nil || len(edgePage.Records) != 3 {
		t.Fatalf("%+v %v", edgePage, err)
	}
	write(t, e.db, func(tx *sql.Tx) error {
		_, err := writeNVDRecords(t.Context(), tx, edgePage.Records, retention{all: true}, sampleDay)
		return err
	})
	cves := make([]string, len(edgePage.Records))
	for i, r := range edgePage.Records {
		cves[i] = r.CVE
	}
	shown, err := e.svc.st.CVSSOf(t.Context(), cves)
	if err != nil {
		t.Fatal(err)
	}
	// the edge cases: CVSS 2.0 when nothing newer; a 3.1 score without a vector is no score; CISA's ADP after the CNA
	want := map[string]CVSS{
		"CVE-2026-90001": {Score: 7.5, Version: "2.0", Source: MetricNVD, Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		"CVE-2026-90002": {Score: 6.1, Version: "3.0", Source: MetricCNA, Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
		"CVE-2026-90003": {Score: 7.1, Version: "3.1", Source: MetricCNA, Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"},
	}
	for cve, w := range want {
		if shown[cve] != w {
			t.Errorf("%s = %+v, want %+v", cve, shown[cve], w)
		}
	}
}

// INV-28: nvd-kev keeps each KEV CVE's scores from the answer it already reads (no new request); an update replaces the scores of the
// CVEs NVD answered for (a score NVD took away goes); a CVE not answered keeps its own.
func TestContract_INV28_CVSSFromNVD(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("nvd-kev")
	e.mirror("nvd-kev", o.url("/nvd"))
	nvdOrigin(o, 3)
	seedKEV(t, e.db, 3)
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	cves := []string{"CVE-2024-0000", "CVE-2024-0001", "CVE-2024-0002", "CVE-2099-0001"}
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
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("lastModStartDate") == "" {
			t.Errorf("want an update: %s", r.URL.RawQuery)
		}
		_, _ = fmt.Fprint(w, `{"totalResults":2,"vulnerabilities":[
	 {"cve":{"id":"CVE-2024-0000","published":"2024-01-15T10:00:00.000","lastModified":"2026-11-05T10:00:00.000","vulnStatus":"Modified",
	  "metrics":{"cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":8.7,"baseSeverity":"HIGH","vectorString":"`+v4+`"}}]},"configurations":[]}},
	 {"cve":{"id":"CVE-2024-0001","published":"2024-01-15T10:00:00.000","lastModified":"2026-11-05T10:00:00.000","vulnStatus":"Modified","metrics":{},"configurations":[]}}]}`)
	})
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if got := read(); !maps.Equal(got, map[string]CVSS{"CVE-2024-0000": {Score: 8.7, Version: "4.0", Source: "cna", Vector: v4}, "CVE-2024-0002": nvd75}) {
		t.Fatalf("after the update: %+v", got)
	}
}

// The retention rule: a CVE stays while it was published inside the window, or an exploited list names it, or a qualifying signal
// names it (any age), or an open finding pins it; an NVD pull stores only such CVEs, and a CVE NVD rejects goes unless one holds it.
func TestRetention_KeepsWindowListsSignalsAndPins(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	now := epoch0
	old, recent := now.AddDate(-3, 0, 0), now.AddDate(0, -1, 0)
	rec := func(cve string, pub time.Time, status string) NVDRecord {
		return NVDRecord{CVE: cve, Published: pub, LastModified: now, Status: status, Affected: []AffectedRow{{CPE: "cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*", EndExcl: "2.0"}}}
	}
	applyV(t, db, now, "cisa-kev", []Vuln{vuln("CVE-2023-0001", "Acme", "Box", "2023-03-01")}, false)
	write(t, db, func(tx *sql.Tx) error {
		if err := putSignal(t.Context(), tx, "CVE-2023-0002", SignalPublicExploit, nucleiFeedID, store0, store0, true, ""); err != nil {
			return err
		}
		return putSignal(t.Context(), tx, "CVE-2023-0003", SignalPublicExploit, "poc-index", store0, store0, false, "") // does not qualify
	})
	recs := []NVDRecord{rec("CVE-2023-0001", old, "Analyzed"), rec("CVE-2023-0002", old, "Analyzed"), rec("CVE-2023-0003", old, "Analyzed"),
		rec("CVE-2023-0004", old, "Analyzed"), rec("CVE-2026-0005", recent, "Analyzed"), rec("CVE-2026-0006", recent, "Rejected")}
	write(t, db, func(tx *sql.Tx) error {
		ret, err := retentionOf(t.Context(), tx, now, []string{"CVE-2023-0004"})
		if err != nil {
			return err
		}
		_, err = writeNVDRecords(t.Context(), tx, recs, ret, now)
		return err
	})
	held := func() []string {
		got, err := stringSet(t.Context(), db.Reader(), `SELECT cve FROM feeds_cve`)
		if err != nil {
			t.Fatal(err)
		}
		return slices.Sorted(maps.Keys(got))
	}
	if got := held(); !slices.Equal(got, []string{"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0004", "CVE-2026-0005"}) {
		t.Fatalf("stored: %v", got)
	}
	// a year later, without the pin: the window CVE ages out, the listed and signalled ones stay
	write(t, db, func(tx *sql.Tx) error { return pruneCatalogue(t.Context(), tx, now.AddDate(1, 0, 1), nil) })
	if got := held(); !slices.Equal(got, []string{"CVE-2023-0001", "CVE-2023-0002"}) {
		t.Fatalf("after the window moved: %v", got)
	}
	// NVD rejects the listed CVE: it keeps its row (the list holds it) with the status and no ranges
	write(t, db, func(tx *sql.Tx) error {
		err := storeRecords(t.Context(), tx, []NVDRecord{rec("CVE-2023-0001", old, "Rejected")}, now)
		return err
	})
	if n := count(t, db, `SELECT count(*) FROM feeds_cve_range WHERE cve = 'CVE-2023-0001'`); n != 0 || count(t, db, `SELECT count(*) FROM feeds_cve WHERE cve = 'CVE-2023-0001' AND nvd_status = 'Rejected'`) != 1 {
		t.Fatalf("rejected: %d ranges", n)
	}
}

// store0 is a stored time for signals of the tests.
var store0 = "2026-11-01T00:00:00.000Z"

// Range precedence and the new reads: NVD's rows when NVD gives any, else the CVE record's; Ranges finds the CVEs of a product by
// CPE vendor and product; Catalogue and Signals read one CVE's facts.
func TestCatalogue_RangesSignalsAndEntries(t *testing.T) {
	t.Parallel()
	s, db := newStore(t)
	now := epoch0
	applyV(t, db, now, "cisa-kev", []Vuln{vuln("CVE-2026-0101", "Acme", "Box", "2026-11-01"), vuln("CVE-2026-0102", "Acme", "Box", "2026-11-02")}, false)
	write(t, db, func(tx *sql.Tx) error {
		err := storeRecords(t.Context(), tx, []NVDRecord{
			{CVE: "CVE-2026-0101", Published: now.AddDate(0, -2, 0), LastModified: now, Status: "Analyzed", Description: "A flaw in Acme Box.",
				Metrics:  []Metric{{Source: MetricCNA, Version: "3.1", Score: 8.1, Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
				Affected: []AffectedRow{{CPE: "cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*", EndExcl: "2.0"}, {CPE: "cpe:2.3:a:acme:other:*:*:*:*:*:*:*:*", EndExcl: "5"}}},
			{CVE: "CVE-2026-0102", Published: now.AddDate(0, -1, 0), LastModified: now, Status: "Received", Affected: []AffectedRow{}},
		}, now)
		if err != nil {
			return err
		}
		// the CVE record's rows of both: NVD's win for the first, the second has only these
		recs := []CVERecord{
			{CVE: "CVE-2026-0101", State: RecordPublished, Ranges: []Range{{CVE: "CVE-2026-0101", Origin: OriginCNA, Vendor: "acme", Product: "box", EndExcl: "1.9", DefaultStatus: DefaultUnaffected}}},
			{CVE: "CVE-2026-0102", State: RecordPublished, Ranges: []Range{{CVE: "CVE-2026-0102", Origin: OriginCNA, Vendor: "acme", Product: "box", StartIncl: "3.0", EndExcl: "3.4", DefaultStatus: DefaultUnknown}}},
		}
		k, err := recordKeepOf(t.Context(), tx, now, nil)
		if err != nil {
			return err
		}
		_, err = writeRecords(t.Context(), tx, recs, k, now)
		return err
	})
	// NVD has ranges for 0101: the CVE record's are kept beside them and never read while NVD's are there; 0102's come from the CNA
	// (a partial list: no defaultStatus)
	if n := count(t, db, `SELECT count(*) FROM feeds_cve_range WHERE cve = 'CVE-2026-0101' AND origin = 'cna'`); n != 1 {
		t.Fatalf("CNA rows of 0101: %d", n)
	}
	got, err := s.Ranges(t.Context(), []ProductKey{{Vendor: "Acme", Product: "Box"}})
	if err != nil || len(got) != 2 || got[0].CVE != "CVE-2026-0101" || got[0].Origin != OriginNVD || got[0].EndExcl != "2.0" ||
		got[1].CVE != "CVE-2026-0102" || got[1].Origin != OriginCNA || got[1].DefaultStatus != DefaultUnknown || got[1].StartIncl != "3.0" {
		t.Fatalf("Ranges = %+v %v", got, err)
	}
	cat, err := s.Catalogue(t.Context(), []string{"CVE-2026-0101", "CVE-2026-0102", "CVE-2099-0001"})
	if err != nil || len(cat) != 2 {
		t.Fatalf("Catalogue = %+v %v", cat, err)
	}
	if a := cat["CVE-2026-0101"]; a.NVDStatus != "Analyzed" || a.Description != "A flaw in Acme Box." || a.CVSS == nil || a.CVSS.Score != 8.1 ||
		a.Severity != "HIGH" || a.RangesFrom != OriginNVD || a.NVDAt == nil || a.RecordAt == nil {
		t.Fatalf("0101 = %+v", a)
	}
	if b := cat["CVE-2026-0102"]; b.NVDStatus != "Received" || b.CVSS != nil || b.RangesFrom != OriginCNA || b.RangesComplete {
		t.Fatalf("0102 = %+v", b)
	}
	sig, err := s.Signals(t.Context(), []string{"CVE-2026-0101", "CVE-2099-0001"})
	if err != nil || len(sig) != 1 || len(sig["CVE-2026-0101"]) != 1 {
		t.Fatalf("Signals = %+v %v", sig, err)
	}
	if g := sig["CVE-2026-0101"][0]; g.Kind != SignalExploited || g.Source != kevFeedID || !g.Qualifies || g.FirstSeen != time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("CISA signal = %+v", g)
	}
	// KevAffected and RangesFromCVEOrg, as findings reads them: NVD's rows of 0101; the CNA's of 0102, named as a partial list
	aff, err := s.KevAffected(t.Context())
	if err != nil || len(aff["CVE-2026-0101"]) != 2 || len(aff["CVE-2026-0102"]) != 1 {
		t.Fatalf("KevAffected = %+v %v", aff, err)
	}
	if src, err := s.RangesFromCVEOrg(t.Context()); err != nil || !maps.Equal(src, map[string]string{"CVE-2026-0102": rangesCVEOrgPartial}) {
		t.Fatalf("RangesFromCVEOrg = %v %v", src, err)
	}
}

// Golden test of the decoders on the catalogue: the CISA list fixture, nuclei's index, a real NVD answer and a CVE record, decoded and
// stored as the pulls store them, then every row of feeds_cve, feeds_cve_metric, feeds_cve_range, feeds_kev and feeds_signal written
// out. go test ./modules/feeds -run Golden_Catalogue -update rewrites testdata/golden/catalogue.txt.
func TestGolden_CatalogueTables(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	cat, err := ParseKEV(fixture(t, "kev.json"))
	if err != nil {
		t.Fatal(err)
	}
	nvd, err := ParseNVD(fixture(t, "nvd-kev-page.json"))
	if err != nil {
		t.Fatal(err)
	}
	nuclei, err := ParseNucleiCVEs(fixture(t, "nuclei-cves.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	pan, err := ParseCVERecord(fixture(t, "cveorg/CVE-2024-3400.json"), "CVE-2024-3400")
	if err != nil {
		t.Fatal(err)
	}
	vs := append(cat.Vulns, vuln("CVE-2016-4655", "Apple", "iOS", "2021-11-03"), vuln("CVE-2021-3493", "Linux", "Kernel", "2022-10-20"),
		vuln("CVE-2024-21762", "Fortinet", "FortiOS", "2024-02-09"), vuln("CVE-2024-3400", "Palo Alto Networks", "PAN-OS", "2024-04-12"))
	applyV(t, db, epoch0, "cisa-kev", vs, false)
	write(t, db, func(tx *sql.Tx) error {
		if _, err := applyTemplates(t.Context(), tx, epoch0, nuclei.Templates); err != nil {
			return err
		}
		if err := storeRecords(t.Context(), tx, nvd.Records, epoch0); err != nil {
			return err
		}
		k, err := recordKeepOf(t.Context(), tx, epoch0, nil)
		if err != nil {
			return err
		}
		_, err = writeRecords(t.Context(), tx, []CVERecord{pan}, k, epoch0)
		return err
	})
	var b strings.Builder
	for _, q := range []string{
		`SELECT 'cve', cve, coalesce(published, '-'), coalesce(modified, '-'), coalesce(nvd_status, '-'), coalesce(nvd_at, '-'), coalesce(record_at, '-'), substr(description, 1, 60) FROM feeds_cve ORDER BY cve`,
		`SELECT 'metric', cve, source, version, score, vector FROM feeds_cve_metric ORDER BY cve, version DESC, source`,
		`SELECT 'range', cve, origin, part, vendor, product, cpe, start_incl, start_excl, end_incl, end_excl, default_status, coalesce(platforms, '-') FROM feeds_cve_range ORDER BY cve, id`,
		`SELECT 'kev', cve, list, source_id, vendor, product, date_added, coalesce(due_date, '-'), ransomware, links FROM feeds_kev ORDER BY cve, list`,
		`SELECT 'signal', cve, kind, source, first_seen, qualifies, url FROM feeds_signal ORDER BY cve, kind, source`,
	} {
		rows, err := db.Reader().QueryContext(t.Context(), q)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			parts := make([]string, len(vals))
			for i, v := range vals {
				parts[i] = fmt.Sprint(v)
			}
			b.WriteString(strings.Join(parts, " | ") + "\n")
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	path := "testdata/golden/catalogue.txt"
	if *update {
		if err := writeFile(path, b.String()); err != nil {
			t.Fatal(err)
		}
	}
	if want := testFile(t, "golden/catalogue.txt"); want != b.String() {
		t.Errorf("catalogue differs from %s (run with -update and review the diff):\n%s", path, b.String())
	}
}

// A record older than the stored one is not written: a pull that collected its pages over several checks never puts back what a later
// pull replaced (the ranges NVD added stay).
func TestCatalogue_OlderRecordNeverReplacesANewerOne(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	applyV(t, db, epoch0, kevFeedID, []Vuln{vuln("CVE-2026-0201", "Acme", "Box", "2026-11-01")}, false)
	rec := func(mod time.Time, rows ...AffectedRow) NVDRecord {
		return NVDRecord{CVE: "CVE-2026-0201", Published: epoch0.AddDate(0, -1, 0), LastModified: mod, Status: "Analyzed", Affected: append([]AffectedRow{}, rows...)}
	}
	newer := rec(epoch0.Add(-time.Hour), AffectedRow{CPE: "cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*", EndExcl: "2.0"})
	older := rec(epoch0.Add(-48 * time.Hour))
	write(t, db, func(tx *sql.Tx) error { return storeRecords(t.Context(), tx, []NVDRecord{newer}, epoch0) })
	var w nvdWrite
	write(t, db, func(tx *sql.Tx) (err error) {
		ret, err := retentionOf(t.Context(), tx, epoch0, nil)
		if err != nil {
			return err
		}
		w, err = writeNVDRecords(t.Context(), tx, []NVDRecord{older}, ret, epoch0)
		return err
	})
	if w.Stored != 0 || len(w.KEVChanged) != 0 || count(t, db, `SELECT count(*) FROM feeds_cve_range WHERE cve = 'CVE-2026-0201'`) != 1 {
		t.Fatalf("the older record replaced the newer one: %+v", w)
	}
}
