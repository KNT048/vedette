package feeds

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
)

// A real NVD CVE API 2.0 answer (three KEV records, fetched 2026-11-13): only vulnerable entries are kept, with
// their ranges, in NVD's order.
func TestParseNVD_RealAnswer(t *testing.T) {
	t.Parallel()
	d, err := ParseNVD([]byte(testFile(t, "nvd-kev-page.json")))
	if err != nil {
		t.Fatal(err)
	}
	if d.Total != 3 || d.Returned != 3 || d.Accepted != 3 || d.Rejected != 0 {
		t.Fatalf("page = %+v", d)
	}
	ios := d.Affected["CVE-2016-4655"]
	if len(ios) != 2 || ios[0] != (AffectedRow{CPE: "cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*", EndExcl: "9.3.5"}) {
		t.Fatalf("CVE-2016-4655 = %+v", ios)
	}
	fgt := d.Affected["CVE-2024-21762"]
	if !slices.Contains(fgt, AffectedRow{CPE: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", StartIncl: "7.2.0", EndExcl: "7.2.7"}) {
		t.Fatalf("CVE-2024-21762 = %+v", fgt)
	}
	// INV-28: NVD's own 3.1 score, even where the CNA's Secondary entry comes first with another score (Ubuntu's 8.8 for CVE-2021-3493)
	want := map[string]CVSS{
		"CVE-2016-4655":  {Score: 5.5, Version: "3.1", Source: "nvd", Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"},
		"CVE-2021-3493":  {Score: 7.8, Version: "3.1", Source: "nvd", Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
		"CVE-2024-21762": {Score: 9.8, Version: "3.1", Source: "nvd", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	if !maps.Equal(d.CVSS, want) {
		t.Fatalf("cvss = %+v", d.CVSS)
	}
}

// INV-28: the newest CVSS version present wins, NVD's own ("Primary") before another scorer's ("Secondary") within it; CVSS 2.0 only
// when there is nothing newer (its severity is beside cvssData). An entry counts only with a known severity, a score in 0..10 and a
// valid vector of its version; otherwise the next scorer or version is tried (review r1 L3, M1). The score is rounded to one decimal
// (L4). No usable entry is no score (absent, never 0).
func TestParseNVD_CVSS(t *testing.T) {
	t.Parallel()
	rec := func(id, metrics string) string {
		return fmt.Sprintf(`{"cve":{"id":%q,"metrics":{%s},"configurations":[]}}`, id, metrics)
	}
	e := func(typ string, score float64, sev, vec string) string {
		return fmt.Sprintf(`{"type":%q,"cvssData":{"baseScore":%v,"baseSeverity":%q,"vectorString":%q}}`, typ, score, sev, vec)
	}
	v4 := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Amber"
	v31 := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	v30 := "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
	recs := []string{
		rec("CVE-2026-0001", `"cvssMetricV40":[`+e("Secondary", 8.5, "HIGH", v4)+`],"cvssMetricV31":[`+e("Primary", 9.8, "CRITICAL", v31)+`]`),
		rec("CVE-2026-0002", `"cvssMetricV30":[`+e("Secondary", 6.1, "MEDIUM", v30)+`,`+e("Primary", 5.0, "MEDIUM", v30)+`]`),
		rec("CVE-2026-0003", `"cvssMetricV30":[`+e("Primary", 0, "NONE", "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N")+`]`),
		rec("CVE-2026-0004", `"cvssMetricV2":[{"type":"Primary","cvssData":{"baseScore":7.5,"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]`),
		rec("CVE-2014-0005", `"cvssMetricV2":[{"type":"Secondary","baseSeverity":"MEDIUM","cvssData":{"version":"2.0","baseScore":5.0,"vectorString":"AV:N/AC:L/Au:N/C:P/I:N/A:N"}},`+
			`{"type":"Primary","baseSeverity":"HIGH","cvssData":{"version":"2.0","baseScore":9.3,"vectorString":"AV:N/AC:M/Au:N/C:C/I:C/A:C"}}]`),
		// the v2 entry is valid but a 3.0 one is newer
		rec("CVE-2014-0006", `"cvssMetricV2":[{"type":"Primary","baseSeverity":"HIGH","cvssData":{"baseScore":7.5,"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}],"cvssMetricV30":[`+e("Secondary", 9.8, "CRITICAL", v30)+`]`),
		rec("CVE-2026-0005", `"cvssMetricV31":[`+e("Primary", 11, "CRITICAL", v31)+`,`+e("Secondary", 7.0, "BOGUS", v31)+`]`),
		rec("CVE-2026-0006", ``),
		// L3: the Primary 3.1 entry has no score, the Secondary one a wrong-version vector: the v2 score is used
		rec("CVE-2026-0007", `"cvssMetricV31":[{"type":"Primary","cvssData":{"baseSeverity":"HIGH","vectorString":"`+v31+`"}},`+e("Secondary", 8.1, "HIGH", v30)+`],`+
			`"cvssMetricV2":[{"type":"Primary","baseSeverity":"HIGH","cvssData":{"baseScore":7.5,"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]`),
		// M1: a score without a valid vector is not a score; L3: the Secondary one of the same version is
		rec("CVE-2026-0008", `"cvssMetricV31":[`+e("Primary", 9.1, "CRITICAL", "")+`,`+e("Secondary", 7.2, "HIGH", v31)+`]`),
		rec("CVE-2026-0009", `"cvssMetricV31":[`+e("Primary", 9.1, "CRITICAL", "AV:N/AC:L")+`]`),
		// L4: rounded to one decimal, so "7.0" is never "Medium"
		rec("CVE-2026-0010", `"cvssMetricV31":[`+e("Primary", 6.95, "MEDIUM", v31)+`]`),
	}
	d, err := ParseNVD([]byte(fmt.Sprintf(`{"totalResults":%d,"vulnerabilities":[%s]}`, len(recs), strings.Join(recs, ","))))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]CVSS{
		"CVE-2026-0001": {Score: 8.5, Version: "4.0", Source: "cna", Vector: v4},
		"CVE-2026-0002": {Score: 5.0, Version: "3.0", Source: "nvd", Vector: v30},
		"CVE-2026-0003": {Score: 0, Version: "3.0", Source: "nvd", Vector: "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"},
		"CVE-2014-0005": {Score: 9.3, Version: "2.0", Source: "nvd", Vector: "AV:N/AC:M/Au:N/C:C/I:C/A:C"},
		"CVE-2014-0006": {Score: 9.8, Version: "3.0", Source: "cna", Vector: v30},
		"CVE-2026-0007": {Score: 7.5, Version: "2.0", Source: "nvd", Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		"CVE-2026-0008": {Score: 7.2, Version: "3.1", Source: "cna", Vector: v31},
		"CVE-2026-0010": {Score: 7.0, Version: "3.1", Source: "nvd", Vector: v31},
	}
	if d.Accepted != len(recs) || !maps.Equal(d.CVSS, want) {
		t.Fatalf("accepted %d, cvss %+v", d.Accepted, d.CVSS)
	}
}

// Review r1 H1: one record with malformed `metrics` (a string score, 1e999, a number for a vector, an array, a number for a type)
// next to a good one: the page parses, both records and their affected versions are accepted, only the bad one has no score. L2: a
// record rejected for its affected entries keeps its score.
func TestParseNVD_MalformedMetricsOnlyCostTheScore(t *testing.T) {
	t.Parallel()
	good := `{"cve":{"id":"CVE-2024-0001","published":"2024-01-15T10:00:00.000","metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},` +
		`"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}`
	for name, metrics := range map[string]string{
		"string score":  `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":"9.8","baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}`,
		"1e999":         `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":1e999,"baseSeverity":"CRITICAL"}}]}`,
		"number vector": `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":5}}]}`,
		"array":         `[]`,
		"number type":   `{"cvssMetricV2":[{"type":1,"baseSeverity":"HIGH","cvssData":{"baseScore":7.5}}]}`,
	} {
		bad := `{"cve":{"id":"CVE-2024-0002","published":"2024-02-01T10:00:00.000","metrics":` + metrics +
			`,"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:tool:*:*:*:*:*:*:*:*","versionEndExcluding":"3.0"}]}]}]}}`
		d, err := ParseNVD([]byte(`{"totalResults":2,"vulnerabilities":[` + good + `,` + bad + `]}`))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.Accepted != 2 || len(d.Affected["CVE-2024-0002"]) != 1 || d.Published["CVE-2024-0002"] != "2024-02-01" {
			t.Fatalf("%s: accepted %d, affected %+v, published %+v", name, d.Accepted, d.Affected, d.Published)
		}
		if _, ok := d.CVSS["CVE-2024-0002"]; ok || d.CVSS["CVE-2024-0001"].Score != 9.8 || !d.Seen["CVE-2024-0002"] {
			t.Fatalf("%s: cvss %+v seen %+v", name, d.CVSS, d.Seen)
		}
		r, err := ParseNVDRecent([]byte(`{"totalResults":2,"vulnerabilities":[` + strings.ReplaceAll(good, `"published"`, `"lastModified":"2024-01-16T10:00:00.000","vulnStatus":"Analyzed","published"`) + `,` +
			strings.ReplaceAll(bad, `"published"`, `"lastModified":"2024-02-02T10:00:00.000","vulnStatus":"Analyzed","published"`) + `]}`))
		if err != nil || r.Accepted != 2 || len(r.Records) != 2 || r.Records[0].CVSS == nil || r.Records[1].CVSS != nil || len(r.Records[1].Affected) != 1 {
			t.Fatalf("%s: nvd-recent %+v %v", name, r, err)
		}
	}
	// L2: an over-long version string rejects the record (never half a configuration), but its score stays
	d, err := ParseNVD([]byte(`{"totalResults":1,"vulnerabilities":[` + strings.Replace(good, `"versionEndExcluding":"2.0"`, `"versionEndExcluding":"`+strings.Repeat("9", 200)+`"`, 1) + `]}`))
	if err != nil || d.Rejected != 1 || len(d.Affected) != 0 || d.CVSS["CVE-2024-0001"].Score != 9.8 {
		t.Fatalf("rejected record: %+v %v", d, err)
	}
}

func TestNVDPageURL(t *testing.T) {
	t.Parallel()
	u, err := NVDPageURL("https://services.nvd.nist.gov/rest/json/cves/2.0", 200, time.Time{}, time.Time{})
	if err != nil || u != "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&resultsPerPage=100&startIndex=200" {
		t.Fatalf("%q %v", u, err)
	}
	from, to := time.Date(2026, 11, 12, 7, 0, 0, 0, time.UTC), time.Date(2026, 11, 13, 7, 0, 0, 0, time.UTC)
	u, _ = NVDPageURL("https://services.nvd.nist.gov/rest/json/cves/2.0", 0, from, to)
	if !strings.HasSuffix(u, "&lastModStartDate=2026-11-12T07:00:00.000Z&lastModEndDate=2026-11-13T07:00:00.000Z") {
		t.Fatalf("%q", u)
	}
	if _, err := NVDPageURL("https://services.nvd.nist.gov/x?y=1", 0, time.Time{}, time.Time{}); err == nil {
		t.Fatal("query string accepted")
	}
}

// nvdOrigin answers ?hasKev pages of n records CVE-2024-0000… (fixed before 2.0), each with an NVD CVSS 3.1 score of 7.5; with
// lastModStartDate only the first two.
func nvdOrigin(o *origin, n int) {
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		start, _ := strconv.Atoi(q.Get("startIndex"))
		total := n
		if q.Get("lastModStartDate") != "" {
			total = 2
		}
		var recs []string
		for i := start; i < min(start+NVDPageSize, total); i++ {
			recs = append(recs, fmt.Sprintf(`{"cve":{"id":"CVE-2024-%04d","published":"2024-01-15T10:00:00.000","metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}]},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}`, i))
		}
		_, _ = fmt.Fprintf(w, `{"totalResults":%d,"vulnerabilities":[%s]}`, total, strings.Join(recs, ","))
	})
}

// The first pull asks for every page and fills the table, says so once (First), and a later pull asks only
// for what NVD changed since the last good pull.
func TestContract_NVDRangesPull(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("nvd-kev")
	e.mirror("nvd-kev", o.url("/nvd"))
	nvdOrigin(o, 250)
	var got []RangesUpdatedEvent
	e.svc.Events = publishFunc(func(ev events.Event) {
		if r, ok := ev.Data.(RangesUpdatedEvent); ok {
			got = append(got, r)
		}
	})
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if n := o.count("/nvd"); n != 3 {
		t.Fatalf("%d requests for 250 CVEs, want 3", n)
	}
	if f := e.feed("nvd-kev"); f.Status != "ok" || f.Records == nil || *f.Records != 250 {
		t.Fatalf("feed = %+v", f)
	}
	if len(got) != 1 || len(got[0].CVEs) != 250 || !got[0].First {
		t.Fatalf("events = %d %+v", len(got), got)
	}
	// the next day: an incremental pull with the window; one changed entry, one unchanged: one event for one CVE
	nvdOrigin(o, 250)
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("lastModStartDate") == "" {
			t.Errorf("full pull the next day: %s", r.URL.RawQuery)
		}
		_, _ = fmt.Fprint(w, `{"totalResults":2,"vulnerabilities":[
		 {"cve":{"id":"CVE-2024-0000","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"3.0"}]}]}]}},
		 {"cve":{"id":"CVE-2024-0001","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}]}`)
	})
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !slices.Equal(got[1].CVEs, []string{"CVE-2024-0000"}) || got[1].First {
		t.Fatalf("events = %+v", got)
	}
	if f := e.feed("nvd-kev"); *f.Records != 250 {
		t.Fatalf("records after an incremental pull = %d, want the table's 250", *f.Records)
	}
	rows, err := readAffected(t.Context(), e.db.Reader(), `WHERE cve = ?`, "CVE-2024-0000")
	if err != nil || len(rows["CVE-2024-0000"]) != 1 || rows["CVE-2024-0000"][0].EndExcl != "3.0" {
		t.Fatalf("rows = %+v %v", rows, err)
	}
	// a failing page fails the pull and keeps every entry
	o.serve("/nvd", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	e.setNow(e.clock().Add(25 * time.Hour))
	_ = e.svc.Fetch(t.Context(), "nvd-kev")
	if f := e.feed("nvd-kev"); f.Status != "error" {
		t.Fatalf("feed = %+v", f)
	}
	if n, _ := e.svc.st.affectedCount(t.Context()); n != 250 {
		t.Fatalf("entries after a failed pull: %d", n)
	}
}

type publishFunc func(events.Event)

func (f publishFunc) Publish(_ context.Context, e events.Event) error { f(e); return nil }
