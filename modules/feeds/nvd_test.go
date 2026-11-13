package feeds

import (
	"context"
	"fmt"
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
}

// Fail closed: a hostile or damaged answer never gives a CVE half of its entries.
func TestParseNVD_Defensive(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{"not json": `nope`, "no totalResults": `{"vulnerabilities":[]}`} {
		if _, err := ParseNVD([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	d, err := ParseNVD([]byte(`{"totalResults":3,"vulnerabilities":[
	 {"cve":{"id":"CVE-2020-0001","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:x:y:*:*:*:*:*:*:*:*","versionEndExcluding":"1.0"},{"vulnerable":true,"criteria":"garbage"}]}]}]}},
	 {"cve":{"id":"bad","configurations":[]}},
	 {"cve":{"id":"CVE-2020-0002","configurations":[{"nodes":[{"negate":true,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:x:z:*:*:*:*:*:*:*:*"}]},{"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:h:x:box:-:*:*:*:*:*:*:*"},{"vulnerable":true,"criteria":"cpe:2.3:a:x:y:*:*:*:*:*:*:*:*","versionEndExcluding":"2\u0000"}]}]}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Affected) != 0 || d.Rejected != 3 {
		t.Fatalf("affected %+v, rejected %d", d.Affected, d.Rejected)
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

// nvdOrigin answers ?hasKev pages of n records CVE-2024-0000…; with lastModStartDate only the first two.
func nvdOrigin(o *origin, n int, endExcl string) {
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		start, _ := strconv.Atoi(q.Get("startIndex"))
		total := n
		if q.Get("lastModStartDate") != "" {
			total = 2
		}
		var recs []string
		for i := start; i < min(start+NVDPageSize, total); i++ {
			recs = append(recs, fmt.Sprintf(`{"cve":{"id":"CVE-2024-%04d","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":%q}]}]}]}}`, i, endExcl))
		}
		_, _ = fmt.Fprintf(w, `{"totalResults":%d,"vulnerabilities":[%s]}`, total, strings.Join(recs, ","))
	})
}

// D-500: the first pull asks for every page and fills the table, says so once (First), and a later pull asks only
// for what NVD changed since the last good pull.
func TestContract_NVDRangesPull(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("nvd-kev")
	e.mirror("nvd-kev", o.url("/nvd"))
	nvdOrigin(o, 250, "2.0")
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
	nvdOrigin(o, 250, "2.0")
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
