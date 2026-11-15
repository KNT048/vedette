package feeds

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// D-614: what tier 3 keeps of a record: dates, NVD's status, the newest CVSS version's severity (NVD's own before the
// CNA's), the vulnerable entries; a record with an unusable entry is rejected whole.
func TestParseNVDRecent(t *testing.T) {
	t.Parallel()
	body := `{"totalResults":3,"vulnerabilities":[
{"cve":{"id":"CVE-2026-0001","published":"2026-08-01T03:16:25.307","lastModified":"2026-08-12T21:00:37.147","vulnStatus":"Deferred",
 "metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}],
            "cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":8.7,"baseSeverity":"HIGH"}}]}}},
{"cve":{"id":"CVE-2026-0002","published":"2026-08-02T00:00:00.000","lastModified":"2026-08-03T00:00:00.000","vulnStatus":"Analyzed",
 "metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}},{"type":"Primary","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]},
 "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"},{"vulnerable":false,"criteria":"cpe:2.3:o:acme:os:-:*:*:*:*:*:*:*"}]}]}]}},
{"cve":{"id":"CVE-2026-0003","published":"2026-08-02T00:00:00.000","lastModified":"2026-08-03T00:00:00.000","vulnStatus":"Analyzed",
 "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"not a cpe"}]}]}]}}]}`
	d, err := ParseNVDRecent([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if d.Total != 3 || d.Returned != 3 || d.Accepted != 2 || d.Rejected != 1 || len(d.Records) != 2 {
		t.Fatalf("%+v", d)
	}
	a, b := d.Records[0], d.Records[1]
	if a.Severity != "HIGH" || *a.Score != 8.7 || a.Status != "Deferred" || len(a.Affected) != 0 || a.Published != time.Date(2026, 8, 1, 3, 16, 25, 307e6, time.UTC) {
		t.Fatalf("v4.0 first, the CNA's when NVD gives none: %+v", a)
	}
	if b.Severity != "HIGH" || *b.Score != 7.5 || len(b.Affected) != 1 || b.Affected[0].EndExcl != "2.0" {
		t.Fatalf("NVD's own score before the CNA's: %+v", b)
	}
	for name, in := range map[string]string{"html": "<html>", "no total": `{"vulnerabilities":[]}`} {
		if _, err := ParseNVDRecent([]byte(in)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// recentNVD is a fake NVD for nvd-recent: each date window (pubStartDate, or lastModStartDate for an update) has a number
// of records, CVE-<window>-<n> published an hour after the window starts; plan makes a startIndex answer busy.
type recentNVD struct {
	mu     sync.Mutex
	perWin func(from time.Time, byPub bool) int
	busy   map[string]bool // "<from>/<start>" answered 503
	asked  []string        // "<pub|mod> <from> <start>"
	extra  []string        // records added to every update answer (raw JSON)
}

func (n *recentNVD) serve(o *origin) {
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		byPub := q.Get("pubStartDate") != ""
		fromS := q.Get("pubStartDate")
		if !byPub {
			fromS = q.Get("lastModStartDate")
		}
		from, _ := time.Parse("2006-01-02T15:04:05.000Z", fromS)
		start, _ := strconv.Atoi(q.Get("startIndex"))
		key := fmt.Sprintf("%s/%d", fromS, start)
		n.mu.Lock()
		kind := "mod"
		if byPub {
			kind = "pub"
		}
		n.asked = append(n.asked, fmt.Sprintf("%s %s %d", kind, from.Format("2006-01-02"), start))
		busy := n.busy[key]
		total := n.perWin(from, byPub)
		extra := n.extra
		n.mu.Unlock()
		if busy {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var recs []string
		for i := start; i < min(start+RecentPageSize, total); i++ {
			pub := from.Add(time.Hour).Format("2006-01-02T15:04:05.000")
			recs = append(recs, fmt.Sprintf(`{"cve":{"id":"CVE-%s-%s%04d","published":%q,"lastModified":%q,"vulnStatus":"Analyzed",
"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}`, from.Format("2006"), from.Format("0102"), i, pub, pub))
		}
		if !byPub {
			recs = append(recs, extra...)
		}
		_, _ = fmt.Fprintf(w, `{"totalResults":%d,"vulnerabilities":[%s]}`, total+len(extraIf(!byPub, extra)), strings.Join(recs, ","))
	})
}

func extraIf(on bool, l []string) []string {
	if on {
		return l
	}
	return nil
}

func (n *recentNVD) requests() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.asked)
}

func recentEnv(t *testing.T) (*env, *recentNVD) {
	t.Helper()
	e, o := pullEnv(t)
	e.only(recentFeedID)
	e.mirror(recentFeedID, o.url("/nvd"))
	n := &recentNVD{busy: map[string]bool{}}
	n.serve(o)
	return e, n
}

// D-614: the first fill asks for 12 months of published CVEs in 120-day windows, page by page (nvdPause apart; 0 in the tests), stores
// them with their entries and records the counts on the feed.
func TestRecentPull_FillsTwelveMonthsInWindows(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(from time.Time, _ bool) int {
		if from.Equal(e.clock().AddDate(0, 0, -recentDays)) {
			return 1200 // two pages in the first window
		}
		return 1
	}
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	want := []string{"pub 2025-11-05 0", "pub 2025-11-05 1000", "pub 2026-03-05 0", "pub 2026-07-03 0", "pub 2026-10-31 0"}
	if got := n.requests(); !slices.Equal(got, want) {
		t.Fatalf("requests %v", got)
	}
	f := e.feed(recentFeedID)
	if f.Status != "ok" || f.Records == nil || *f.Records != 1203 || f.Error == nil || !strings.Contains(*f.Error, "1,203 CVEs published since 5 Nov 2025; NVD gives affected versions for 1,203 of them.") {
		t.Fatalf("feed %+v %v", f, f.Error)
	}
	if rowsOf(t, e.db, "feeds_recent_affected") != 1203 || rowsOf(t, e.db, "feeds_recent_cursor") != 0 {
		t.Fatal("entries or cursor")
	}
}

// D-614: a pull that stops (NVD busy after every try) keeps the pages it stored and where it was, is not a failure of the
// feed, and the next pull goes on from there instead of asking the first windows again.
func TestRecentPull_PausesAndGoesOn(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return 2 }
	n.busy["2026-03-05T12:00:00.000Z/0"] = true
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	f := e.feed(recentFeedID)
	if f.Status != "never" || rowsOf(t, e.db, "feeds_recent_cve") != 2 || rowsOf(t, e.db, "feeds_recent_cursor") != 1 {
		t.Fatalf("paused: %+v, %d CVEs", f, rowsOf(t, e.db, "feeds_recent_cve"))
	}
	if live := e.svc.live(f); live.Error == nil || !strings.Contains(*live.Error, "Loading the CVEs of the last 12 months from NVD: 2 stored so far") {
		t.Fatalf("progress %v", live.Error)
	}
	n.mu.Lock()
	n.busy = map[string]bool{}
	n.asked = nil
	n.mu.Unlock()
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests(); !slices.Equal(got, []string{"pub 2026-03-05 0", "pub 2026-07-03 0", "pub 2026-10-31 0"}) {
		t.Fatalf("resumed requests %v", got)
	}
	if f := e.feed(recentFeedID); f.Status != "ok" || *f.Records != 8 {
		t.Fatalf("feed %+v", f)
	}
}

// D-614: after a good pull, the update asks only for NVD's changes since one day before it; a changed CVE published
// before the 12 months is not kept, a rejected one is dropped, and CVEs that aged out go.
func TestRecentPull_UpdateKeepsTwelveMonths(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(_ time.Time, byPub bool) int {
		if byPub {
			return 1
		}
		return 0
	}
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	first := e.clock()
	if rowsOf(t, e.db, "feeds_recent_cve") != 4 {
		t.Fatal("fill")
	}
	n.mu.Lock()
	n.asked = nil
	n.extra = []string{
		`{"cve":{"id":"CVE-2020-0001","published":"2020-01-01T00:00:00.000","lastModified":"2026-11-30T00:00:00.000","vulnStatus":"Modified"}}`,
		`{"cve":{"id":"CVE-2026-07030000","published":"2026-07-03T13:00:00.000","lastModified":"2026-11-30T00:00:00.000","vulnStatus":"Rejected"}}`,
	}
	n.mu.Unlock()
	e.setNow(first.AddDate(0, 0, 30)) // the first window's CVE (published 5 Nov 2025) is now older than 12 months
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests(); !slices.Equal(got, []string{"mod " + first.AddDate(0, 0, -1).Format("2006-01-02") + " 0"}) {
		t.Fatalf("update requests %v", got)
	}
	var left []string
	rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve FROM feeds_recent_cve ORDER BY cve`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		left = append(left, c)
	}
	if !slices.Equal(left, []string{"CVE-2026-03050000", "CVE-2026-10310000"}) {
		t.Fatalf("left %v", left)
	}
}
