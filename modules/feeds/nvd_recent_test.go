package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// What the catalogue keeps of a record: dates, NVD's status, the vulnerable entries, and only scores with a valid vector (one CVSS
// rule for every page: a score without its vector is no score); a record with an unusable entry is rejected whole.
func TestParseNVD_Record(t *testing.T) {
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
	d, err := ParseNVD([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if d.Total != 3 || d.Returned != 3 || d.Accepted != 2 || d.Rejected != 1 || len(d.Records) != 2 {
		t.Fatalf("%+v", d)
	}
	a, b := d.Records[0], d.Records[1]
	if len(a.Metrics) != 0 || a.Status != "Deferred" || len(a.Affected) != 0 || a.Published != time.Date(2026, 8, 1, 3, 16, 25, 307e6, time.UTC) {
		t.Fatalf("scores without a vector are not kept: %+v", a)
	}
	if len(b.Metrics) != 0 || len(b.Affected) != 1 || b.Affected[0].EndExcl != "2.0" {
		t.Fatalf("entries: %+v", b)
	}
	// review r2 #9 of #802: one record of the wrong JSON type is rejected alone, the page is kept
	d, err = ParseNVD([]byte(`{"totalResults":2,"vulnerabilities":[{"cve":{"id":42}},` + body[strings.Index(body, `{"cve":{"id":"CVE-2026-0002"`):strings.Index(body, `,
{"cve":{"id":"CVE-2026-0003"`)] + `]}`))
	if err != nil || d.Returned != 2 || d.Accepted != 1 || d.Rejected != 1 || len(d.Records) != 1 || d.Records[0].CVE != "CVE-2026-0002" {
		t.Fatalf("one bad record: %+v %v", d, err)
	}
	for name, in := range map[string]string{"html": "<html>", "no total": `{"vulnerabilities":[]}`} {
		if _, err := ParseNVD([]byte(in)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// recentNVD is a fake NVD for nvd-recent: each date window (pubStartDate, or lastModStartDate for an update) has a number
// of records, CVE-<window>-<n> published an hour after the window starts; codes makes a startIndex answer an HTTP error; hook runs on each request.
type recentNVD struct {
	mu     sync.Mutex
	perWin func(from time.Time, byPub bool) int
	codes  map[string]int  // "<from>/<start>" answered with this status
	broken map[string]bool // "<from>/<start>/<resultsPerPage>" answered with a page that is not JSON
	sizes  []int           // resultsPerPage of each request
	hook   func()
	asked  []string // "<pub|mod> <from> <start>"
	extra  []string // records added to every update answer (raw JSON)
	retry  string   // Retry-After sent with a codes answer, "" for none
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
		size, _ := strconv.Atoi(q.Get("resultsPerPage"))
		key := fmt.Sprintf("%s/%d", fromS, start)
		n.mu.Lock()
		kind := "mod"
		if byPub {
			kind = "pub"
		}
		n.asked = append(n.asked, fmt.Sprintf("%s %s %d", kind, from.Format("2006-01-02"), start))
		code := n.codes[key]
		broken := n.broken[fmt.Sprintf("%s/%d", key, size)]
		n.sizes = append(n.sizes, size)
		hook := n.hook
		total := n.perWin(from, byPub)
		extra, retry := n.extra, n.retry
		n.mu.Unlock()
		if hook != nil {
			hook()
		}
		if code != 0 {
			if retry != "" {
				w.Header().Set("Retry-After", retry)
			}
			w.WriteHeader(code)
			return
		}
		if broken {
			_, _ = fmt.Fprint(w, `{"totalResults":1,"vulnerabilities":[{"cve":`)
			return
		}
		var recs []string
		for i := start; i < min(start+size, total); i++ {
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
	n := &recentNVD{codes: map[string]int{}, broken: map[string]bool{}}
	n.serve(o)
	return e, n
}

// The first fill asks for 12 months of published CVEs in 120-day windows, page by page (nvdPause apart; 0 in the tests), stores
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
	if rowsOf(t, e.db, "feeds_cve_range") != 1203 {
		t.Fatal("entries")
	}
	if c, err := e.svc.st.recentCursor(t.Context()); err != nil || c == nil || c.Mode != modeDone || !c.Until.Equal(e.clock()) {
		t.Fatalf("cursor after the fill: %+v %v", c, err)
	}
}

// A pull that stops (NVD busy after every try) keeps the pages it stored and where it was, is not a failure of the
// feed, and the next pull goes on from there instead of asking the first windows again.
func TestRecentPull_PausesAndGoesOn(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return 2 }
	n.codes["2026-03-05T12:00:00.000Z/0"] = http.StatusServiceUnavailable
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	f := e.feed(recentFeedID)
	if f.Status != "never" || rowsOf(t, e.db, "feeds_cve") != 2 || count(t, e.db, `SELECT count(*) FROM feeds_nvd_cursor WHERE selector = 'recent'`) != 1 {
		t.Fatalf("paused: %+v, %d CVEs", f, rowsOf(t, e.db, "feeds_cve"))
	}
	if live := e.svc.live(t.Context(), f); live.Error == nil || !strings.Contains(*live.Error, "Loading the CVEs of the last 12 months from NVD: 2 stored so far") {
		t.Fatalf("progress %v", live.Error)
	}
	n.mu.Lock()
	n.codes = map[string]int{}
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

// After a good pull, the update asks only for NVD's changes since one day before it; a changed CVE published
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
	if rowsOf(t, e.db, "feeds_cve") != 4 {
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
	if left := recentCVEs(t, e); !slices.Equal(left, []string{"CVE-2026-03050000", "CVE-2026-10310000"}) {
		t.Fatalf("left %v", left)
	}
}

func recentCVEs(t *testing.T, e *env) []string {
	t.Helper()
	rows, err := e.db.Reader().QueryContext(t.Context(), `SELECT cve FROM feeds_cve ORDER BY cve`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		out = append(out, c)
	}
	return out
}

func (n *recentNVD) reset() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.asked, n.codes, n.hook, n.sizes = nil, map[string]int{}, nil, nil
}

// Review r1 #1, #4: an update NVD refuses on its first page is a failure the feed line shows as it is (not a progress
// line), and the next pull is an update again, not a refill of 12 months.
func TestRecentPull_FailedUpdateIsNotARefill(t *testing.T) {
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
	n.reset()
	n.mu.Lock()
	n.codes[first.Add(-24*time.Hour).Format("2006-01-02T15:04:05.000Z")+"/0"] = http.StatusForbidden
	n.mu.Unlock()
	e.setNow(first.Add(24 * time.Hour))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	f := e.svc.live(t.Context(), e.feed(recentFeedID))
	if f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, "HTTP 403") || strings.Contains(*f.Error, "Loading") {
		t.Fatalf("failed update: %+v %v", f, *f.Error)
	}
	n.reset()
	e.setNow(first.Add(72 * time.Hour))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests(); !slices.Equal(got, []string{"mod " + first.Add(-24*time.Hour).Format("2006-01-02") + " 0"}) {
		t.Fatalf("after a failed update the next pull asks %v, want the update from the last complete time", got)
	}
	if f := e.feed(recentFeedID); f.Status != "ok" {
		t.Fatalf("feed %+v", f)
	}
}

// Review r1 #2: a fill that pauses and goes on days later finishes its windows, then in the same pull asks for NVD's
// changes since one day before the fill started, so CVEs published in between are not lost.
func TestRecentPull_LateFillCatchesUp(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return 1 }
	start := e.clock()
	n.codes["2026-03-05T12:00:00.000Z/0"] = http.StatusServiceUnavailable
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	n.reset()
	e.setNow(start.Add(72 * time.Hour))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	want := []string{"pub 2026-03-05 0", "pub 2026-07-03 0", "pub 2026-10-31 0", "mod " + start.Add(-24*time.Hour).Format("2006-01-02") + " 0"}
	if got := n.requests(); !slices.Equal(got, want) {
		t.Fatalf("requests %v, want %v", got, want)
	}
	c, err := e.svc.st.recentCursor(t.Context())
	if err != nil || c == nil || c.Mode != modeDone || !c.Until.Equal(start.Add(72*time.Hour)) {
		t.Fatalf("cursor %+v %v", c, err)
	}
}

// Review r1 #2: an update window that ended more than 12 h ago is asked again up to now.
func TestRecentStart(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	u := "https://nvd.example/x"
	upd := &recentCursor{URL: u, Mode: modeUpdate, From: now.AddDate(0, 0, -5), To: now.AddDate(0, 0, -3), Until: now.AddDate(0, 0, -3), NextIndex: 1000, Total: 1500}
	if c := recentStart(upd, u, 10, now); c.Mode != modeUpdate || !c.From.Equal(upd.From) || !c.To.Equal(now) || c.NextIndex != 0 {
		t.Fatalf("stale update %+v", c)
	}
	fresh := *upd
	fresh.To = now.Add(-time.Hour)
	if c := recentStart(&fresh, u, 10, now); c.NextIndex != 1000 || !c.To.Equal(fresh.To) {
		t.Fatalf("fresh update goes on: %+v", c)
	}
	done := &recentCursor{URL: u, Mode: modeDone, Until: now.AddDate(0, 0, -2)}
	if c := recentStart(done, u, 10, now); c.Mode != modeUpdate || !c.From.Equal(now.AddDate(0, 0, -3)) {
		t.Fatalf("after done %+v", c)
	}
	staleFill := &recentCursor{URL: u, Mode: modeFill, From: now.AddDate(0, 0, -300), To: now.AddDate(0, 0, -200), Until: now.AddDate(0, 0, -61), NextIndex: 5}
	freshFill := *staleFill
	freshFill.Until = now.AddDate(0, 0, -59)
	if c := recentStart(&freshFill, u, 10, now); c.NextIndex != 5 {
		t.Fatalf("an unfinished fill younger than 60 days goes on: %+v", c)
	}
	for name, c := range map[string]recentCursor{
		"stale fill":  recentStart(staleFill, u, 10, now),
		"no data":     recentStart(done, u, 0, now),
		"new address": recentStart(done, "https://mirror.example/x", 10, now),
		"long gap":    recentStart(&recentCursor{URL: u, Mode: modeDone, Until: now.AddDate(0, 0, -120)}, u, 10, now),
		"nothing":     recentStart(nil, u, 10, now),
	} {
		if c.Mode != modeFill || !c.From.Equal(now.AddDate(0, 0, -recentDays)) {
			t.Errorf("%s: %+v", name, c)
		}
	}
}

// While nvd-kev is pulling, nvd-recent asks NVD nothing and goes on later (not a failure).
func TestRecentPull_WaitsForNVDKev(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return 1 }
	release, _, err := e.svc.lockFeed(t.Context(), nvdFeedID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	release()
	if len(n.requests()) != 0 || e.feed(recentFeedID).Status != "never" {
		t.Fatalf("requests %v, feed %+v", n.requests(), e.feed(recentFeedID))
	}
}

// A feed turned off in the middle of a fill stores nothing more: the page that came back after is not written.
func TestRecentPull_TurnedOffMidFill(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return 1 }
	calls := 0
	n.hook = func() {
		calls++
		if calls == 2 {
			if c, b := e.put(recentFeedID, `{"enabled":false}`); c != 200 {
				t.Errorf("turn off: %d %v", c, b)
			}
		}
	}
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := recentCVEs(t, e); len(got) != 1 || len(n.requests()) != 2 {
		t.Fatalf("stored %v after %v", got, n.requests())
	}
	if f := e.feed(recentFeedID); f.Enabled || f.Status == "ok" {
		t.Fatalf("feed %+v", f)
	}
}

// Review r2 #1: every NVD request of the two NVD feeds books a slot nvdPause after the previous one, whoever asks; a
// cancelled caller returns. Not parallel: it sets nvdPause (0 in the other tests).
func TestNVDSlot_SpacesRequestsOfBothFeeds(t *testing.T) {
	pause := nvdPause
	t.Cleanup(func() { nvdPause = pause })
	nvdPause = 6 * time.Second
	e := newEnv(t)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.svc.nvdSlot(t.Context()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := e.waited(); !slices.Equal(got, []time.Duration{6 * time.Second}) {
		t.Fatalf("waits %v: the second caller must wait nvdPause", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.svc.nvdSlot(ctx); err == nil {
		t.Fatal("a cancelled caller got a slot")
	}
}

// Review r2 #1: while nvd-kev waits out NVD (a Retry-After still in the future), nvd-recent asks nothing.
func TestRecentPull_WaitsWhileNVDKevWaitsOutNVD(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return 1 }
	e.svc.nvdMu.Lock()
	e.svc.nvd = &nvdRun{url: "x", retryAt: e.clock().Add(10 * time.Minute)}
	e.svc.nvdMu.Unlock()
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if len(n.requests()) != 0 || e.feed(recentFeedID).Status != "never" {
		t.Fatalf("requests %v, feed %+v", n.requests(), e.feed(recentFeedID))
	}
}

// Review r1 #6, r2 #1: a page of 1,000 that cannot be read is asked again with 250 records, and the next page starts
// after the records that came back.
func TestRecentPull_RetriesASmallerPage(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	first := e.clock().AddDate(0, 0, -recentDays)
	n.perWin = func(from time.Time, _ bool) int {
		if from.Equal(first) {
			return 300
		}
		return 0
	}
	n.broken[first.Format("2006-01-02T15:04:05.000Z")+"/0/1000"] = true
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests()[:3]; !slices.Equal(got, []string{"pub 2025-11-05 0", "pub 2025-11-05 0", "pub 2025-11-05 250"}) {
		t.Fatalf("requests %v", got)
	}
	n.mu.Lock()
	sizes := slices.Clone(n.sizes[:3])
	n.mu.Unlock()
	if !slices.Equal(sizes, []int{1000, 250, 1000}) {
		t.Fatalf("page sizes %v", sizes)
	}
	if f := e.feed(recentFeedID); f.Status != "ok" || *f.Records != 300 {
		t.Fatalf("feed %+v", f)
	}
}

// Review r1 #6, r2 #1: a fill window NVD says has more than recentMaxTotal records is refused (a broken answer).
func TestRecentPull_RefusesAnOverlargeWindow(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return recentMaxTotal + 1 }
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	f := e.feed(recentFeedID)
	if f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, "more than Vedette expects") || len(n.requests()) != 1 {
		t.Fatalf("feed %+v %v, requests %v", f, f.Error, n.requests())
	}
}

// Review r2 #2: an update NVD says changed more than recentMaxTotal records turns into a fill in the same pull.
func TestRecentPull_UpdateOverCapFills(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(_ time.Time, byPub bool) int {
		if byPub {
			return 1
		}
		return recentMaxTotal + 1
	}
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	first := e.clock()
	n.reset()
	e.setNow(first.Add(24 * time.Hour))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	got := n.requests()
	if len(got) != 5 || got[0] != "mod "+first.Add(-24*time.Hour).Format("2006-01-02")+" 0" || !strings.HasPrefix(got[1], "pub 2025-11-06") {
		t.Fatalf("requests %v", got)
	}
	if f := e.feed(recentFeedID); f.Status != "ok" {
		t.Fatalf("feed %+v", f)
	}
}

// Review r1 #4, r2 #1: a feed whose last pull failed and that is now part-way through shows both the error and how far
// it got, and keeps its error status.
func TestRecentLive_ErrorAndProgress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.setRecent(&recentProgress{cur: recentCursor{Mode: modeFill, From: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)}, stored: 1000, run: &nvdRun{}}, time.Time{})
	msg := "NVD was busy (HTTP 503), after every try."
	r := e.svc.live(t.Context(), sourceRow{ID: recentFeedID, Enabled: true, Status: "error", Error: &msg})
	if r.Status != "error" || r.Error == nil || *r.Error != msg+" Loading the CVEs of the last 12 months from NVD: 1,000 stored so far, published up to 1 Mar 2026." {
		t.Fatalf("%+v %v", r, *r.Error)
	}
	r = e.svc.live(t.Context(), sourceRow{ID: recentFeedID, Enabled: true, Status: "never"})
	if r.Status != "never" || r.Error == nil || !strings.HasPrefix(*r.Error, "Loading") {
		t.Fatalf("%+v", r)
	}
}

// Review r2 #1: nvd-recent's pages go through the shared NVD gate (each request waits for its slot). Not parallel: it
// sets nvdPause. The test clock stands still, so the booked slots add up.
func TestRecentPull_PagesGoThroughTheNVDGate(t *testing.T) {
	pause := nvdPause
	t.Cleanup(func() { nvdPause = pause })
	nvdPause = 6 * time.Second
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return 1 }
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := e.waited(); !slices.Equal(got, []time.Duration{6 * time.Second, 12 * time.Second, 18 * time.Second}) || len(n.requests()) != 4 {
		t.Fatalf("waits %v for %v", got, n.requests())
	}
}

// Review r2 #5, #6 of #802: a fill paused by NVD's busy answer says why and when it goes on, read at the time the row is shown, and
// the 5-minute check does not ask NVD again before that time.
func TestRecentPull_WaitsOutNVDsRetryTime(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return 2 }
	n.codes["2026-03-05T12:00:00.000Z/0"] = http.StatusServiceUnavailable
	n.retry = "900" // NVD: come back in 15 minutes
	if err := e.runPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if live := e.svc.live(t.Context(), e.feed(recentFeedID)); live.Error == nil || !strings.Contains(*live.Error, "NVD was busy (HTTP 503). Vedette tries again in") {
		t.Fatalf("progress %v", *live.Error)
	}
	n.mu.Lock()
	n.codes, n.asked = map[string]int{}, nil
	n.mu.Unlock()
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) != 0 {
		t.Fatalf("asked NVD before its retry time: %v %v", n.requests(), err)
	}
	e.setNow(e.clock().Add(10 * time.Minute))
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) != 0 {
		t.Fatalf("asked NVD 10 minutes into its 15: %v %v", n.requests(), err)
	}
	e.setNow(e.clock().Add(6 * time.Minute))
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) == 0 {
		t.Fatalf("did not go on after the retry time: %v %v", n.requests(), err)
	}
	if live := e.svc.live(t.Context(), e.feed(recentFeedID)); live.Error != nil && strings.Contains(*live.Error, "busy") {
		t.Fatalf("still says busy after NVD answered: %v", *live.Error)
	}
}

// Review r2 #7 of #802: a clock stepped back does not make the next NVD request wait as long as the step. Not parallel: it sets
// nvdPause.
func TestNVDSlot_ClockSteppedBack(t *testing.T) {
	pause := nvdPause
	t.Cleanup(func() { nvdPause = pause })
	nvdPause = 6 * time.Second
	e := newEnv(t)
	if err := e.svc.nvdSlot(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.setNow(e.clock().Add(-time.Hour))
	if err := e.svc.nvdSlot(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, w := range e.waited() {
		if w > nvdPause {
			t.Fatalf("waited %v after the clock went back an hour", w)
		}
	}
}

// On a test box: a cursor reset (migration 0013) after a recent good pull is a fill the feed still owes: the
// 5-minute check pulls it at once (only the back-off after a failure holds it back), goes on with a fill longer than one pull,
// and meanwhile the feed row says where it goes on instead of its old "OK" (after a restart too, with an old error; review 1 #1,
// #3 of #805). With a done cursor the same check asks nothing; a done cursor for another address is owed.
func TestRecentPull_CursorResetIsDueAtTheNextCheck(t *testing.T) {
	t.Parallel()
	e, n := recentEnv(t)
	n.perWin = func(time.Time, bool) int { return 1 }
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	first := e.clock()
	n.reset()
	e.setNow(first.Add(PullEvery))
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) != 0 {
		t.Fatalf("a done cursor and a good pull 5 minutes ago: asked %v, %v", n.requests(), err)
	}
	if f := e.svc.live(t.Context(), e.feed(recentFeedID)); f.Status != "ok" || f.Error == nil || strings.Contains(*f.Error, "Loading") {
		t.Fatalf("complete: %+v", f)
	}
	sqlDo := func(q string) {
		t.Helper()
		if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q); return err }); err != nil {
			t.Fatal(err)
		}
	}
	window := func(i int) string { // the date window i of a fill started now, as NVD's fake keys it
		return e.clock().AddDate(0, 0, -recentDays).Add(time.Duration(i)*recentWindow).Format("2006-01-02T15:04:05.000Z") + "/0"
	}
	setCode := func(key string) {
		n.mu.Lock()
		n.codes[key] = http.StatusForbidden
		n.mu.Unlock()
	}

	sqlDo(`DELETE FROM feeds_nvd_cursor`) // what migration 0013 did
	f := e.svc.live(t.Context(), e.feed(recentFeedID))
	line := "Loading the CVEs of the last 12 months from NVD: 4 stored so far, published up to " + e.clock().AddDate(0, 0, -recentDays).Format("2 Jan 2006") + "."
	if f.Status != "ok" || f.Error == nil || *f.Error != line+" Vedette goes on at the next check (every 5 minutes)." {
		t.Fatalf("row after the reset: %+v %v", f, f.Error)
	}

	setCode(window(1)) // the refill stores its first window, then NVD refuses the second: paused, cursor in fill, no failure
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) != 2 {
		t.Fatalf("the reset cursor is due at once: asked %v, %v", n.requests(), err)
	}
	if c, err := e.svc.st.recentCursor(t.Context()); err != nil || c == nil || c.Mode != modeFill || e.feed(recentFeedID).Failures != 0 {
		t.Fatalf("cursor after the paused pull: %+v %v", c, err)
	}
	n.reset() // the next check goes on with the fill, though the last success is recent
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) != 3 {
		t.Fatalf("the unfinished fill goes on: asked %v, %v", n.requests(), err)
	}
	if c, err := e.svc.st.recentCursor(t.Context()); err != nil || c == nil || c.Mode != modeDone {
		t.Fatalf("cursor after the refill: %+v %v", c, err)
	}

	n.reset()
	sqlDo(`DELETE FROM feeds_nvd_cursor`)
	setCode(window(0)) // a refill whose first page fails: the back-off holds the next check
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) != 1 {
		t.Fatalf("the reset cursor is due at once: asked %v, %v", n.requests(), err)
	}
	failed := e.clock()
	e.svc.setRecent(nil, time.Time{}) // a restart: the old error shows with how far the data got, without a 5-minute promise
	f = e.svc.live(t.Context(), e.feed(recentFeedID))
	if f.Status != "error" || f.Error == nil || *f.Error != "The source answered HTTP 403. "+line {
		t.Fatalf("row after a restart: %+v %v", f, *f.Error)
	}
	n.reset()
	e.setNow(failed.Add(BackoffBase - time.Minute))
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) != 0 {
		t.Fatalf("within the back-off: asked %v, %v", n.requests(), err)
	}
	n.reset()
	e.setNow(failed.Add(BackoffBase))
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) != 4 {
		t.Fatalf("after the back-off the refill runs: asked %v, %v", n.requests(), err)
	}

	n.reset() // a done cursor for another address is owed
	sqlDo(`UPDATE feeds_nvd_cursor SET url = 'https://old.example/nvd'`)
	e.setNow(e.clock().Add(PullEvery))
	if err := e.runPull(t.Context()); err != nil || len(n.requests()) != 4 {
		t.Fatalf("another address: asked %v, %v", n.requests(), err)
	}
}

// #898: NVD's real shapes of 2026. An application CVE "running on" Windows Server 2025 (CVE-2026-23666:
// .NET Framework vulnerable AND windows_server_2025 vulnerable:false) keeps only its .NET entries as Affected, with the Windows releases
// as their Platforms: no Affected row names windows_server_2025, so it never counts for a Windows Server row. An OS CVE (CVE-2026-69902)
// keeps its windows_server_2025 range as Affected, with no platform condition.
func TestParseNVD_M2_10_RunningOnWindowsIsNotAffected(t *testing.T) {
	t.Parallel()
	body := `{"totalResults":2,"vulnerabilities":[
{"cve":{"id":"CVE-2026-23666","published":"2026-01-13T18:16:00.000","lastModified":"2026-02-01T00:00:00.000","vulnStatus":"Analyzed",
 "configurations":[
  {"operator":"AND","nodes":[
   {"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:microsoft:.net_framework:3.5:-:*:*:*:*:*:*"},
    {"vulnerable":true,"criteria":"cpe:2.3:a:microsoft:.net_framework:4.8.1:*:*:*:*:*:*:*"}]},
   {"operator":"OR","negate":false,"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows_11_24h2:-:*:*:*:*:*:x64:*"},
    {"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*"},
    {"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows_server_2025:-:*:*:*:*:*:x64:*"}]}]}]}},
{"cve":{"id":"CVE-2026-69902","published":"2026-10-13T17:15:00.000","lastModified":"2026-10-20T00:00:00.000","vulnStatus":"Analyzed",
 "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
  {"vulnerable":true,"criteria":"cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:x64:*","versionEndExcluding":"10.0.26100.9711"},
  {"vulnerable":true,"criteria":"cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:x64:*","versionEndExcluding":"10.0.26100.33650"}]}]}]}}]}`
	d, err := ParseNVD([]byte(body))
	if err != nil || len(d.Records) != 2 {
		t.Fatalf("%+v %v", d, err)
	}
	app, os := d.Records[0], d.Records[1]
	if len(app.Affected) != 2 || len(app.Platforms) != 2 {
		t.Fatalf(".NET entries only: %+v", app)
	}
	for i, r := range app.Affected {
		if !strings.Contains(r.CPE, ":.net_framework:") || !slices.Contains(app.Platforms[i], "microsoft:windows_server_2025") {
			t.Fatalf("entry %d: %+v platforms %v", i, r, app.Platforms[i])
		}
	}
	if len(os.Affected) != 2 || os.Affected[1].CPE != "cpe:2.3:o:microsoft:windows_server_2025:*:*:*:*:*:*:x64:*" || os.Affected[1].EndExcl != "10.0.26100.33650" ||
		len(os.Platforms[1]) != 0 {
		t.Fatalf("OS entries: %+v", os)
	}
}
