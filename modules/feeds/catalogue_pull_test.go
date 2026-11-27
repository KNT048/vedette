package feeds

import (
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

// catalogueNVD is a fake NVD for the catalogue pull: the date windows of the fill answer nothing, the walk over the whole set answers
// walk (one record per CVE, published 2019), and a request by id answers the record of that CVE when byID holds it.
type catalogueNVD struct {
	mu    sync.Mutex
	walk  []string        // CVEs of the whole list
	byID  map[string]bool // CVEs NVD has a record of when asked by id
	busy  map[string]bool // CVEs NVD answers 503 for when asked by id
	big   bool            // a walk page of more than recentSmallPage records is not JSON (too large for the proxy, say)
	asked []string        // "walk <start> <size>", "id <cve>", "window"
}

func fakeNVDRecord(cve string) string {
	return fmt.Sprintf(`{"cve":{"id":%q,"published":"2019-05-01T10:00:00.000","lastModified":"2026-01-01T10:00:00.000","vulnStatus":"Analyzed",
"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}`, cve)
}

func (n *catalogueNVD) serve(o *origin) {
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		n.mu.Lock()
		defer n.mu.Unlock()
		switch {
		case q.Get("cveId") != "":
			cve := q.Get("cveId")
			n.asked = append(n.asked, "id "+cve)
			if n.busy[cve] {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if n.byID[cve] {
				_, _ = fmt.Fprintf(w, `{"totalResults":1,"vulnerabilities":[%s]}`, fakeNVDRecord(cve))
				return
			}
			_, _ = fmt.Fprint(w, `{"totalResults":0,"vulnerabilities":[]}`)
		case q.Get("pubStartDate") != "" || q.Get("lastModStartDate") != "":
			n.asked = append(n.asked, "window")
			_, _ = fmt.Fprint(w, `{"totalResults":0,"vulnerabilities":[]}`)
		default:
			start, _ := strconv.Atoi(q.Get("startIndex"))
			size, _ := strconv.Atoi(q.Get("resultsPerPage"))
			n.asked = append(n.asked, fmt.Sprintf("walk %d %d", start, size))
			if n.big && size > recentSmallPage {
				_, _ = fmt.Fprint(w, `{"totalResults":`)
				return
			}
			var recs []string
			for i := start; i < min(start+size, len(n.walk)); i++ {
				recs = append(recs, fakeNVDRecord(n.walk[i]))
			}
			_, _ = fmt.Fprintf(w, `{"totalResults":%d,"vulnerabilities":[%s]}`, len(n.walk), strings.Join(recs, ","))
		}
	})
}

func (n *catalogueNVD) requests(prefix string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, a := range n.asked {
		if strings.HasPrefix(a, prefix) {
			out = append(out, a)
		}
	}
	return out
}

func catalogueEnv(t *testing.T) (*env, *catalogueNVD) {
	t.Helper()
	e, o := pullEnv(t)
	e.only(recentFeedID)
	e.mirror(recentFeedID, o.url("/nvd"))
	n := &catalogueNVD{byID: map[string]bool{}, busy: map[string]bool{}}
	n.serve(o)
	return e, n
}

// signal stores a public-exploit signal of each CVE dated inside the window (store0), qualifying or not.
func signal(t *testing.T, e *env, source string, qualifies bool, cves ...string) {
	t.Helper()
	write(t, e.db, func(tx *sql.Tx) error {
		for _, c := range cves {
			if err := putSignal(t.Context(), tx, c, SignalPublicExploit, source, store0, store0, qualifies, ""); err != nil {
				return err
			}
		}
		return nil
	})
}

func held(t *testing.T, e *env) []string {
	t.Helper()
	got, err := stringSet(t.Context(), e.db.Reader(), `SELECT cve FROM feeds_cve`)
	if err != nil {
		t.Fatal(err)
	}
	return slices.Sorted(mapsKeys(got))
}

// When hundreds of kept CVEs older than the window have no NVD record (a signal source loaded them), the catalogue pull walks NVD's
// whole list once, page by page with NVD's largest page and no other parameter, and stores only the records the retention rule keeps;
// a walk is not started again for a week, and the few CVEs still missing are asked for by id instead.
func TestCataloguePull_WalksTheWholeSetForOlderKeptCVEs(t *testing.T) {
	t.Parallel()
	e, n := catalogueEnv(t)
	var many []string
	for i := range walkMissing {
		many = append(many, fmt.Sprintf("CVE-2018-%04d", 1000+i))
	}
	signal(t, e, exploitDBFeedID, true, many...)
	signal(t, e, exploitDBFeedID, true, "CVE-2019-0001")
	n.walk = []string{"CVE-2019-0001", "CVE-2019-0002", many[0]}
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests("walk"); !slices.Equal(got, []string{"walk 0 2000"}) {
		t.Fatalf("walk requests %v", got)
	}
	if got := held(t, e); !slices.Equal(got, []string{many[0], "CVE-2019-0001"}) { // CVE-2019-0002 is not kept
		t.Fatalf("catalogue %v", got)
	}
	if w, err := e.svc.st.nvdCursor(t.Context(), selectorWalk); err != nil || w == nil || w.Mode != modeDone || w.Total != 3 {
		t.Fatalf("walk cursor %+v %v", w, err)
	}
	if f := e.feed(recentFeedID); f.Status != "ok" || f.Error == nil || !strings.Contains(*f.Error, "The catalogue keeps 2 older CVEs") {
		t.Fatalf("feed %+v %q", f, deref(f.Error))
	}
	// the next day: no second walk; the missing ones are asked by id, at most missingPerPull a pull
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests("walk"); len(got) != 1 {
		t.Fatalf("walked again within a week: %v", got)
	}
	if got := n.requests("id "); len(got) != missingPerPull {
		t.Fatalf("%d asked by id, want %d", len(got), missingPerPull)
	}
}

// A few kept CVEs without an NVD record are asked for by id: a qualifying signal of a public source and an exploited-list entry, never
// a CVE only a custom feed names, a signal that does not qualify, or one of a source that is not a public list. A CVE NVD has no record of is not asked again within a day.
func TestCataloguePull_AsksNVDByIDForSignalledCVEsOnly(t *testing.T) {
	t.Parallel()
	e, n := catalogueEnv(t)
	signal(t, e, exploitDBFeedID, true, "CVE-2018-0007", "CVE-2018-0010")
	signal(t, e, "poc-index", false, "CVE-2018-0009")
	signal(t, e, "ids-local", true, "CVE-2018-0012") // a signal of what the box saw itself: never sent anywhere
	addCustom(t, e.db, "cf-v", "Partner advisories", KindVulnerabilities)
	applyV(t, e.db, epoch0, "cf-v", []Vuln{vuln("CVE-2018-0008", "Acme", "Box", "2026-11-01")}, true)
	applyV(t, e.db, epoch0, kevFeedID, []Vuln{vuln("CVE-2017-0011", "Acme", "Box", "2026-11-01")}, false)
	n.byID["CVE-2018-0007"], n.byID["CVE-2017-0011"] = true, true
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	asked := n.requests("id ")
	slices.Sort(asked)
	if want := []string{"id CVE-2017-0011", "id CVE-2018-0007", "id CVE-2018-0010"}; !slices.Equal(asked, want) {
		t.Fatalf("asked by id %v, want %v", asked, want)
	}
	if len(n.requests("walk")) != 0 {
		t.Fatal("a walk for three CVEs")
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE nvd_at IS NOT NULL AND cve IN ('CVE-2018-0007', 'CVE-2017-0011')`); n != 2 {
		t.Fatalf("%d records stored", n)
	}
	if n := count(t, e.db, `SELECT count(*) FROM feeds_cve_range WHERE cve = 'CVE-2018-0007' AND origin = 'nvd'`); n != 1 {
		t.Fatalf("%d ranges", n)
	}
	e.setNow(e.clock().Add(time.Hour))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests("id "); len(got) != 3 {
		t.Fatalf("CVE-2018-0010, which NVD does not have, was asked again within a day: %v", got)
	}
}

// Each EPSS file writes the day's score of the CVEs an exploited list or a signal names into feeds_epss_hist (only those); the pages
// read today's score and the one of seven days before from there ("rising"), and the history keeps epssHistKeep days.
func TestEPSSAllPull_WritesTheHistoryOfListedAndSignalledCVEs(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only(epssAllFeedID)
	e.mirror(epssAllFeedID, o.url("/epss.csv.gz"))
	applyV(t, e.db, epoch0, kevFeedID, []Vuln{vuln("CVE-2026-1234", "Acme", "Box", "2026-11-01")}, false)
	signal(t, e, exploitDBFeedID, true, "CVE-1999-0001")
	file := func(day string, score string) string {
		return gz(t, "#model_version:v2026.06.15,score_date:"+day+"T12:00:22Z\ncve,epss,percentile\nCVE-1999-0001,0.04,0.92\nCVE-2026-1234,"+score+
			",0.99\nCVE-2025-0002,0.1,0.95\n")
	}
	o.body("/epss.csv.gz", `"d1"`, file("2026-11-07", "0.30"))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	if got := count(t, e.db, `SELECT count(*) FROM feeds_epss_hist WHERE day = '2026-11-07'`); got != 2 {
		t.Fatalf("%d history rows, want the listed and the signalled CVE only", got)
	}
	o.body("/epss.csv.gz", `"d2"`, file("2026-11-14", "0.65"))
	e.setNow(e.clock().Add(25 * time.Hour))
	if err := e.svc.Fetch(t.Context(), epssAllFeedID); err != nil {
		t.Fatal(err)
	}
	v, ok, err := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-1234")
	if err != nil || !ok || v.EPSS == nil || *v.EPSS != 0.65 || v.EPSS7dAgo == nil || *v.EPSS7dAgo != 0.30 {
		t.Fatalf("today's and a week ago's score: %+v %v", v, err)
	}
	write(t, e.db, func(tx *sql.Tx) error {
		return pruneCatalogue(t.Context(), tx, time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC), nil)
	})
	if got := count(t, e.db, `SELECT count(*) FROM feeds_epss_hist WHERE day = '2026-11-07'`); got != 0 {
		t.Fatalf("history older than %d days kept: %d", epssHistKeep, got)
	}
}

// A walk page that comes back unreadable is asked again with recentSmallPage records, page by page, so one bad page never stalls the
// walk.
func TestCataloguePull_WalkAsksASmallerPageAgain(t *testing.T) {
	t.Parallel()
	e, n := catalogueEnv(t)
	var many []string
	for i := range walkMissing {
		many = append(many, fmt.Sprintf("CVE-2018-%04d", 1000+i))
	}
	signal(t, e, exploitDBFeedID, true, many...)
	n.walk = many[:recentSmallPage+10]
	n.big = true
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	want := []string{"walk 0 2000", "walk 0 250", "walk 250 2000", "walk 250 250"}
	if got := n.requests("walk"); !slices.Equal(got, want) {
		t.Fatalf("walk requests %v, want %v", got, want)
	}
	if w, err := e.svc.st.nvdCursor(t.Context(), selectorWalk); err != nil || w == nil || w.Mode != modeDone || w.NextIndex != recentSmallPage+10 {
		t.Fatalf("walk cursor %+v %v", w, err)
	}
	if got := count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE nvd_at IS NOT NULL`); got != recentSmallPage+10 {
		t.Fatalf("%d records stored", got)
	}
}

// A CVE NVD answers busy for is not counted as asked: the next pull asks it again (and stores its record), while one NVD answered for
// waits a day.
func TestCataloguePull_BusyByIDAnswerIsAskedAgainNextPull(t *testing.T) {
	t.Parallel()
	e, n := catalogueEnv(t)
	signal(t, e, exploitDBFeedID, true, "CVE-2018-0021")
	n.byID["CVE-2018-0021"], n.busy["CVE-2018-0021"] = true, true
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests("id "); len(got) == 0 || count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE cve = 'CVE-2018-0021'`) != 0 {
		t.Fatalf("first pull: asked %v", got)
	}
	n.mu.Lock()
	n.busy["CVE-2018-0021"] = false
	n.mu.Unlock()
	e.setNow(e.clock().Add(time.Hour))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if count(t, e.db, `SELECT count(*) FROM feeds_cve WHERE cve = 'CVE-2018-0021' AND nvd_at IS NOT NULL`) != 1 {
		t.Fatalf("the busy CVE was not asked again: %v", n.requests("id "))
	}
}

// CVEs of every age: switched on, the next catalogue pull reads NVD's whole set once although no kept CVE is missing, and stores every
// record of it; that read does not start again until the setting is switched on anew.
func TestCataloguePull_EveryAgeReadsTheWholeSetOnce(t *testing.T) {
	t.Parallel()
	e, n := catalogueEnv(t)
	n.walk = []string{"CVE-2019-0001", "CVE-2019-0002"}
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests("walk"); len(got) != 0 || len(held(t, e)) != 0 {
		t.Fatalf("by default: walk %v, catalogue %v", got, held(t, e))
	}
	write(t, e.db, func(tx *sql.Tx) error { return saveWindow(t.Context(), tx, true, "admin@example.test", e.clock()) })
	var url string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT url FROM feeds_source WHERE id = ?`, recentFeedID).Scan(&url); err != nil {
		t.Fatal(err)
	}
	if owed, err := e.svc.st.recentOwed(t.Context(), url); err != nil || !owed {
		t.Fatalf("owed after the switch: %v %v", owed, err)
	}
	e.setNow(e.clock().Add(time.Minute))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests("walk"); !slices.Equal(got, []string{"walk 0 2000"}) {
		t.Fatalf("walk requests %v", got)
	}
	if got := held(t, e); !slices.Equal(got, []string{"CVE-2019-0001", "CVE-2019-0002"}) {
		t.Fatalf("catalogue %v", got)
	}
	// switched off and on again within a day: no second read of the whole set before 24 hours have passed since the first began
	e.setNow(e.clock().Add(time.Hour))
	for _, on := range []bool{false, true} {
		write(t, e.db, func(tx *sql.Tx) error { return saveWindow(t.Context(), tx, on, "admin@example.test", e.clock()) })
	}
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests("walk"); len(got) != 1 {
		t.Fatalf("a second read within a day: %v", got)
	}
	e.setNow(e.clock().Add(24 * time.Hour))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests("walk"); len(got) != 2 {
		t.Fatalf("the switch's read after the cooldown: %v", got)
	}
	e.setNow(e.clock().Add(8 * 24 * time.Hour))
	if err := e.svc.Fetch(t.Context(), recentFeedID); err != nil {
		t.Fatal(err)
	}
	if got := n.requests("walk"); len(got) != 2 {
		t.Fatalf("a read with no new switch: %v", got)
	}
}
