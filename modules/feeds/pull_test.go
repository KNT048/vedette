package feeds

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// onlyLoopback lets a test reach its own origin and fails on any other host: no real network in tests. The origin is
// named originHost in feed addresses (a loopback address is refused when a feed is saved, D-420) and reached on 127.0.0.1.
type onlyLoopback struct{ t *testing.T }

const originHost = "origin.lan"

func (o onlyLoopback) RoundTrip(r *http.Request) (*http.Response, error) {
	if h := r.URL.Hostname(); h == originHost {
		r = r.Clone(r.Context())
		r.URL.Host = net.JoinHostPort("127.0.0.1", r.URL.Port())
	} else if h != "127.0.0.1" {
		o.t.Errorf("request to a real host: %s", r.URL.Host)
		return nil, fmt.Errorf("no network in this test")
	}
	return http.DefaultTransport.RoundTrip(r)
}

type hit struct {
	path, query string
	header      http.Header
}

// origin is a fake feed source on 127.0.0.1.
type origin struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	routes map[string]http.HandlerFunc
	hits   []hit
}

func newOrigin(t *testing.T) *origin {
	o := &origin{t: t, routes: map[string]http.HandlerFunc{}}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.hits = append(o.hits, hit{r.URL.Path, r.URL.RawQuery, r.Header.Clone()})
		h := o.routes[r.URL.Path]
		o.mu.Unlock()
		if h == nil {
			t.Errorf("request to an undeclared path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(o.srv.Close)
	return o
}

func (o *origin) url(path string) string {
	return strings.Replace(o.srv.URL, "127.0.0.1", originHost, 1) + path
}

func (o *origin) serve(path string, h http.HandlerFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.routes[path] = h
}

// body serves text with an ETag; a request that sends the same ETag back gets 304.
func (o *origin) body(path, etag, text string) {
	o.serve(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(text))
	})
}

func (o *origin) count(path string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, h := range o.hits {
		if h.path == path {
			n++
		}
	}
	return n
}

func (o *origin) all() []hit {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]hit(nil), o.hits...)
}

func testFile(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name) //nolint:gosec // a fixed test fixture name
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// pullEnv is an env whose fetcher reaches only the origin.
func pullEnv(t *testing.T) (*env, *origin) {
	t.Helper()
	return newEnvFetcher(t, Fetcher{Client: &http.Client{Transport: onlyLoopback{t}}, Version: "test"}), newOrigin(t)
}

// only turns every built-in feed off except the given ones (so the job contacts nothing else).
func (e *env) only(ids ...string) {
	e.t.Helper()
	for _, b := range BuiltinSources() {
		on := false
		for _, id := range ids {
			on = on || id == b.ID
		}
		c, body := e.put(b.ID, fmt.Sprintf(`{"enabled":%v}`, on))
		if c != 200 {
			e.t.Fatalf("%s: %d %v", b.ID, c, body)
		}
	}
}

// mirror points a built-in feed at the origin (the admin's mirror address).
func (e *env) mirror(id, url string) {
	e.t.Helper()
	if c, b := e.put(id, fmt.Sprintf(`{"url":%q}`, url)); c != 200 {
		e.t.Fatalf("mirror %s: %d %v", id, c, b)
	}
}

func (e *env) fetch(id string) (int, map[string]any) {
	e.t.Helper()
	c, b, _ := e.do("POST", "/feeds/sources/"+id+"/fetch", "admin", "")
	return c, b
}

func (e *env) feed(id string) sourceRow {
	e.t.Helper()
	r, err := e.svc.st.source(e.t.Context(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func TestContract_POST1_KEVPullStoresAndPublishesNewCVEsOnce(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev")
	e.mirror("cisa-kev", o.url("/kev.json"))
	kev := testFile(t, "kev.json")
	o.body("/kev.json", `"v1"`, kev)

	c, b := e.fetch("cisa-kev")
	if c != 200 || at(b, "status") != "ok" || at(b, "records") != 3.0 || at(b, "last_fetch") != "2026-11-05T12:00:00Z" || !strings.Contains(at(b, "error").(string), "rows were rejected") {
		t.Fatalf("%d %v", c, b)
	}
	if n := rowsOf(t, e.db, "feeds_vuln"); n != 3 {
		t.Fatalf("%d vulnerabilities", n)
	}
	// D-78: the first pull into an empty table is a baseline: one event, not one per CVE
	if news, base := e.pub.named(EventNewKEV), e.pub.named(EventSyncBaseline); len(news) != 0 || len(base) != 1 || base[0] != (SyncBaselineEvent{Source: "cisa-kev", Count: 3}) {
		t.Errorf("first pull: new_kev %v, baseline %v", news, base)
	}
	_, s := e.get("/feeds/status")
	if at(s, "kev_catalog_version") != "2026.11.04" || at(s, "sources", 0, "name") != "CISA KEV" {
		t.Errorf("status: %v", s)
	}
	if !strings.Contains(e.auditText(), "admin@acme.example"+"feeds.fetch"+"CISA KEV"+"3 records") {
		t.Errorf("audit: %q", e.auditText())
	}

	// the same catalog again: a conditional request, answered 304, nothing new
	e.setNow(e.clock().Add(time.Hour))
	c, b = e.fetch("cisa-kev")
	hits := o.all()
	if c != 200 || at(b, "status") != "ok" || at(b, "records") != 3.0 || hits[len(hits)-1].header.Get("If-None-Match") != `"v1"` || len(e.pub.named(EventNewKEV)) != 0 || len(e.pub.named(EventSyncBaseline)) != 1 {
		t.Errorf("repeat: %d %v %v", c, b, hits[len(hits)-1].header)
	}
	if ua := hits[0].header.Get("User-Agent"); ua != "Vedette/test" || hits[0].header.Get("Authorization") != "" {
		t.Errorf("request identity: %v", hits[0].header)
	}

	// one more CVE in the catalog: exactly one more event
	extra := `{"cveID":"CVE-2026-10099","vendorProject":"Acme","product":"Box","vulnerabilityName":"n","dateAdded":"2026-11-04","shortDescription":"d","requiredAction":"a","dueDate":"2026-11-25","knownRansomwareCampaignUse":"Unknown","notes":""},`
	o.body("/kev.json", `"v2"`, strings.Replace(kev, `"vulnerabilities": [`, `"vulnerabilities": [`+extra, 1))
	e.setNow(e.clock().Add(time.Hour))
	if c, b = e.fetch("cisa-kev"); c != 200 || at(b, "records") != 4.0 {
		t.Fatalf("%d %v", c, b)
	}
	// later pulls publish per item
	news := e.pub.named(EventNewKEV)
	if len(news) != 1 || news[0] != (NewKEVEvent{CVE: "CVE-2026-10099", Vendor: "Acme", Product: "Box", DateAdded: "2026-11-04"}) || len(e.pub.named(EventSyncBaseline)) != 1 || len(e.pub.named(EventVulnUpdated)) != 0 {
		t.Errorf("events: %v", e.pub.events)
	}
}

func TestContract_INV8_DisabledFeedRefusedAndErrorsAreRecorded(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev")
	e.mirror("cisa-kev", o.url("/kev.json"))
	if c, _ := e.put("cisa-kev", `{"enabled":false}`); c != 200 {
		t.Fatal(c)
	}
	if c, b := e.fetch("cisa-kev"); c != 409 || code(b) != "feed_disabled" || len(o.all()) != 0 {
		t.Errorf("disabled: %d %v, %d requests", c, b, len(o.all()))
	}
	if c, b := e.fetch("nope"); c != 404 || code(b) != "not_found" {
		t.Errorf("unknown: %d %v", c, b)
	}
	e.put("cisa-kev", `{"enabled":true}`)
	o.body("/kev.json", `"v1"`, testFile(t, "kev.json"))
	e.fetch("cisa-kev")

	// the source goes down: the error is recorded on the feed, the data stays, the job does not fail
	o.serve("/kev.json", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	e.setNow(e.clock().Add(30 * time.Hour)) // due again
	failedAt := e.clock()
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	f := e.feed("cisa-kev")
	if f.Status != "error" || *f.Error != "The source answered HTTP 503." || f.Failures != 1 || *f.Records != 3 || rowsOf(t, e.db, "feeds_vuln") != 3 || !f.LastFetch.Equal(failedAt) {
		t.Errorf("after the error: %+v", f)
	}
	if ev := e.pub.named(EventFetchFailed); len(ev) != 1 || ev[0] != (FetchFailedEvent{FeedID: "cisa-kev", Error: "The source answered HTTP 503."}) {
		t.Errorf("failed event: %v", ev)
	}
	_, list := e.get("/feeds/sources")
	if at(list, "items", 0, "status") != "error" || at(list, "items", 0, "error") != "The source answered HTTP 503." {
		t.Errorf("listing: %v", at(list, "items", 0))
	}
	// back-off: 5 minutes, then 10
	before := o.count("/kev.json")
	e.setNow(failedAt.Add(4 * time.Minute))
	_ = e.svc.RunPull(t.Context())
	if o.count("/kev.json") != before {
		t.Error("retried before the back-off of 5 minutes")
	}
	e.setNow(failedAt.Add(5 * time.Minute))
	_ = e.svc.RunPull(t.Context())
	if o.count("/kev.json") != before+1 || e.feed("cisa-kev").Failures != 2 {
		t.Errorf("no retry after 5 minutes: %d hits, %d failures", o.count("/kev.json")-before, e.feed("cisa-kev").Failures)
	}
	e.setNow(failedAt.Add(5*time.Minute + 9*time.Minute))
	_ = e.svc.RunPull(t.Context())
	if o.count("/kev.json") != before+1 {
		t.Error("retried before the back-off of 10 minutes")
	}
	// the source comes back: success resets the state
	o.body("/kev.json", `"v1"`, testFile(t, "kev.json"))
	e.setNow(failedAt.Add(5*time.Minute + 10*time.Minute))
	_ = e.svc.RunPull(t.Context())
	if f = e.feed("cisa-kev"); f.Status != "ok" || f.Failures != 0 {
		t.Errorf("recovered: %+v", f)
	}
}

func TestContract_INV9_DataIsNeverOlderThanIntervalPlusAnHour(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev")
	e.mirror("cisa-kev", o.url("/kev.json"))
	e.put("cisa-kev", `{"interval_hours":6}`)
	o.body("/kev.json", `"v1"`, testFile(t, "kev.json"))
	for i := 0; i <= 36*60/5; i++ { // 36 hours in the job's own 5 minute steps
		if err := e.svc.RunPull(t.Context()); err != nil {
			t.Fatal(err)
		}
		f := e.feed("cisa-kev")
		if f.LastSuccess == nil || IsStale(e.clock(), *f.LastSuccess, f.IntervalHours) {
			t.Fatalf("stale at %s: %+v", e.clock(), f)
		}
		e.setNow(e.clock().Add(PullEvery))
	}
	if n := o.count("/kev.json"); n != 7 { // 0, 6, 12, 18, 24, 30, 36 hours
		t.Errorf("%d pulls in 36 hours at an interval of 6", n)
	}
}

func TestContract_INV1_JobContactsOnlyDeclaredEnabledSources(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev", "et-open")
	e.mirror("cisa-kev", o.url("/kev.json"))
	e.mirror("et-open", o.url("/et.txt"))
	o.body("/kev.json", `"v1"`, testFile(t, "kev.json"))
	o.body("/et.txt", `"e1"`, "185.220.101.47\n")
	// a custom feed that is turned off is never contacted
	body := strings.Replace(strings.Replace(customBody, `https://threat-share.example.net/c2.csv`, o.url("/off.csv"), 1), `"enabled":true`, `"enabled":false`, 1)
	if c, b, _ := e.do("POST", "/feeds/custom", "admin", body); c != 201 {
		t.Fatalf("%d %v", c, b)
	}
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, h := range o.all() {
		paths[h.path] = true
		if h.header.Get("Cookie") != "" || h.header.Get("Referer") != "" {
			t.Errorf("customer data in a request: %v", h.header)
		}
	}
	if len(paths) != 2 || !paths["/kev.json"] || !paths["/et.txt"] {
		t.Errorf("contacted: %v", paths)
	}
}

// epssOrigin answers like api.first.org: epss 0.8 for the latest day, 0.5 when a date is asked.
func epssOrigin(o *origin, maxIDs *int) {
	o.serve("/epss", func(w http.ResponseWriter, r *http.Request) {
		ids := strings.Split(r.URL.Query().Get("cve"), ",")
		if len(ids) > *maxIDs {
			*maxIDs = len(ids)
		}
		score := "0.8"
		if r.URL.Query().Get("date") != "" {
			score = "0.5"
		}
		var rows []string
		for _, id := range ids {
			rows = append(rows, fmt.Sprintf(`{"cve":%q,"epss":%q,"percentile":"0.9","date":"2026-11-05"}`, id, score))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"OK","total":%d,"data":[%s]}`, len(rows), strings.Join(rows, ",")) //nolint:gosec // a test origin echoing numbers and fixed ids
	})
}

func TestContract_INV2_EPSSInBatchesOfAHundredAndForcedForNewCVEs(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev", "first-epss")
	e.mirror("cisa-kev", o.url("/kev.json"))
	e.mirror("first-epss", o.url("/epss"))
	e.put("cisa-kev", `{"interval_hours":1}`)
	kev := testFile(t, "kev.json")
	o.body("/kev.json", `"v1"`, kev)
	maxIDs := 0
	epssOrigin(o, &maxIDs)
	var extra []Vuln
	for i := range 250 {
		extra = append(extra, vuln(fmt.Sprintf("CVE-2025-%04d", 1000+i), "Acme", "Box", "2026-10-01"))
	}
	applyV(t, e.db, e.clock(), "cisa-kev", extra, false)

	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := o.count("/epss"); n != 6 || maxIDs != 100 { // 253 CVEs: 3 requests for today, 3 for 7 days ago
		t.Errorf("%d EPSS requests, largest %d ids", n, maxIDs)
	}
	dated := 0
	for _, h := range o.all() {
		if h.path == "/epss" && strings.Contains(h.query, "date=2026-10-29") {
			dated++
		}
	}
	if dated != 3 {
		t.Errorf("%d requests for the score of 7 days ago (2026-10-29)", dated)
	}
	v, _, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001")
	if *v.EPSS != 0.8 || *v.EPSS7dAgo != 0.5 || e.feed("first-epss").Records == nil || *e.feed("first-epss").Records != 253 {
		t.Errorf("epss: %v %v records %v", v.EPSS, v.EPSS7dAgo, e.feed("first-epss").Records)
	}
	_, hot := e.get("/feeds/hot?window=7d")
	if d, _ := at(hot, "rows", 0, "max_epss_delta").(float64); d < 0.29 || d > 0.31 {
		t.Errorf("delta: %v", at(hot, "rows", 0))
	}

	// a new CVE an hour later gets its score in the same tick, not a day later
	o.body("/kev.json", `"v2"`, strings.Replace(kev, `"vulnerabilities": [`, `"vulnerabilities": [{"cveID":"CVE-2026-10099","vendorProject":"Acme","product":"Box","vulnerabilityName":"n","dateAdded":"2026-11-04","shortDescription":"d","requiredAction":"a","dueDate":"2026-11-25","knownRansomwareCampaignUse":"Unknown","notes":""},`, 1))
	e.setNow(e.clock().Add(time.Hour))
	before := o.count("/epss")
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	v, _, _ = e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10099")
	if o.count("/epss") != before+6 || v.EPSS == nil || *v.EPSS != 0.8 {
		t.Errorf("forced EPSS pull: %d requests, %v", o.count("/epss")-before, v.EPSS)
	}
	// a failing batch fails the whole pull: no half-updated scores
	o.serve("/epss", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	e.setNow(e.clock().Add(48 * time.Hour))
	_ = e.svc.RunPull(t.Context())
	if f := e.feed("first-epss"); f.Status != "error" || *f.Error != "The source answered HTTP 502." {
		t.Errorf("epss error: %+v", f)
	}
	if v, _, _ = e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001"); *v.EPSS != 0.8 {
		t.Error("scores changed by a failed pull")
	}
}

func TestNucleiTemplatesReachKEVAtOnce(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev", "nuclei-templates")
	e.mirror("cisa-kev", o.url("/kev.json"))
	e.mirror("nuclei-templates", o.url("/cves.json"))
	o.body("/kev.json", `"v1"`, testFile(t, "kev.json"))
	o.body("/cves.json", `"n1"`, testFile(t, "nuclei-cves.jsonl"))
	// the job pulls KEV first, then nuclei; the CVEs already stored get their flag from the same tick
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	a, _, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001")
	b, _, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10002")
	if !a.HasTemplate || b.HasTemplate {
		t.Errorf("flags: %v %v", a.HasTemplate, b.HasTemplate)
	}
	if ev := e.pub.named(EventVulnUpdated); len(ev) != 1 || len(ev[0].(VulnUpdatedEvent).CVEs) != 2 {
		t.Errorf("updated: %v", ev)
	}
	// nuclei drops one template: the flag goes and scan hears about it
	o.body("/cves.json", `"n2"`, `{"ID":"CVE-2026-10003"}`+"\n")
	e.setNow(e.clock().Add(25 * time.Hour))
	_ = e.svc.RunPull(t.Context())
	a, _, _ = e.svc.st.VulnByCVE(t.Context(), "CVE-2026-10001")
	if a.HasTemplate || len(e.pub.named(EventVulnUpdated)) != 2 {
		t.Errorf("after the change: %v %v", a.HasTemplate, e.pub.named(EventVulnUpdated))
	}
	_, hot := e.get("/feeds/hot?window=7d")
	if at(hot, "rows", 2, "key") != "qnap|photo station" || at(hot, "rows", 2, "has_template") != true {
		t.Errorf("hot: %v", hot)
	}
}

func TestIOCFeedsPullMergeAndReportChanges(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("et-open", "abusech-feodo")
	e.mirror("et-open", o.url("/et.txt"))
	e.mirror("abusech-feodo", o.url("/feodo.txt"))
	o.body("/et.txt", `"e1"`, "185.220.101.47\n45.148.10.95\n10.0.0.1\n")
	o.body("/feodo.txt", `"f1"`, "# feodo\n185.220.101.47\n")
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	ev := e.pub.named(EventIOCUpdated)
	if len(ev) != 2 || ev[0] != (IOCUpdatedEvent{FeedID: "et-open", Added: 2}) || ev[1] != (IOCUpdatedEvent{FeedID: "abusech-feodo", Added: 1}) {
		t.Errorf("events: %v", ev)
	}
	if f := e.feed("et-open"); *f.Records != 2 || !strings.Contains(*f.Error, "1 of 3 rows were rejected") {
		t.Errorf("et-open: %+v", f)
	}
	_, b := e.get("/feeds/search?q=185.220.101.47")
	if at(b, "hit", "verdict") != "block" || len(at(b, "hit", "sources").([]any)) != 2 {
		t.Errorf("both feeds list it: %v", b)
	}
	if _, b = e.get("/feeds/search?q=45.148.10.95"); at(b, "hit", "verdict") != "alert" {
		t.Errorf("one source of the ET Open kind: %v", b)
	}
	// et-open drops one address and adds another
	o.body("/et.txt", `"e2"`, "185.220.101.47\n103.75.190.12\n")
	e.setNow(e.clock().Add(7 * time.Hour))
	_ = e.svc.RunPull(t.Context())
	ev = e.pub.named(EventIOCUpdated)
	if len(ev) != 3 || ev[2] != (IOCUpdatedEvent{FeedID: "et-open", Added: 1, Removed: 1}) {
		t.Errorf("events: %v", ev)
	}
	if _, b = e.get("/feeds/search?q=45.148.10.95"); b["hit"] != nil {
		t.Errorf("a dropped listing is still a hit: %v", b)
	}
}

func TestContract_INV3_BadDataKeepsWhatTheBoxHas(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("cisa-kev")
	e.mirror("cisa-kev", o.url("/kev.json"))
	o.body("/kev.json", `"v1"`, testFile(t, "kev.json"))
	e.fetch("cisa-kev")
	for _, c := range []struct {
		name, want string
		serve      http.HandlerFunc
	}{
		{"not a catalog", "The catalog has no", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"vulnerabilities": 5}`)) }},
		{"only bad rows", "All 2 rows were rejected", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"x"},{"cveID":"y"}]}`))
		}},
		{"empty", "The feed returned no records.", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"vulnerabilities":[]}`)) }},
		{"too large", "larger than 5000000 bytes", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat(" ", MaxBodyBytes+10)))
		}},
	} {
		o.serve("/kev.json", c.serve)
		e.setNow(e.clock().Add(48 * time.Hour))
		_, b := e.fetch("cisa-kev")
		if at(b, "status") != "error" || !strings.Contains(at(b, "error").(string), c.want) || at(b, "records") != 3.0 {
			t.Errorf("%s: %v", c.name, b)
		}
		if n := rowsOf(t, e.db, "feeds_vuln"); n != 3 {
			t.Errorf("%s: %d vulnerabilities left", c.name, n)
		}
	}
}

func TestCustomFeedPullsWithItsSecretAndTheEditorsRules(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only()
	var auth string
	o.serve("/c2.csv", func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("dst_ip\n185.220.101.47\n8.8.4.4\nnot-an-ip\n"))
	})
	body := strings.Replace(customBody, `https://threat-share.example.net/c2.csv`, o.url("/c2.csv"), 1)
	_, b, _ := e.do("POST", "/feeds/custom", "admin", body)
	id := at(b, "id").(string)
	c, f := e.fetch(id)
	if c != 200 || at(f, "status") != "ok" || at(f, "records") != 2.0 || auth != "Bearer s3cretTOKEN-x7Qk" || at(f, "auth", "secret_last4") != "x7Qk" {
		t.Fatalf("%d %v auth=%q", c, f, auth)
	}
	_, s := e.get("/feeds/search?q=8.8.4.4")
	if at(s, "hit", "verdict") != "alert" || at(s, "hit", "category") != "Custom feed" || at(s, "hit", "sources", 0) != "Partner C2 list" {
		t.Errorf("custom IOC: %v", s)
	}
	// a feed whose server rejects the secret: a clear error, no secret in it
	o.serve("/c2.csv", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	e.setNow(e.clock().Add(time.Hour))
	if _, f = e.fetch(id); at(f, "status") != "error" || at(f, "error") != "The source answered HTTP 401." {
		t.Errorf("401: %v", f)
	}
	// a custom vulnerability feed replaces its rows on each pull and takes the date of the first sight
	vbody := `{"name":"Partner CVEs","kind":"vulnerabilities","url":"` + o.url("/v.csv") + `","enabled":true,"interval_hours":24,
"auth":{"type":"none","header_name":null,"username":null},
"parser":{"format":"csv","records_path":"","delimiter":",","has_header":true,"fields":{"cve":{"source":"cve","regex":"","trim":true,"lowercase":false,"date_format":"auto"},
"vendor":{"source":"vendor","regex":"","trim":true,"lowercase":false,"date_format":"auto"}}}}`
	o.serve("/v.csv", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("cve,vendor\nCVE-2026-20001,Acme\nCVE-2026-20002,\n"))
	})
	_, b, _ = e.do("POST", "/feeds/custom", "admin", vbody)
	vid := at(b, "id").(string)
	e.fetch(vid)
	v, found, _ := e.svc.st.VulnByCVE(t.Context(), "CVE-2026-20002")
	if !found || v.Vendor != "Unknown" || v.DateAdded != "2026-11-05" || len(e.pub.named(EventNewKEV)) != 0 {
		t.Errorf("custom vuln: %+v", v)
	}
	o.serve("/v.csv", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("cve,vendor\nCVE-2026-20001,Acme\n"))
	})
	e.setNow(e.clock().Add(time.Hour))
	e.fetch(vid)
	if n := rowsOf(t, e.db, "feeds_vuln"); n != 1 {
		t.Errorf("%d rows after a pull that lists one", n)
	}
	if c, _, _ := e.do("DELETE", "/feeds/custom/"+vid, "admin", ""); c != 204 || rowsOf(t, e.db, "feeds_vuln") != 0 {
		t.Errorf("delete: %d, %d rows", c, rowsOf(t, e.db, "feeds_vuln"))
	}
}

func TestJobsRunOnlyThroughTheScheduler(t *testing.T) {
	t.Parallel()
	e, _ := pullEnv(t)
	js := e.svc.Jobs()
	if len(js) != 1 || js[0].Module != "feeds" || js[0].Name != "pull" || js[0].Every != PullEvery || js[0].Run == nil {
		t.Fatalf("jobs: %+v", js)
	}
	sched := jobs.New(slog.New(slog.DiscardHandler), e.gate, nil)
	if err := sched.Add(js[0]); err != nil {
		t.Fatal(err)
	}
}

// Walk 2026-11-12: the rejected-rows note writes numbers as the GUI does and says why a few rows were dropped.
func TestNote_GroupedCountsAndReason(t *testing.T) {
	got := note(Stats{Accepted: 185937, Rejected: 50, Reasons: []Reason{{Reason: `"…" is not a domain`, Count: 48, Example: `"a b" is not a domain`}, {Reason: "other", Count: 2}}})
	want := `50 of 185,987 rows were rejected. Most often: "a b" is not a domain. A few bad lines in a public list are normal; they are skipped.`
	if got != want {
		t.Fatalf("note = %q, want %q", got, want)
	}
	for n, w := range map[int]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567"} {
		if g := grouped(n); g != w {
			t.Errorf("grouped(%d) = %q, want %q", n, g, w)
		}
	}
	if note(Stats{Accepted: 3}) != "" {
		t.Error("no rejected row: no note")
	}
}

// D-420 (3): the status line of a pull shows one real rejected value of the most common reason (quoted, cut to 40
// UTF-16 units, unprintable runes as spaces), not an ellipsis; the grouped reasons of the API stay masked.
func TestNote_ShowsOneRejectedValue(t *testing.T) {
	in := "8.8.8.8\nbad!" + strings.Repeat("v", 50) + "\nalso!bad\n1.1.1.1\n"
	r, err := ParseFeed(t.Context(), []byte(in), KindIOC, DefaultParser(KindIOC, FormatLines))
	if err != nil {
		t.Fatal(err)
	}
	got := note(r.Stats)
	if !strings.Contains(got, `Most often: indicator: "bad!`+strings.Repeat("v", 36)+`" is not a valid indicator.`) {
		t.Errorf("note = %q", got)
	}
	if !strings.Contains(r.Reasons[0].Reason, `"…"`) || strings.Contains(r.Reasons[0].Reason, "bad") {
		t.Errorf("grouped reason must stay masked: %q", r.Reasons[0].Reason)
	}
	all := accepted(Stats{Rejected: r.Rejected, Reasons: r.Reasons})
	if all == nil || !strings.Contains(all.Error(), `"bad!vvv`) {
		t.Errorf("all rejected: %v", all)
	}
}
