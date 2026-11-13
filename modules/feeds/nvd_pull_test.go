package feeds

import (
	"fmt"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
)

// nvdBody is one ?hasKev answer: the records CVE-2024-<start>… of total.
func nvdBody(start, total int) string {
	var recs []string
	for i := start; i < min(start+NVDPageSize, total); i++ {
		recs = append(recs, fmt.Sprintf(`{"cve":{"id":"CVE-2024-%04d","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:box:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}`, i))
	}
	return fmt.Sprintf(`{"totalResults":%d,"vulnerabilities":[%s]}`, total, strings.Join(recs, ","))
}

// nvdScript answers each startIndex with the given status codes in turn (the last one repeats; 200 is a page of
// total records) and counts the requests per startIndex.
type nvdScript struct {
	mu    sync.Mutex
	total int
	plan  map[int][]int
	asked map[int]int
	retry string // Retry-After of the busy answers
}

func (n *nvdScript) serve(o *origin) {
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		n.mu.Lock()
		codes := n.plan[start]
		i := min(n.asked[start], len(codes)-1)
		n.asked[start]++
		code := http.StatusOK
		if i >= 0 {
			code = codes[i]
		}
		n.mu.Unlock()
		if code != http.StatusOK {
			if n.retry != "" {
				w.Header().Set("Retry-After", n.retry)
			}
			w.WriteHeader(code)
			return
		}
		_, _ = fmt.Fprint(w, nvdBody(start, n.total))
	})
}

func (n *nvdScript) set(start int, codes ...int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.plan[start] = codes
}

func (n *nvdScript) count(start int) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.asked[start]
}

func nvdEnv(t *testing.T) (*env, *nvdScript) {
	t.Helper()
	e, o := pullEnv(t)
	e.only("nvd-kev")
	e.mirror("nvd-kev", o.url("/nvd"))
	n := &nvdScript{total: 250, plan: map[int][]int{}, asked: map[int]int{}}
	n.serve(o)
	return e, n
}

// W3-1: a busy page is tried again after 6 s, 30 s, 2 min, or NVD's Retry-After when longer; the pull then finishes.
func TestNVDPull_BusyPageIsTriedAgain(t *testing.T) {
	t.Parallel()
	e, n := nvdEnv(t)
	n.retry = "45"
	n.set(100, 503, 503, 200)
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if f := e.feed("nvd-kev"); f.Status != "ok" || f.Records == nil || *f.Records != 250 {
		t.Fatalf("feed = %+v", f)
	}
	if got := e.waited(); !slices.Equal(got, []time.Duration{45 * time.Second, 45 * time.Second}) {
		t.Fatalf("waits %v, want Retry-After 45 s twice (longer than 6 s and 30 s)", got)
	}
	if n.count(100) != 3 || n.count(0) != 1 || n.count(200) != 1 {
		t.Fatalf("requests per page: %v", n.asked)
	}
}

// W3-1: without Retry-After the waits are 6 s, 30 s, 2 min; after the fourth busy answer the pull pauses with the
// pages it has: nothing is written, the feed is not an error, the row says how far it got, and the next pull goes
// on from the next page (page 1 is not asked again).
func TestNVDPull_PausesAndResumesFromTheLastGoodPage(t *testing.T) {
	t.Parallel()
	e, n := nvdEnv(t)
	var failed []events.Event
	e.svc.Events = publishFunc(func(ev events.Event) {
		if ev.Name == EventFetchFailed {
			failed = append(failed, ev)
		}
	})
	n.set(100, 503)
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if got := e.waited(); !slices.Equal(got, []time.Duration{6 * time.Second, 30 * time.Second, 2 * time.Minute}) {
		t.Fatalf("waits %v", got)
	}
	f := e.feed("nvd-kev")
	if f.Status != "never" || f.Failures != 0 || len(failed) != 0 {
		t.Fatalf("a paused first fill is recorded as a failure: %+v, events %v", f, failed)
	}
	if c, _ := e.svc.st.affectedCount(t.Context()); c != 0 {
		t.Fatalf("%d entries written by a pull that did not finish", c)
	}
	c, b := e.fetchList(t, "nvd-kev")
	if c != "never" || !strings.Contains(b, "Loading version ranges from NVD: 1 of 3 pages done. NVD was busy (HTTP 503). Vedette goes on in 5 min.") {
		t.Fatalf("feeds page: %s %q", c, b)
	}
	// the job does not go on before the pause is over, then goes on from record 100
	if err := e.svc.RunPull(t.Context()); err != nil || n.count(100) != 4 {
		t.Fatalf("the job went on before the pause ended: %v %d", err, n.count(100))
	}
	n.set(100, 200)
	e.setNow(e.clock().Add(6 * time.Minute))
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n.count(0) != 1 || n.count(100) != 5 || n.count(200) != 1 {
		t.Fatalf("requests per page: %v", n.asked)
	}
	if f := e.feed("nvd-kev"); f.Status != "ok" || *f.Records != 250 || f.Error != nil {
		t.Fatalf("feed = %+v", f)
	}
	if e.svc.nvdState() != nil {
		t.Fatal("the finished pull is still kept")
	}
}

// A full pull that never finished never deletes: the table keeps its 250 CVEs although the paused pull got only 100
// so far, and the row says the versions are being loaded again, not an error.
func TestNVDPull_UnfinishedFullPullDeletesNothing(t *testing.T) {
	t.Parallel()
	e, n := nvdEnv(t)
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	e.setNow(e.clock().Add((nvdIncrementalDays + 1) * 24 * time.Hour)) // too old for a window: a full pull
	n.set(100, 503)
	if err := e.svc.Fetch(t.Context(), "nvd-kev"); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.svc.st.affectedCount(t.Context()); c != 250 {
		t.Fatalf("entries after an unfinished full pull: %d", c)
	}
	if c, b := e.fetchList(t, "nvd-kev"); c != "ok" || !strings.HasPrefix(b, "Loading version ranges from NVD: 1 of 3 pages done.") {
		t.Fatalf("feeds page: %s %q", c, b)
	}
}

// A first page that never comes is a failure, with what NVD did; review M3: an empty page before the total is one too.
func TestNVDPull_FailuresSayWhy(t *testing.T) {
	t.Parallel()
	e, n := nvdEnv(t)
	n.set(0, 503)
	_ = e.svc.Fetch(t.Context(), "nvd-kev")
	if f := e.feed("nvd-kev"); f.Status != "error" || f.Error == nil || !strings.HasPrefix(*f.Error, "NVD was busy (HTTP 503) for the first page, after every try.") {
		t.Fatalf("feed = %+v %v", f, f.Error)
	}
	if e.svc.nvdState() != nil {
		t.Fatal("a pull without a page is kept to go on from")
	}

	e2, o := pullEnv(t)
	e2.only("nvd-kev")
	e2.mirror("nvd-kev", o.url("/nvd"))
	o.serve("/nvd", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"totalResults":250,"vulnerabilities":[]}`)
	})
	_ = e2.svc.Fetch(t.Context(), "nvd-kev")
	if f := e2.feed("nvd-kev"); f.Status != "error" || f.Error == nil || !strings.Contains(*f.Error, "empty page at record 0 of 250") {
		t.Fatalf("feed = %+v %v", f, f.Error)
	}
	if c, _ := e2.svc.st.affectedCount(t.Context()); c != 0 {
		t.Fatal("an empty answer was stored")
	}
}

// W3-1: one pull at a time. While a pull runs, "Fetch now" answers at once with how far it got, the job skips the
// feed, and a second Fetch joins the running pull: NVD is asked each page once.
func TestNVDPull_OnePullAtATime(t *testing.T) {
	t.Parallel()
	e, o := pullEnv(t)
	e.only("nvd-kev")
	e.mirror("nvd-kev", o.url("/nvd"))
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	o.serve("/nvd", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		_, _ = fmt.Fprint(w, nvdBody(start, 150))
	})
	first := make(chan error, 1)
	go func() { first <- e.svc.Fetch(t.Context(), "nvd-kev") }()
	<-started
	c, b := e.fetch("nvd-kev")
	if c != 200 || at(b, "status") != "never" || at(b, "error") != "Loading version ranges from NVD: page 1." {
		t.Fatalf("Fetch now during a pull: %d %v", c, b)
	}
	if err := e.svc.RunPull(t.Context()); err != nil {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() { second <- e.svc.Fetch(t.Context(), "nvd-kev") }()
	for deadline := time.Now().Add(30 * time.Second); ; runtime.Gosched() { // wait until the second Fetch is waiting
		e.svc.mu.Lock()
		waiting := e.svc.locks["nvd-kev"].refs == 2
		e.svc.mu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second Fetch never waited for the first")
		}
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if n := o.count("/nvd"); n != 2 {
		t.Fatalf("%d requests for 2 pages: a second pull ran", n)
	}
	if f := e.feed("nvd-kev"); f.Status != "ok" || *f.Records != 150 {
		t.Fatalf("feed = %+v", f)
	}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 9, 45, 0, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"": 0, "30": 30 * time.Second, " 120 ": 2 * time.Minute, "-5": 0, "soon": 0, "999999": maxRetryAfter,
		"Fri, 13 Nov 2026 09:46:00 GMT": time.Minute, "Fri, 13 Nov 2026 09:00:00 GMT": 0,
	} {
		if got := retryAfter(v, now); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", v, got, want)
		}
	}
}

// W3-1: NVD may take over 30 s before it answers: its requests wait up to nvdHeaderTimeout (at least 90 s) for the
// headers, on a clone of the guarded transport; the shared client is left as it was.
func TestSlowHeaders(t *testing.T) {
	t.Parallel()
	if nvdHeaderTimeout < 90*time.Second || nvdPageTimeout <= nvdHeaderTimeout {
		t.Fatalf("NVD header timeout %v, page timeout %v", nvdHeaderTimeout, nvdPageTimeout)
	}
	shared := NewClient(0)
	c := *shared
	tr := slowHeaders(&c, nvdHeaderTimeout)
	if tr == nil || tr.ResponseHeaderTimeout != nvdHeaderTimeout || c.Timeout != 0 || tr.DialContext == nil {
		t.Fatalf("clone %+v, client timeout %v", tr, c.Timeout)
	}
	if shared.Transport.(*http.Transport).ResponseHeaderTimeout != 30*time.Second || shared.Timeout != DefaultFetchTimeout {
		t.Fatal("the shared client was changed")
	}
}

// fetchList returns the status and the line of a feed as GET /feeds/sources shows it.
func (e *env) fetchList(t *testing.T, id string) (status, line string) {
	t.Helper()
	c, b := e.get("/feeds/sources")
	if c != 200 {
		t.Fatalf("list %d", c)
	}
	for _, it := range b["items"].([]any) {
		m := it.(map[string]any)
		if m["id"] == id {
			l, _ := m["error"].(string)
			return m["status"].(string), l
		}
	}
	t.Fatalf("%s not listed", id)
	return "", ""
}
