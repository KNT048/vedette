package feeds

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// cisa.gov answers 403 to Vietnamese addresses. Both copies of the CISA list are asked every check;
// /feeds/status says which copy the newest list came from and what each copy said, a failure of both is said with both reasons, and
// the admins get one alert when both copies fail or the list is six checks old, and one when it is up to date again.

// kevStatus is GET /feeds/status's kev block and its first source.
func (e *env) kevStatus() (kev map[string]any, srcURL string) {
	e.t.Helper()
	c, b := e.get("/feeds/status")
	if c != 200 {
		e.t.Fatalf("status: %d %v", c, b)
	}
	kev, _ = b["kev"].(map[string]any)
	srcURL, _ = at(b, "sources", 0, "url").(string)
	return kev, srcURL
}

// /feeds/status: the copy the newest list came from (and its address as the source), and each copy's last result.
func TestKEVCopies_StatusSaysTheNewestCopyAndEachCopysResult(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	e.fetch("cisa-kev")
	k, src := e.kevStatus()
	if k["answered_by"] != AnsweredMirror || src != o.url(mirrorPath) {
		t.Errorf("newest from %v, source %q", k["answered_by"], src)
	}
	copies, _ := k["copies"].([]any)
	if len(copies) != 2 || at(copies, 0, "name") != AnsweredCISA || at(copies, 0, "error") != "cisa.gov refused this box (HTTP 403)" ||
		at(copies, 0, "catalog_version") != nil || at(copies, 1, "name") != AnsweredMirror || at(copies, 1, "error") != nil ||
		at(copies, 1, "catalog_version") != "2026.11.04" || at(copies, 1, "checked_at") != "2026-11-05T12:00:00Z" {
		t.Errorf("copies = %v", copies)
	}
	if k["error"] != nil {
		t.Errorf("one copy failing is not a failed check: %v", k["error"])
	}
	// cisa.gov answers again with the same catalog: of two equal catalogs cisa.gov's is kept (#946 r1: deterministic)
	o.body(primaryPath, `"p1"`, testFile(t, "kev.json"))
	e.setNow(e.clock().Add(time.Hour))
	e.fetch("cisa-kev")
	k, _ = e.kevStatus()
	copies, _ = k["copies"].([]any)
	if at(copies, 0, "error") != nil || at(copies, 0, "catalog_version") != "2026.11.04" || k["answered_by"] != AnsweredCISA {
		t.Errorf("after cisa.gov came back: %v, newest from %v", copies, k["answered_by"])
	}
}

// fakeNet answers some hosts with a dial failure and sends the rest to the origin on loopback.
type fakeNet map[string]error

func (f fakeNet) RoundTrip(r *http.Request) (*http.Response, error) {
	if err, ok := f[r.URL.Hostname()]; ok {
		return nil, err
	}
	r = r.Clone(r.Context())
	if r.URL.Hostname() == originHost {
		r.URL.Host = net.JoinHostPort("127.0.0.1", r.URL.Port())
	}
	return http.DefaultTransport.RoundTrip(r)
}

// A cisa.gov the box cannot get to at all (blocked at the host or the network) is said in plain words, and the GitHub copy's list is
// used (as on a test box that blocked cisa.gov for one cycle).
func TestKEVCopies_CISAUnreachedIsSaidAndTheCopyAnswers(t *testing.T) {
	t.Parallel()
	// every failure is the dial error the network gives, never a real closed port: a port closed here can be taken at once by another
	// test's server, which then answers instead
	dial := func(err error) error { return &net.OpError{Op: "dial", Net: "tcp", Err: err} }
	for name, c := range map[string]struct {
		primary string
		why     string
	}{
		"refused":   {"http://closed.lan/kev.json", "cisa.gov refused the connection"},
		"no name":   {"http://nxdomain.lan/kev.json", "cisa.gov did not resolve on this box"},
		"sinkholed": {"http://sinkhole.lan/kev.json", "cisa.gov resolved to an address Vedette does not connect to"},
		"reset":     {"http://reset.lan/kev.json", "cisa.gov cut the connection"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnvFetcher(t, Fetcher{Client: &http.Client{Transport: fakeNet{
				"closed.lan":   dial(syscall.ECONNREFUSED),
				"nxdomain.lan": dial(&net.DNSError{Err: "no such host", Name: "nxdomain.lan", IsNotFound: true}),
				"sinkhole.lan": fmt.Errorf("feeds: dial: %w", ErrOwnAddress),
				"reset.lan":    dial(syscall.ECONNRESET),
			}}, Version: "test"})
			o := newOrigin(t)
			e.only("cisa-kev")
			e.svc.KEVPrimary, e.svc.KEVFallback = c.primary, o.url(mirrorPath)
			e.mirror("cisa-kev", c.primary)
			o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
			if code, b := e.fetch("cisa-kev"); code != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredMirror ||
				!strings.HasPrefix(at(b, "error").(string), c.why+"; the other copy answered.") {
				t.Fatalf("%d %v %v %v", code, at(b, "status"), at(b, "answered_by"), at(b, "error"))
			}
		})
	}
}

func TestKEVCopies_CopyWhyNamesTheCopyNeverTheAddress(t *testing.T) {
	t.Parallel()
	for err, want := range map[error]string{
		&StatusError{Code: 403}:                             "cisa.gov refused this box (HTTP 403)",
		&StatusError{Code: 502}:                             "cisa.gov answered HTTP 502",
		context.DeadlineExceeded:                            "cisa.gov did not answer in time",
		&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}: "cisa.gov could not be reached from this box",
		fail(ErrBadSample, "The catalog has no list."):      "cisa.gov: The catalog has no list",
		errors.New("boom"):                                  "cisa.gov: Could not reach www.cisa.gov",
	} {
		if got := copyWhy("cisa.gov", err, "https://www.cisa.gov/x.json"); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
}

// Both down after the list had loaded: /feeds/status says why, with both reasons (the GitHub copy's own too), when it last tried and
// since when the list is stale; that is what Home's card prints.
func TestKEVCopies_BothDownIsSaidWithBothReasonsAndSinceWhen(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	e.fetch("cisa-kev")
	good := e.clock()
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	e.setNow(good.Add(3 * time.Hour))
	if _, b := e.fetch("cisa-kev"); at(b, "status") != "error" {
		t.Fatalf("both down: %v", b)
	}
	k, _ := e.kevStatus()
	if k["state"] != "loaded" || k["error"] != "cisa.gov refused this box (HTTP 403), and CISA's GitHub copy answered HTTP 502" ||
		k["last_success"] != good.Format(time.RFC3339) || k["checked_at"] != good.Add(3*time.Hour).Format(time.RFC3339) {
		t.Errorf("kev = %v", k)
	}
	copies, _ := k["copies"].([]any)
	if at(copies, 1, "error") != "CISA's GitHub copy answered HTTP 502" || at(copies, 1, "catalog_version") != "2026.11.04" {
		t.Errorf("the GitHub copy's own result: %v", copies)
	}
}

// alerts records what the watch sent.
type alerts struct {
	mu   sync.Mutex
	sent []string // "id: title"
	text []string
	crit []bool
	off  bool
}

func (a *alerts) send(_ context.Context, id, title, text string, critical bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.off {
		return fmt.Errorf("notify: %w", ErrAlertOff)
	}
	a.sent, a.text, a.crit = append(a.sent, id+": "+title), append(a.text, text), append(a.crit, critical)
	return nil
}

func (a *alerts) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.sent...)
}

// tick runs the pull job at now+d on the given service.
func (e *env) tick(s *Service, d time.Duration) {
	e.t.Helper()
	e.setNow(e.clock().Add(d))
	if _, err := e.sched.Tick(e.t.Context()); err != nil { // the schedules that came due by now
		e.t.Fatal(err)
	}
	if err := s.RunPull(e.t.Context()); err != nil {
		e.t.Fatal(err)
	}
}

// Both copies failing: quiet after one such check, one alert after two in a row, no repeat, one "up to date again", and a restart repeats neither.
func TestContract_BothFailingAlertsOnceResolvesOnceAcrossRestarts(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	a := &alerts{}
	e.svc.Alert = a.send
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	e.tick(e.svc, 0) // the GitHub copy answers: a good pull at 12:00
	if len(a.list()) != 0 {
		t.Fatalf("one copy failing alerted: %v", a.list())
	}
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	e.tick(e.svc, time.Hour) // both fail once: a blip of the box's own network stays quiet
	if f := e.feed("cisa-kev"); f.Status != "error" || f.Failures != 1 || len(a.list()) != 0 {
		t.Fatalf("one both-failed check: status %v, failures %d, alerts %v", f.Status, f.Failures, a.list())
	}
	e.tick(e.svc, time.Hour) // both fail again: the second check in a row
	if f := e.feed("cisa-kev"); f.Failures != 2 {
		t.Fatalf("the second check did not run: failures %d", f.Failures)
	}
	got := a.list()
	if len(got) != 1 || !strings.HasPrefix(got[0], "feeds-kev-stale-") || !strings.Contains(got[0], "cannot update the list") {
		t.Fatalf("both failing: %v", got)
	}
	if !a.crit[0] {
		t.Error("the alert is not critical: a critical-only channel would never get it")
	}
	if txt := a.text[0]; !strings.Contains(txt, "The check at 5 Nov 2026, 14:00 UTC failed: cisa.gov refused this box (HTTP 403), and CISA's GitHub copy answered HTTP 502") ||
		!strings.Contains(txt, "last good pull, at 5 Nov 2026, 12:00 UTC") {
		t.Errorf("alert text: %q", txt)
	}
	for range 7 { // still failing, past six hours too: nothing more
		e.tick(e.svc, time.Hour)
	}
	restarted, err := NewService(e.svc.Deps) // a restart: a new service on the same database remembers the alert
	if err != nil {
		t.Fatal(err)
	}
	e.tick(restarted, time.Hour)
	if got := a.list(); len(got) != 1 {
		t.Fatalf("repeated: %v", got)
	}
	o.body(mirrorPath, `"m2"`, testFile(t, "kev.json")) // the GitHub copy answers again
	if err := restarted.Fetch(t.Context(), "cisa-kev"); err != nil {
		t.Fatal(err)
	}
	e.tick(restarted, time.Minute)
	got = a.list()
	if len(got) != 2 || !strings.HasPrefix(got[1], "feeds-kev-fresh-") || !strings.Contains(got[1], "up to date again") {
		t.Fatalf("after the recovery: %v", got)
	}
	if a.crit[1] || !strings.Contains(a.text[1], "the newest list on the box came from CISA's GitHub copy") {
		t.Errorf("fresh text: %q", a.text[1])
	}
	again, err := NewService(e.svc.Deps)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		e.tick(again, time.Hour)
	}
	if got := a.list(); len(got) != 2 {
		t.Errorf("after the recovery and a restart: %v", got)
	}
}

// One copy failing for a day is a note, never an alert.
func TestContract_OneCopyFailingNeverAlerts(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	a := &alerts{}
	e.svc.Alert = a.send
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	for range 24 {
		e.tick(e.svc, time.Hour)
	}
	if len(a.list()) != 0 {
		t.Errorf("one copy failing alerted: %v", a.list())
	}
	if f := e.feed("cisa-kev"); f.Status != "ok" || f.Error == nil || !strings.Contains(*f.Error, "cisa.gov refused this box (HTTP 403)") {
		t.Errorf("the note on the feed: %v %v", f.Status, f.Error)
	}
}

// A list at an admin's own address has the six-check rule only: quiet for under six hours of failures, one alert at six. Notify off:
// nothing recorded as sent, the alert goes out at the first tick notify takes it. A list turned off: no alert, and turning it on counts
// the six checks from then.
func TestContract_SixChecksNotifyOffAndAListTurnedOff(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	a := &alerts{off: true}
	e.svc.Alert = a.send
	o.body("/own.json", `"o1"`, testFile(t, "kev.json"))
	e.mirror("cisa-kev", o.url("/own.json"))
	e.tick(e.svc, 0) // a good pull at 12:00
	o.serve("/own.json", func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	for range 11 {
		e.tick(e.svc, 30*time.Minute)
	}
	e.tick(e.svc, 30*time.Minute) // six hours, but notify is off
	if len(a.list()) != 0 {
		t.Fatal("sent while notify was off (or before six hours)")
	}
	a.mu.Lock()
	a.off = false
	a.mu.Unlock()
	e.tick(e.svc, 5*time.Minute)
	if got := a.list(); len(got) != 1 || !strings.Contains(a.text[0], "last good pull, at 5 Nov 2026, 12:00 UTC") ||
		!strings.Contains(a.text[0], "reach "+originHost+", the address set for this list") || strings.Contains(a.text[0], "www.cisa.gov") {
		t.Fatalf("after notify came back: %v %v", got, a.text)
	}

	e2, o2 := kevEnv(t)
	a2 := &alerts{}
	e2.svc.Alert = a2.send
	o2.serve("/own.json", func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	e2.mirror("cisa-kev", o2.url("/own.json"))
	e2.tick(e2.svc, 0)
	if c, b := e2.put("cisa-kev", `{"enabled":false}`); c != 200 {
		t.Fatalf("turn off: %d %v", c, b)
	}
	e2.tick(e2.svc, 7*time.Hour)
	if len(a2.list()) != 0 {
		t.Fatal("alerted about a list that is off")
	}
	if c, b := e2.put("cisa-kev", `{"enabled":true}`); c != 200 {
		t.Fatalf("turn on: %d %v", c, b)
	}
	e2.tick(e2.svc, 5*time.Minute) // on again: the six checks count from now
	e2.tick(e2.svc, 5*time.Hour)
	if len(a2.list()) != 0 {
		t.Fatalf("alerted within six hours of turning it on: %v", a2.list())
	}
	e2.tick(e2.svc, time.Hour)
	if len(a2.list()) != 1 {
		t.Fatalf("six hours after turning it on: %v", a2.list())
	}
}
