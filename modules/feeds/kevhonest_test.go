package feeds

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// kien G13 (D-629): cisa.gov answers 403 to Vietnamese addresses, and the box reads CISA's GitHub copy (D-91). Home says which copy
// answered and why, /feeds/status names the copy that answered, a failure of both is said with both reasons, and the admins get one
// alert after six missed checks and one when the list is up to date again.

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

// The answer and its why stay true across the switch back and forth (supervisor, N100 2026-11-17): mirror, then CISA asked without
// validators, then CISA's 304, then the mirror again (a 304 on its own validators).
func TestG13_AnsweredByStaysTrueAcrossTheSwitch(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	kev := testFile(t, "kev.json")
	cisaUp := false
	var mu sync.Mutex
	o.serve(primaryPath, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		up := cisaUp
		mu.Unlock()
		if !up {
			answer(w, http.StatusForbidden)
			return
		}
		if r.Header.Get("If-None-Match") == `W/"c1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `W/"c1"`)
		_, _ = w.Write([]byte(kev))
	})
	o.body(mirrorPath, `"m1"`, kev)
	step := func(name, by string, why any, url string) {
		t.Helper()
		e.setNow(e.clock().Add(time.Hour))
		if c, b := e.fetch("cisa-kev"); c != 200 || at(b, "status") != "ok" || at(b, "answered_by") != by {
			t.Fatalf("%s: %d %v %v %v", name, c, at(b, "status"), at(b, "answered_by"), at(b, "error"))
		}
		k, src := e.kevStatus()
		if k["answered_by"] != by || k["answered_why"] != why || src != url {
			t.Errorf("%s: answered_by %v, why %v, source %q", name, k["answered_by"], k["answered_why"], src)
		}
	}
	step("cisa.gov refuses", AnsweredMirror, "cisa.gov refused this box (HTTP 403)", o.url(mirrorPath))
	mu.Lock()
	cisaUp = true
	mu.Unlock()
	step("cisa.gov answers again", AnsweredCISA, nil, o.url(primaryPath))
	step("cisa.gov: no change", AnsweredCISA, nil, o.url(primaryPath))
	mu.Lock()
	cisaUp = false
	mu.Unlock()
	step("cisa.gov refuses again", AnsweredMirror, "cisa.gov refused this box (HTTP 403)", o.url(mirrorPath))

	var cisaAsks, mirrorAsks []string
	for _, h := range o.all() {
		switch h.path {
		case primaryPath:
			cisaAsks = append(cisaAsks, h.header.Get("If-None-Match"))
		case mirrorPath:
			mirrorAsks = append(mirrorAsks, h.header.Get("If-None-Match"))
		}
	}
	// CISA: refused (plain), asked without validators after the mirror held it, then conditional (304), then conditional and refused
	if got := strings.Join(cisaAsks, "|"); got != `||W/"c1"|W/"c1"` {
		t.Errorf("CISA asked with %q", got)
	}
	if got := strings.Join(mirrorAsks, "|"); got != `|"m1"` { // never CISA's validators; the second time a 304
		t.Errorf("the mirror asked with %q", got)
	}
}

// fakeNet answers some hosts with a dial failure and sends the rest to the origin on loopback.
type fakeNet map[string]error

func (f fakeNet) RoundTrip(r *http.Request) (*http.Response, error) {
	if err, ok := f[r.URL.Hostname()]; ok {
		return nil, err
	}
	r = r.Clone(r.Context())
	if h := r.URL.Hostname(); h == originHost || h == "closed.lan" { // closed.lan: a loopback port nobody listens on
		r.URL.Host = net.JoinHostPort("127.0.0.1", r.URL.Port())
	}
	return http.DefaultTransport.RoundTrip(r)
}

// A cisa.gov the box cannot get to at all (blocked at the host or the network: refused, name not resolved, sinkholed to an address the
// dialer refuses) is fallback-worthy too, not only a 403 (supervisor: the N100 done check blocks cisa.gov for one cycle).
func TestG13_CISAUnreachedFallsBackToTheMirror(t *testing.T) {
	t.Parallel()
	// a real refused connection: a loopback port nobody listens on
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://closed.lan:" + fmt.Sprint(ln.Addr().(*net.TCPAddr).Port) + "/kev.json"
	_ = ln.Close()
	dial := func(err error) error { return &net.OpError{Op: "dial", Net: "tcp", Err: err} }
	for name, c := range map[string]struct {
		primary string
		why     string
	}{
		"refused":   {closed, "cisa.gov refused the connection"},
		"no name":   {"http://nxdomain.lan/kev.json", "cisa.gov did not resolve on this box"},
		"sinkholed": {"http://sinkhole.lan/kev.json", "cisa.gov resolved to an address Vedette does not connect to"},
		"reset":     {"http://reset.lan/kev.json", "cisa.gov cut the connection"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnvFetcher(t, Fetcher{Client: &http.Client{Transport: fakeNet{
				"nxdomain.lan": dial(&net.DNSError{Err: "no such host", Name: "nxdomain.lan", IsNotFound: true}),
				"sinkhole.lan": fmt.Errorf("feeds: dial: %w", ErrOwnAddress),
				"reset.lan":    dial(syscall.ECONNRESET),
			}}, Version: "test"})
			o := newOrigin(t)
			e.only("cisa-kev")
			e.svc.KEVPrimary, e.svc.KEVFallback = c.primary, o.url(mirrorPath)
			e.mirror("cisa-kev", c.primary)
			o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
			if code, b := e.fetch("cisa-kev"); code != 200 || at(b, "status") != "ok" || at(b, "answered_by") != AnsweredMirror {
				t.Fatalf("%d %v %v %v", code, at(b, "status"), at(b, "answered_by"), at(b, "error"))
			}
			if k, _ := e.kevStatus(); k["answered_why"] != c.why {
				t.Errorf("why = %v, want %q", k["answered_why"], c.why)
			}
		})
	}
}

func TestG13_UnreachedErrorsAreFallbackWorthy(t *testing.T) {
	t.Parallel()
	wrap := func(err error) error {
		return &url.Error{Op: "Get", URL: "https://www.cisa.gov/x", Err: &net.OpError{Op: "dial", Net: "tcp", Err: err}}
	}
	for name, err := range map[string]error{
		"refused":      wrap(&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}),
		"reset":        wrap(syscall.ECONNRESET),
		"host unreach": wrap(syscall.EHOSTUNREACH),
		"net unreach":  wrap(syscall.ENETUNREACH),
		"dns":          wrap(&net.DNSError{Err: "no such host", Name: "www.cisa.gov", IsNotFound: true}),
		"sinkhole":     fmt.Errorf("feeds: fetch www.cisa.gov: %w", ErrOwnAddress),
		"blocked":      fmt.Errorf("feeds: fetch www.cisa.gov: %w", ErrBlockedAddress),
	} {
		if !fallbackWorthy(err) {
			t.Errorf("%s is not fallback-worthy", name)
		}
	}
	if fallbackWorthy(&StatusError{Code: 404}) || fallbackWorthy(ErrRedirect) || fallbackWorthy(errors.New("boom")) {
		t.Error("a broken address falls back")
	}
}

// Both down after the list had loaded: /feeds/status says why, with both reasons (the mirror's own too), when it last tried and since
// when the list is stale; that is what Home's card prints.
func TestG13_BothDownIsSaidWithBothReasonsAndSinceWhen(t *testing.T) {
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
	if k["state"] != "loaded" || k["error"] != "cisa.gov refused this box (HTTP 403), and CISA's GitHub copy failed too (HTTP 502)" ||
		k["last_success"] != good.Format(time.RFC3339) || k["checked_at"] != good.Add(3*time.Hour).Format(time.RFC3339) {
		t.Errorf("kev = %v", k)
	}
}

// alerts records what the stale watch sent.
type alerts struct {
	mu   sync.Mutex
	sent []string // "id: title"
	text []string
	off  bool
}

func (a *alerts) send(_ context.Context, id, title, text string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.off {
		return fmt.Errorf("notify: %w", ErrAlertOff)
	}
	a.sent, a.text = append(a.sent, id+": "+title), append(a.text, text)
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
	if err := s.RunPull(e.t.Context()); err != nil {
		e.t.Fatal(err)
	}
}

// One alert after six missed hourly checks, none in between, one "up to date again", and a restart repeats neither (D-629).
func TestContract_D629_StaleAlertOnceResolvedOnceAcrossRestarts(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	a := &alerts{}
	e.svc.Alert = a.send
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json"))
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	e.tick(e.svc, 0) // the mirror answers: a good pull at 12:00
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	for range 11 { // 5 h 30 min of failing checks: quiet
		e.tick(e.svc, 30*time.Minute)
	}
	if got := a.list(); len(got) != 0 {
		t.Fatalf("alerted during a short outage: %v", got)
	}
	e.tick(e.svc, 30*time.Minute) // six hours
	if got := a.list(); len(got) != 1 || !strings.HasPrefix(got[0], "feeds-kev-stale-") || !strings.Contains(got[0], "cannot update the list") {
		t.Fatalf("after six hours: %v", got)
	}
	if txt := a.text[0]; !strings.Contains(txt, "since 5 Nov 2026, 12:00 UTC") || !strings.Contains(txt, "failed too (HTTP 502)") {
		t.Errorf("stale text: %q", txt)
	}
	for range 4 {
		e.tick(e.svc, time.Hour)
	}
	// a restart: a new service on the same database remembers the alert
	restarted, err := NewService(e.svc.Deps)
	if err != nil {
		t.Fatal(err)
	}
	e.tick(restarted, time.Hour)
	if got := a.list(); len(got) != 1 {
		t.Fatalf("repeated: %v", got)
	}
	o.body(mirrorPath, `"m1"`, testFile(t, "kev.json")) // the copy answers again
	if err := restarted.Fetch(t.Context(), "cisa-kev"); err != nil {
		t.Fatal(err)
	}
	e.tick(restarted, time.Minute)
	got := a.list()
	if len(got) != 2 || !strings.HasPrefix(got[1], "feeds-kev-fresh-") || !strings.Contains(got[1], "up to date again") {
		t.Fatalf("after the recovery: %v", got)
	}
	if !strings.Contains(a.text[1], "from CISA's GitHub copy, because cisa.gov refused this box (HTTP 403)") {
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

// Notify off: nothing recorded as sent, the alert goes out at the first tick notify takes it. A list turned off: no alert at all, and
// turning it on counts the six checks from then.
func TestContract_D629_NotifyOffWaitsAndAListTurnedOffIsQuiet(t *testing.T) {
	t.Parallel()
	e, o := kevEnv(t)
	a := &alerts{off: true}
	e.svc.Alert = a.send
	o.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
	e.tick(e.svc, 0)
	e.tick(e.svc, 6*time.Hour) // never pulled for six hours, but notify is off
	if len(a.list()) != 0 {
		t.Fatal("sent while notify was off")
	}
	a.mu.Lock()
	a.off = false
	a.mu.Unlock()
	e.tick(e.svc, 5*time.Minute)
	if got := a.list(); len(got) != 1 {
		t.Fatalf("after notify came back: %v", got)
	}

	e2, o2 := kevEnv(t)
	a2 := &alerts{}
	e2.svc.Alert = a2.send
	o2.serve(primaryPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusForbidden) })
	o2.serve(mirrorPath, func(w http.ResponseWriter, _ *http.Request) { answer(w, http.StatusBadGateway) })
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
	e2.tick(e2.svc, 5*time.Minute) // on again: the six checks count from now, not from the first look
	e2.tick(e2.svc, 5*time.Hour)
	if len(a2.list()) != 0 {
		t.Fatalf("alerted within six hours of turning it on: %v", a2.list())
	}
	e2.tick(e2.svc, time.Hour)
	if len(a2.list()) != 1 {
		t.Fatalf("six hours after turning it on: %v", a2.list())
	}
}
