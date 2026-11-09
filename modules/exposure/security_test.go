package exposure

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Tests of the security review of the backend (H1, M1, L1 to L4, L6). The names say which item they pin.

// listener counts the connections made to it and closes them at once. It stands in for a proxy.
func listener(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted = new(atomic.Int32)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), accepted
}

var invalidServices = []string{"https://a.invalid", "https://b.invalid", "https://c.invalid"}

// H1: a customer's HTTPS_PROXY (Zscaler and the like) must not decide the box's public IP: all three services
// would agree on the proxy vendor's address and the box would verify, then scan, somebody else's IP.
func TestProbe_IgnoresProxyEnvironment(t *testing.T) { // not parallel: it sets the environment
	addr, accepted := listener(t)
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"} {
		t.Setenv(k, "http://"+addr)
	}
	p, err := NewPublicServiceProber(invalidServices, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if tr, ok := p.client.Transport.(*http.Transport); !ok || tr.Proxy != nil {
		t.Fatalf("the transport still has a proxy function: %+v", p.client.Transport)
	}
	if _, err := p.Round(t.Context()); err == nil {
		t.Fatal("a round over unresolvable names gave an address")
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections went to the proxy", n)
	}
}

func TestProbe_ProxyOfAPassedTransportIsCleared(t *testing.T) {
	t.Parallel()
	addr, accepted := listener(t)
	u, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPublicServiceProber(invalidServices, &http.Transport{Proxy: http.ProxyURL(u)}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if tr := p.client.Transport.(*http.Transport); tr.Proxy != nil || !tr.DisableKeepAlives {
		t.Fatalf("transport = proxy %v, keep-alives off %v", tr.Proxy != nil, tr.DisableKeepAlives)
	}
	_, _ = p.Round(t.Context())
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections went to the proxy", n)
	}
}

// M1: two of the three services on one host would be one vote cast twice.
func TestProbe_ConstructorRejectsTwoServicesOnOneHost(t *testing.T) {
	t.Parallel()
	for _, urls := range [][]string{
		{"https://a.example/x", "https://a.example/y", "https://c.example"},
		{"https://a.example", "https://A.EXAMPLE:8443/ip", "https://c.example"},
		{"https://a.example", "https://c.example", "https://c.example"},
	} {
		if _, err := NewPublicServiceProber(urls, nil, 0); err == nil {
			t.Errorf("%v accepted", urls)
		}
	}
	if _, err := NewPublicServiceProber([]string{"https://a.example", "https://b.example", "https://c.example"}, nil, 0); err != nil {
		t.Fatal(err)
	}
}

// L2: a request that carries nothing identifying: Go's own User-Agent, not the name of the product.
func TestProbe_SendsNoIdentifyingHeader(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var agents []string
	h := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		agents = append(agents, r.UserAgent())
		mu.Unlock()
		_, _ = w.Write([]byte(ipA))
	}
	p := prober(t, 0, newFakeService(t, h), newFakeService(t, h), newFakeService(t, h))
	if _, err := round(t, p); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(agents) != 3 {
		t.Fatalf("%d requests", len(agents))
	}
	for _, a := range agents {
		if !strings.HasPrefix(a, "Go-http-client/") || strings.Contains(strings.ToLower(a), "vedette") {
			t.Errorf("User-Agent = %q", a)
		}
	}
}

// L6: the voting rule, for every combination of three answers (an address, another, a third, or no answer).
func TestProbe_RoundVotingProperty(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var say [3]string
	svc := func(i int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			a := say[i]
			mu.Unlock()
			if a == "" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(a))
		}
	}
	p := prober(t, 0, newFakeService(t, svc(0)), newFakeService(t, svc(1)), newFakeService(t, svc(2)))
	choices := []string{ipA, ipB, ipC, ""}
	for _, x := range choices {
		for _, y := range choices {
			for _, z := range choices {
				mu.Lock()
				say = [3]string{x, y, z}
				mu.Unlock()
				votes := map[string]int{}
				answered := 0
				for _, a := range []string{x, y, z} {
					if a != "" {
						votes[a]++
						answered++
					}
				}
				want := ""
				for a, n := range votes {
					if n >= 2 {
						want = a
					}
				}
				got, err := round(t, p)
				switch {
				case want != "":
					if err != nil || got.String() != want {
						t.Fatalf("%q %q %q: got %v %v, want %s", x, y, z, got, err, want)
					}
				case answered == 0:
					if !errors.Is(err, ErrServicesDown) {
						t.Fatalf("%q %q %q: got %v %v, want services down", x, y, z, got, err)
					}
				default:
					if got.IsValid() || !errors.Is(err, ErrNoAgreement) {
						t.Fatalf("%q %q %q: got %v %v, want no agreement", x, y, z, got, err)
					}
				}
			}
		}
	}
}

func (e *env) ipTargets() []TargetView {
	e.t.Helper()
	all, err := e.svc.Targets(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	var out []TargetView
	for _, v := range all {
		if v.Kind == KindIP {
			out = append(out, v)
		}
	}
	return out
}

// L1: the clock was ahead (a wrong RTC, then NTP corrected it). A time stored in the future must not keep an IP
// valid for longer than 30 days, and must not stop the job.
func TestContract_INV4_ClockThatWasAhead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prober.set(ipA)
	e.clock.now = t0.Add(365 * day)
	e.runJob() // the box saw the IP "a year from now"
	e.clock.now = t0
	ip := e.ipTargets()[0]
	exp, err := parseTS(str(ip.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	if exp.After(t0.Add(30*day + 5*time.Minute)) {
		t.Fatalf("expires %s, more than 30 days from now", exp)
	}
	calls := e.prober.count()
	e.runJob() // last_run lies in the future: the check is due
	if e.prober.count() == calls {
		t.Fatal("the job did not run with a stored time in the future")
	}
	if b := e.settings(); b.LastRun == nil || b.LastRun.At != "2026-11-09T10:00:00.000Z" {
		t.Fatalf("last run = %+v", b.LastRun)
	}
	// seen again by the corrected clock: the stored sighting is now, so validity follows the real time
	ip = e.ipTargets()[0]
	if str(ip.VerifiedAt) != "2026-11-09T10:00:00.000Z" {
		t.Fatalf("verified_at = %s", str(ip.VerifiedAt))
	}
}

// L3: the audit trail records changes, not every run (last_run covers the routine ones).
func TestContract_INV11_AuditOnlyChanges(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prober.set(ipA)
	e.runJob() // the first run adds an IP: a change
	steady := func(label string, runs int) {
		t.Helper()
		before := len(e.audits())
		for range runs {
			e.advance(time.Hour)
			e.runJob()
		}
		if got := len(e.audits()) - before; got != 0 {
			t.Fatalf("%s: %d audit rows for %d routine runs: %v", label, got, runs, e.audits()[before:])
		}
	}
	steady("same IP seen again", 5)

	count := func(action string) int {
		n := 0
		for _, a := range e.audits() {
			if a.Action == action {
				n++
			}
		}
		return n
	}
	// ok -> fail is one row; staying down adds none; fail -> ok is one row
	e.prober.offline()
	e.advance(time.Hour)
	before := count("exposure.auto_detect")
	e.runJob()
	if count("exposure.auto_detect") != before+1 {
		t.Fatalf("ok to fail: %v", e.audits())
	}
	steady("services stay down", 4)
	e.prober.set(ipA)
	e.advance(time.Hour)
	before = count("exposure.auto_detect")
	e.runJob()
	if count("exposure.auto_detect") != before+1 {
		t.Fatalf("fail to ok: %v", e.audits())
	}
	steady("up again", 3)

	// an IP that had expired and is seen again is a change
	e.prober.offline()
	e.advance(31 * day)
	e.runJob()
	e.prober.set(ipA)
	e.advance(time.Hour)
	e.runJob()
	if count("exposure.verify_renew") != 1 {
		t.Fatalf("the renewal of an expired IP: %v", e.audits())
	}
	// a person's click is always one audited action
	before = len(e.audits())
	e.detect(ipA)
	if len(e.audits()) == before {
		t.Fatal("Detect now left no audit row")
	}
}

func TestContract_INV11_RefusedAddressIsAuditedOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.prober.set("10.1.2.3")
	for range 6 {
		e.runJob()
		e.advance(time.Hour)
	}
	var fails int
	for _, a := range e.audits() {
		if a.Action == "exposure.verify_fail" && a.User == SystemUser {
			fails++
		}
	}
	if fails != 1 {
		t.Fatalf("%d verify_fail rows for 6 runs: %v", fails, e.audits())
	}
	if slices.Contains(e.ipValues(), "10.1.2.3") {
		t.Fatal("a private address was stored")
	}
}

// L4: verifying an IP probes the network and writes the same rows as a detection, so it waits for one in progress.
func TestVerifyOfAnIPWaitsForTheDetectionInProgress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := e.detect(ipA)[0]
	calls := e.prober.count()
	e.svc.detectMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := e.svc.Verify(e.ctx(), "operator@acme.example", ip.ID)
		done <- err
	}()
	select {
	case err := <-done:
		e.svc.detectMu.Unlock()
		t.Fatalf("Verify did not wait for the detection lock (err %v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	if e.prober.count() != calls {
		t.Fatal("Verify probed while a detection held the lock")
	}
	e.svc.detectMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e.prober.count() == calls {
		t.Fatal("Verify never probed")
	}
}
