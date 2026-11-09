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
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
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

// ---- H2 (INV-13): an IP the box no longer uses is not scanned ----

const scanModule = "scan@acme.example"

func (e *env) committedIP(ip string) TargetView {
	e.t.Helper()
	var v TargetView
	for _, x := range e.detect(ip) {
		if x.Value == ip {
			v = x
		}
	}
	v, err := e.svc.Commit(e.ctx(), "admin@acme.example", v.ID, true)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *env) scannable(id string) (bool, BlockedReason) {
	e.t.Helper()
	ok, why, err := e.svc.CheckScannable(e.ctx(), scanModule, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return ok, why
}

// A dynamic IP changes (modem reboot) and is given to somebody else. The IP stays in the list for 30 days (kien's rule),
// but the scan-time check, the counterpart of the TXT re-check, refuses it while the box does not use it.
func TestContract_INV13_IPThatIsNoLongerUsedIsNotScanned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	a := e.committedIP(ipA)

	// the box still goes out through it: the check that just ran saw it, so nothing is probed
	calls := e.prober.count()
	if ok, why := e.scannable(a.ID); !ok || why != "" {
		t.Fatalf("a current IP: %v %q", ok, why)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", a.ID); err != nil || e.prober.count() != calls {
		t.Fatalf("scan of a current IP: %v, probes %d", err, e.prober.count()-calls)
	}

	// the modem reboots: the box now exits through B only
	e.advance(time.Minute)
	e.detect(ipB)
	calls = e.prober.count()
	ok, why := e.scannable(a.ID)
	if ok || why != BlockedNotCurrent {
		t.Fatalf("A after the box moved to B: %v %q", ok, why)
	}
	_, err := e.svc.Scan(e.ctx(), "operator@acme.example", a.ID)
	wantAPI(t, err, 409, "ip_not_current")
	var ae *APIError
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, ipA) || !strings.Contains(ae.Message, "last seen 9 Nov 2026, 10:00.") || !strings.Contains(ae.Message, "paused") {
		t.Fatalf("message = %v", err)
	}
	if run.calls != 1 {
		t.Fatal("the runner ran for an IP the box no longer uses")
	}
	if e.prober.count() != calls {
		t.Fatal("a check ran again inside the 5 minutes: the result of the last full check is reused")
	}
	// the 30-day rule is untouched: still in the list, still verified
	if got := e.target(a.ID); got.Status != "verified" || str(got.Validity) != "valid" {
		t.Fatalf("A in the list = %+v", got)
	}

	// after 5 minutes one full check runs (not more than one per 5 minutes), still not seen: refused
	e.advance(6 * time.Minute)
	if ok, why := e.scannable(a.ID); ok || why != BlockedNotCurrent {
		t.Fatalf("A after a fresh check: %v %q", ok, why)
	}
	if got := e.prober.count() - calls; got != DeepRounds {
		t.Fatalf("%d rounds for the scan-time check, want %d", got, DeepRounds)
	}
	for range 3 {
		e.scannable(a.ID)
	}
	if got := e.prober.count() - calls; got != DeepRounds {
		t.Fatalf("%d rounds after repeated asks inside the window", got)
	}
	if n := e.count(`SELECT COUNT(*) FROM exp_attempt`); n != 0 {
		t.Fatalf("the scan-time check used %d of the person's 10 attempts an hour", n)
	}

	// the box goes out through A again: the next check sees it and the scan runs
	e.prober.set(ipA)
	e.advance(6 * time.Minute)
	if ok, why := e.scannable(a.ID); !ok || why != "" {
		t.Fatalf("A after the box came back: %v %q", ok, why)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", a.ID); err != nil {
		t.Fatal(err)
	}
}

// A load balancer gives each new connection one of several IPs: a one-round check sees only one of them, so the scan-time
// check is a full one and both stay scannable.
func TestContract_INV13_LoadBalancedEgressStaysScannable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a := e.committedIP(ipA)
	b := e.committedIP(ipB) // prober alternates A, B, A, B, ...
	e.prober.set(ipA, ipB)
	e.advance(6 * time.Minute)
	calls := e.prober.count()
	for _, id := range []string{a.ID, b.ID} {
		if ok, why := e.scannable(id); !ok || why != "" {
			t.Fatalf("%s: %v %q", id, ok, why)
		}
	}
	if got := e.prober.count() - calls; got != DeepRounds {
		t.Fatalf("%d rounds for two IPs, want one full check (%d)", got, DeepRounds)
	}
}

// A failed probe (no two of three agree, or the services are down) is not a yes.
func TestContract_INV13_FailedProbeRefuses(t *testing.T) {
	t.Parallel()
	for name, set := range map[string]func(*fakeProber){"down": func(p *fakeProber) { p.offline() }, "no agreement": func(p *fakeProber) { p.set("~") }} {
		e := newEnv(t)
		run := &fakeRunner{content: sampleContent()}
		e.svc.SetRunner(run)
		a := e.committedIP(ipA)
		e.advance(6 * time.Minute)
		set(e.prober)
		if ok, why := e.scannable(a.ID); ok || why != BlockedNotCurrent {
			t.Fatalf("%s: %v %q", name, ok, why)
		}
		_, err := e.svc.Scan(e.ctx(), "operator@acme.example", a.ID)
		wantAPI(t, err, 409, "ip_not_current")
		if run.calls != 0 {
			t.Fatalf("%s: the runner ran", name)
		}
	}
}

// An IP that still lacks the commitment is refused for that reason, without a probe.
func TestContract_INV13_NoProbeBeforeTheOtherConditions(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.detect(ipA)[0]
	e.advance(6 * time.Minute)
	calls := e.prober.count()
	if ok, why := e.scannable(v.ID); ok || why != BlockedNoCommitment {
		t.Fatalf("%v %q", ok, why)
	}
	if e.prober.count() != calls {
		t.Fatal("probed for an IP that cannot be scanned anyway")
	}
}

// L5: the TXT re-check before a scan is recorded as the person (or module) that asked, and only when it changes something.
func TestContract_INV1_TXTRecheckIsAttributedAndAuditedOnChange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.committedDomain()
	count := func() (n int, last auditRow) {
		for _, a := range e.audits() {
			if a.Target == v.Value && strings.HasPrefix(a.Detail, "dns_txt, right before a scan") {
				n, last = n+1, a
			}
		}
		return
	}
	for range 4 {
		if ok, _ := e.scannable(v.ID); !ok {
			t.Fatal("not scannable")
		}
	}
	if n, _ := count(); n != 0 {
		t.Fatalf("%d audit rows for 4 re-checks that changed nothing", n)
	}
	e.dns.put(v.Value) // the record is gone
	for range 3 {
		if ok, why := e.scannable(v.ID); ok || why != BlockedTxtMissing {
			t.Fatalf("%v %q", ok, why)
		}
	}
	n, last := count()
	if n != 1 || last.User != scanModule || last.Action != "exposure.verify_fail" {
		t.Fatalf("%d rows, last %+v", n, last)
	}
	e.dns.put(v.Value, txtRecord(v.Token))
	if ok, _ := e.scannable(v.ID); !ok {
		t.Fatal("not scannable after the record came back")
	}
	if n, last = count(); n != 2 || last.Action != "exposure.verify_ok" || last.User != scanModule {
		t.Fatalf("%d rows, last %+v", n, last)
	}
}
