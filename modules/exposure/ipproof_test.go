package exposure

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
)

// ipWorld is a box whose resolver also answers reverse DNS and whose proof files are served from a map, so a test says what the
// Internet answers for each address and each name.
type ipWorld struct {
	*env
	dns   *ptrDNS
	files *fileSite
}

type ptrDNS struct {
	*cnameDNS
	mu  sync.Mutex
	ptr map[string][]string
	a   map[string][]netip.Addr
}

func (d *ptrDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n, ok := d.ptr[addr]; ok {
		return n, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (d *ptrDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.a[strings.TrimSuffix(host, ".")]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// fileSite answers the proof file by URL: the body of a 200, or the error of the real fetcher for anything else.
type fileSite struct {
	mu    sync.Mutex
	files map[string]string
	asks  []string
}

func (f *fileSite) Fetch(_ context.Context, rawURL string, _ netip.Addr) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asks = append(f.asks, rawURL)
	if b, ok := f.files[rawURL]; ok {
		return []byte(b), nil
	}
	return nil, errors.New("answered 404")
}

func (f *fileSite) serve(ip, scheme, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[scheme+"://"+ip+ipProofPath] = body
}

func (f *fileSite) remove() {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.files, "http://"+ipC+ipProofPath)
	delete(f.files, "https://"+ipC+ipProofPath)
}

func (f *fileSite) fetched() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.asks) }

func newIPWorld(t *testing.T) *ipWorld {
	t.Helper()
	e, c := newProofEnv(t)
	w := &ipWorld{env: e, dns: &ptrDNS{cnameDNS: c, ptr: map[string][]string{}, a: map[string][]netip.Addr{}}, files: &fileSite{files: map[string]string{}}}
	e.useService(Config{DB: e.db, Audit: audit.New(e.clock.Now), Resolver: w.dns, Prober: e.prober, Publisher: e.pub, Log: slog.New(slog.DiscardHandler),
		Clock: e.clock.Now, Location: time.UTC, IPFetch: w.files})
	return w
}

func (w *ipWorld) addIP(ip string) TargetView {
	w.t.Helper()
	v, err := w.svc.AddTarget(w.ctx(), "admin@acme.example", KindIP, ip)
	if err != nil {
		w.t.Fatalf("add %s: %v", ip, err)
	}
	return v
}

func (w *ipWorld) scanErr(id string) (string, error) {
	w.t.Helper()
	w.advance(ScanEvery)
	_, err := w.svc.Scan(w.ctx(), "operator@acme.example", id)
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code, err
	}
	return "", err
}

func TestTypedIP_IsInTheListAtOnceButNeverScannedUntilProved(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	run := &fakeRunner{content: Content{}}
	w.svc.SetRunner(run)
	v := w.addIP(ipC)
	if v.Kind != KindIP || v.Origin != "person" || v.Status != "unverified" || v.Scannable || v.ScanState != "unproved" || len(v.Token) != 16 {
		t.Fatalf("a typed IP right after adding = %+v", v)
	}
	if v.IPProof == nil || v.IPProof.Path != "/.well-known/vedette-verify.txt" || v.IPProof.Content != v.Token || len(v.IPProof.URLs) != 2 {
		t.Fatalf("the person is told where the proof goes: %+v", v.IPProof)
	}
	list, err := w.svc.Targets(w.ctx())
	if err != nil || len(list) != 1 || list[0].ID != v.ID {
		t.Fatalf("the list = %+v, %v", list, err)
	}
	if code, _ := w.scanErr(v.ID); code != "not_verified" || run.calls != 0 {
		t.Fatalf("scan code %q, runner calls %d: an unproved IP is not scanned", code, run.calls)
	}
	if w.files.fetched() != 0 {
		t.Fatal("adding looked for a proof the person has not placed yet")
	}
}

func TestTypedIP_TheTokenFileProvesItForNinetyDaysAndItIsScannedAfterwards(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	run := &fakeRunner{content: Content{}}
	w.svc.SetRunner(run)
	v := w.addIP(ipC)
	w.files.serve(ipC, "https", v.Token+"\n")
	r := w.verify(v.ID)
	if !r.Verified || r.Target.Status != "verified" || r.Target.Method == nil || *r.Target.Method != methodIPFile || r.Target.NextCheckAt == nil {
		t.Fatalf("after placing the file = %+v", r)
	}
	if want := w.clock.Now().Add(90 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z"); r.Target.ExpiresAt == nil || *r.Target.ExpiresAt != want {
		t.Fatalf("expires %v, want %s", r.Target.ExpiresAt, want)
	}
	if want := w.clock.Now().Add(83 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z"); *r.Target.NextCheckAt != want {
		t.Fatalf("next check %s, want %s (a week before expiry)", *r.Target.NextCheckAt, want)
	}
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.scanErr(v.ID); err != nil || run.calls != 1 || run.last.Value != ipC {
		t.Fatalf("scan of a proved IP: %v, runner calls %d", err, run.calls)
	}
}

func TestTypedIP_TheTokenOnAnotherAddressProvesNothing(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	a, b := w.addIP(ipC), w.addIP(ipD)
	w.files.serve(ipD, "http", b.Token) // B's own file is there, and A's token is on B's address
	w.files.serve(ipD, "https", a.Token)
	if r := w.verify(a.ID); r.Verified || w.target(a.ID).Status != "unverified" || !strings.Contains(r.Message, "Vedette found no proof of "+ipC) {
		t.Fatalf("A: %+v", r)
	}
	if r := w.verify(b.ID); !r.Verified {
		t.Fatalf("B has its own token on its own address: %+v", r)
	}
}

func TestTypedIP_AFileWithAnotherTokenProvesNothing(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	v := w.addIP(ipC)
	w.files.serve(ipC, "http", "0123456789abcdef")
	if r := w.verify(v.ID); r.Verified || !strings.Contains(r.Message, "does not contain this target's token") || strings.Contains(r.Message, v.Token) {
		t.Fatalf("%+v", r)
	}
}

// redirectWorld serves a proof file behind redirects; the real fetcher is asked, with the test server's own address as the IP.
func redirectWorld(t *testing.T, h http.HandlerFunc) (string, netip.Addr) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	addr := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	return srv.URL + ipProofPath, addr.Addr()
}

func TestTypedIP_AFileBehindARedirectToAnotherHostIsNotFollowed(t *testing.T) {
	t.Parallel()
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hit = true; _, _ = w.Write([]byte("abcdef0123456789")) }))
	defer other.Close()
	u, ip := redirectWorld(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://other.example.test:"+strings.Split(other.URL, ":")[2]+ipProofPath, http.StatusFound)
	})
	_, err := httpIPFetcher{}.Fetch(t.Context(), u, ip)
	if err == nil || !strings.Contains(err.Error(), "another host") || hit {
		t.Fatalf("err %v, the other host was reached: %v", err, hit)
	}
}

func TestTypedIP_AFileBehindARedirectOnTheSameAddressIsRead(t *testing.T) {
	t.Parallel()
	u, ip := redirectWorld(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == ipProofPath {
			http.Redirect(w, r, "/final", http.StatusMovedPermanently)
			return
		}
		_, _ = w.Write([]byte("abcdef0123456789\n"))
	})
	b, err := httpIPFetcher{}.Fetch(t.Context(), u, ip)
	if err != nil || !tokenMatches(b, "abcdef0123456789") {
		t.Fatalf("%q, %v", b, err)
	}
}

func TestTypedIP_TheFileIsReadOnlyUpToTheCap(t *testing.T) {
	t.Parallel()
	u, ip := redirectWorld(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("a", 10_000))) })
	b, err := httpIPFetcher{}.Fetch(t.Context(), u, ip)
	if err != nil || len(b) > ipProofMaxBody+1 || tokenMatches(b, strings.Repeat("a", 10_000)) {
		t.Fatalf("read %d bytes, %v", len(b), err)
	}
}

func TestTypedIP_AnAnswerThatIsNot200IsNotAProof(t *testing.T) {
	t.Parallel()
	u, ip := redirectWorld(t, func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "abcdef0123456789", http.StatusForbidden) })
	if b, err := (httpIPFetcher{}).Fetch(t.Context(), u, ip); err == nil {
		t.Fatalf("read %q from a 403", b)
	}
}

// A proved domain, example.com, whose host name has the IP as PTR.
func ptrWorld(t *testing.T) (*ipWorld, TargetView) {
	t.Helper()
	w := newIPWorld(t)
	d := w.add("admin@acme.example", "example.com")
	w.dns.put("example.com", txtRecord(d.Token))
	if r := w.verify(d.ID); !r.Verified {
		t.Fatalf("domain: %+v", r)
	}
	return w, w.addIP(ipC)
}

func TestTypedIP_ReverseDNSUnderAProvedDomainThatResolvesBackProvesIt(t *testing.T) {
	t.Parallel()
	w, v := ptrWorld(t)
	w.dns.ptr[ipC] = []string{"edge.example.com."}
	w.dns.a["edge.example.com"] = []netip.Addr{netip.MustParseAddr(ipC)}
	r := w.verify(v.ID)
	if !r.Verified || *r.Target.Method != methodIPPTR || !strings.Contains(r.Message, "edge.example.com") {
		t.Fatalf("%+v", r)
	}
	if got := r.Target.IPProof.PTRDomains; len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("the person is told which domains can carry the name: %v", got)
	}
}

func TestTypedIP_AReverseNameThatDoesNotResolveBackProvesNothing(t *testing.T) {
	t.Parallel()
	w, v := ptrWorld(t)
	w.dns.ptr[ipC] = []string{"edge.example.com."}
	w.dns.a["edge.example.com"] = []netip.Addr{netip.MustParseAddr(ipD)} // somebody else's address
	r := w.verify(v.ID)
	if r.Verified || !strings.Contains(r.Message, "does not resolve back to "+ipC) {
		t.Fatalf("%+v", r)
	}
	if code, _ := w.scanErr(v.ID); code != "not_verified" {
		t.Fatalf("scan code %q", code)
	}
}

func TestTypedIP_AReverseNameOutsideTheProvedDomainsProvesNothing(t *testing.T) {
	t.Parallel()
	w, v := ptrWorld(t)
	w.dns.ptr[ipC] = []string{"static.provider.test."}
	w.dns.a["static.provider.test"] = []netip.Addr{netip.MustParseAddr(ipC)}
	if r := w.verify(v.ID); r.Verified || !strings.Contains(r.Message, "not under a domain this box has proved") {
		t.Fatalf("%+v", r)
	}
}

func TestTypedIP_AnARecordOfAProvedDomainPointingAtTheIPIsNotProof(t *testing.T) {
	t.Parallel()
	w, v := ptrWorld(t)
	w.dns.a["www.example.com"] = []netip.Addr{netip.MustParseAddr(ipC)} // the owner of example.com can point a name at anyone's address
	w.dns.a["example.com"] = []netip.Addr{netip.MustParseAddr(ipC)}
	if r := w.verify(v.ID); r.Verified || w.target(v.ID).Status != "unverified" {
		t.Fatalf("%+v", r)
	}
}

func TestTypedIP_ReverseNameUnderADomainWhoseRecordIsGoneProvesNothing(t *testing.T) {
	t.Parallel()
	w, v := ptrWorld(t)
	w.dns.ptr[ipC] = []string{"edge.example.com."}
	w.dns.a["edge.example.com"] = []netip.Addr{netip.MustParseAddr(ipC)}
	w.dns.put("example.com") // the domain's own record is removed: the box proves it no more
	if r := w.verify(v.ID); r.Verified {
		t.Fatalf("a PTR under a domain that is not proved now proved the IP: %+v", r)
	}
}

func TestTypedIP_AnExpiredProofIsNotScannedEvenWhenTheFileIsStillThere(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	run := &fakeRunner{content: Content{}}
	w.svc.SetRunner(run)
	v := w.addIP(ipC)
	w.files.serve(ipC, "http", v.Token)
	if !w.verify(v.ID).Verified {
		t.Fatal("not proved")
	}
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	w.advance(91 * 24 * time.Hour)
	if code, _ := w.scanErr(v.ID); code != "expired" || run.calls != 0 {
		t.Fatalf("scan code %q, runner calls %d", code, run.calls)
	}
	if got := w.target(v.ID); got.Status != "expired" || got.ScanState != "expired" || got.Scannable {
		t.Fatalf("%+v", got)
	}
	if ok, reason := w.scannable(v.ID); ok || reason != BlockedExpired {
		t.Fatalf("scannable %v %q", ok, reason)
	}
	if again := w.verify(v.ID); !again.Verified || w.target(v.ID).Status != "verified" {
		t.Fatalf("a person proves it again: %+v", again)
	}
}

func TestTypedIP_TheProofIsLookedForAgainRightBeforeEveryScan(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	run := &fakeRunner{content: Content{}}
	w.svc.SetRunner(run)
	v := w.addIP(ipC)
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.scanErr(v.ID); err != nil {
		t.Fatal(err)
	}
	w.files.remove() // the file is taken down after the proof
	n := w.files.fetched()
	if code, err := w.scanErr(v.ID); err != nil || run.calls != 2 || w.files.fetched() == n {
		t.Fatalf("scan code %q, runner calls %d, fetched %d: the proof is looked for, and its absence is a warning inside its 90 days", code, run.calls, w.files.fetched()-n)
	}
	if got := w.target(v.ID); got.ScanState != "ready" || got.BlockedReason != nil || got.LastCheck == nil || got.LastCheck.OK {
		t.Fatalf("%+v", got)
	}
	if ok, reason := w.scannable(v.ID); !ok || reason != "" {
		t.Fatalf("the gate a domain scan asks: %v %q", ok, reason)
	}
}

func TestTypedIP_TheBoxChecksTheProofByItselfBeforeItExpires(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	v := w.addIP(ipC)
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	asked := w.files.fetched()

	w.advance(70 * 24 * time.Hour)
	if err := w.svc.RunProofRecheck(w.ctx()); err != nil || w.files.fetched() != asked {
		t.Fatalf("nothing is due 20 days before expiry: %v, fetched %d more", err, w.files.fetched()-asked)
	}
	w.advance(14 * 24 * time.Hour) // 6 days left
	if err := w.svc.RunProofRecheck(w.ctx()); err != nil || w.files.fetched() == asked {
		t.Fatalf("the check was due: %v", err)
	}
	got := w.target(v.ID)
	if want := w.clock.Now().Add(90 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z"); got.ExpiresAt == nil || *got.ExpiresAt != want || got.Status != "verified" {
		t.Fatalf("renewed by itself: %+v", got)
	}
}

func TestTypedIP_AProofThatIsNotFoundAtTheBoxsCheckIsRetriedEverySixHoursUntilItExpires(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	v := w.addIP(ipC)
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	w.files.remove()
	w.advance(84 * 24 * time.Hour)
	_ = w.svc.RunProofRecheck(w.ctx())
	n := w.files.fetched()
	got := w.target(v.ID)
	if got.LastCheck == nil || got.LastCheck.OK || got.NextCheckAt == nil {
		t.Fatalf("%+v", got)
	}
	_ = w.svc.RunProofRecheck(w.ctx())
	if w.files.fetched() != n {
		t.Fatal("tried again at once")
	}
	w.advance(IPRecheckRetry)
	_ = w.svc.RunProofRecheck(w.ctx())
	if w.files.fetched() == n {
		t.Fatal("did not try again after the retry time")
	}
	w.advance(7 * 24 * time.Hour) // expired: a person proves it again
	n = w.files.fetched()
	_ = w.svc.RunProofRecheck(w.ctx())
	if w.files.fetched() != n || w.target(v.ID).Status != "expired" {
		t.Fatal("the box checks an expired proof")
	}
}

func TestTypedIP_OwnershipIsCheckedOncePer30SecondsPerTarget(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	v := w.addIP(ipC)
	w.advance(DomainCheckEvery)
	if _, err := w.svc.Verify(w.ctx(), "operator@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	_, err := w.svc.Verify(w.ctx(), "operator@acme.example", v.ID)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "rate_limited" || !strings.Contains(ae.Message, "30 second") {
		t.Fatalf("second check at once: %v", err)
	}
	w.advance(DomainCheckEvery)
	if _, err := w.svc.Verify(w.ctx(), "operator@acme.example", v.ID); err != nil {
		t.Fatalf("after 30 s: %v", err)
	}
}

func TestTypedIP_TheBoxSeeingItAsItsOwnEgressAddressMakesItTheBoxs(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	v := w.addIP(ipA)
	w.detect(ipA)
	got := w.target(v.ID)
	if got.Origin != "box" || got.Method == nil || *got.Method != methodBoxEgress || got.IPProof != nil || got.Token != "" {
		t.Fatalf("%+v", got)
	}
}

func TestTypedIP_WhatTheListTakes(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	cases := map[string]string{"192.168.1.5": "ip_not_allowed", "10.0.0.1": "ip_not_allowed", "100.64.0.1": "ip_not_allowed", "::1": "ip_not_allowed", "2001:db8::1": "ip_not_allowed",
		"example.com": "bad_value", "": "empty", "8.8.8.8/32": "bad_value"}
	for in, code := range cases {
		_, err := w.svc.AddTarget(w.ctx(), "admin@acme.example", KindIP, in)
		var ae *APIError
		if !errors.As(err, &ae) || ae.Code != code {
			t.Errorf("%q: %v, want %s", in, err, code)
		}
	}
	w.addIP(ipC)
	if _, err := w.svc.AddTarget(w.ctx(), "admin@acme.example", KindIP, ipC); err == nil || !strings.Contains(err.Error(), "already in the list") {
		t.Errorf("duplicate: %v", err)
	}
	// The kind is taken from the value when the request leaves it out
	if v, err := w.svc.AddTarget(w.ctx(), "admin@acme.example", "", ipD); err != nil || v.Kind != KindIP {
		t.Errorf("inferred IP: %+v %v", v, err)
	}
	if v, err := w.svc.AddTarget(w.ctx(), "admin@acme.example", "", "example.org"); err != nil || v.Kind != KindDomain {
		t.Errorf("inferred domain: %+v %v", v, err)
	}
	if _, err := w.svc.AddTarget(w.ctx(), "admin@acme.example", KindDomain, "9.8.7.6"); err == nil {
		t.Error("an IP typed as a domain")
	}
	// An IP the person removed and ignored is not typed back in until it is restored
	v := w.addIP("9.9.9.10")
	if err := w.svc.Remove(w.ctx(), "admin@acme.example", v.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.AddTarget(w.ctx(), "admin@acme.example", KindIP, "9.9.9.10"); err == nil || !strings.Contains(err.Error(), "Ignored list") {
		t.Errorf("ignored: %v", err)
	}
}

func TestTypedIP_TheListRowSaysKindOriginProofExpiryStateAndOpenExposures(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.svc.SetRunner(&fakeRunner{content: sampleContent()})
	dom := w.add("admin@acme.example", "acme.example")
	typed := w.addIP(ipC)
	w.files.serve(ipC, "http", typed.Token)
	w.verify(typed.ID)
	if _, err := w.commit(typed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.scanErr(typed.ID); err != nil {
		t.Fatal(err)
	}
	found := w.detect(ipA)
	rows, err := w.svc.Targets(w.ctx())
	if err != nil || len(rows) != 3 {
		t.Fatalf("%d rows, %v", len(rows), err)
	}
	by := map[string]TargetView{}
	for _, r := range rows {
		by[r.Value] = r
	}
	d, ty, box := by[dom.Value], by[ipC], by[found[0].Value]
	switch {
	case d.Kind != KindDomain || d.Origin != "person" || d.ScanState != "unproved":
		t.Errorf("domain row %+v", d)
	case ty.Kind != KindIP || ty.Origin != "person" || ty.ExpiresAt == nil || ty.ScanState != "ready" || ty.Latest == nil || ty.OpenExposures != ty.Latest.Ports || ty.OpenExposures == 0:
		t.Errorf("typed IP row %+v", ty)
	case box.Origin != "box" || box.Terms != nil || box.ScanState != "needs_terms":
		t.Errorf("auto-detected row %+v", box)
	}
}

func TestTypedIP_AFileBehindARedirectToAnotherPortIsNotFollowed(t *testing.T) {
	t.Parallel()
	u, ip := redirectWorld(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+ip127()+":22/"+"x", http.StatusFound)
	})
	if _, err := (httpIPFetcher{}).Fetch(t.Context(), u, ip); err == nil || !strings.Contains(err.Error(), "another port") {
		t.Fatalf("err %v", err)
	}
}

func ip127() string { return "127.0.0.1" }

func TestTypedIP_OneLiveResultServesTheGateAndEveryStepOfAScan(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	v := w.addIP(ipC)
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	n := w.files.fetched()
	ip := netip.MustParseAddr(ipC)
	for range 5 { // the gate, ScannableIP of each step, the terms
		if ok, err := w.svc.ScannableIP(w.ctx(), "operator@acme.example", ip); err != nil || !ok {
			t.Fatalf("scannable %v %v", ok, err)
		}
	}
	if w.files.fetched() != n {
		t.Fatalf("%d more requests inside the live window", w.files.fetched()-n)
	}
	w.advance(6 * time.Minute)
	for range 5 {
		if ok, _ := w.svc.ScannableIP(w.ctx(), "operator@acme.example", ip); !ok {
			t.Fatal("not scannable")
		}
	}
	if got := w.files.fetched() - n; got != 2 { // one look: the file over http and https
		t.Fatalf("%d requests for one look, want 2", got)
	}
}

func TestTypedIP_AFailureIsReusedOnlyForThePerTargetPause(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	v := w.addIP(ipC)
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr(ipC)
	failing := func() bool { c := w.target(v.ID).LastCheck; return c == nil || !c.OK }
	w.files.remove()
	w.advance(6 * time.Minute)
	if ok, _ := w.svc.ScannableIP(w.ctx(), "op@acme.example", ip); !ok || !failing() { // inside its 90 days: a warning only
		t.Fatalf("without the file: scannable %v, check failing %v", ok, failing())
	}
	w.files.serve(ipC, "http", v.Token) // the person fixed it
	w.advance(10 * time.Second)
	n := w.files.fetched()
	if _, ok := w.svc.liveProof(w.loadTarget(v.ID)); ok || w.files.fetched() != n {
		t.Fatal("the failure was not reused inside the pause")
	}
	w.advance(DomainCheckEvery)
	if ok, _ := w.svc.ScannableIP(w.ctx(), "op@acme.example", ip); !ok || failing() || w.files.fetched() == n {
		t.Fatal("not looked for again after the pause")
	}
}

func TestTypedIP_TheSentencesSayOwnOrAuthorisedAndTheSharedAddressWarningShows(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	v := w.addIP(ipC)
	if !strings.Contains(v.CommitmentNotice.Text, "I own "+ipC+" or am authorised to have it tested") || strings.Contains(v.CommitmentNotice.Text, "my company") {
		t.Fatalf("notice: %s", v.CommitmentNotice.Text)
	}
	if !strings.Contains(v.TermsNotice.Text, "I own "+ipC+" or am authorised to have it tested in depth") {
		t.Fatalf("terms: %s", v.TermsNotice.Text)
	}
	got, err := w.svc.Target(w.ctx(), v.ID)
	if err != nil || got.TermsWarning == nil || !strings.Contains(*got.TermsWarning, "web service only") {
		t.Fatalf("warning: %+v %v", got.TermsWarning, err)
	}
	box := w.detect(ipA)
	if strings.Contains(box[0].CommitmentNotice.Text, "or am authorised") {
		t.Fatal("the box's own IP got the typed sentence")
	}
}

func TestTypedIP_OpenVASLooksForTheProofAgainAndRefusesWhenItIsGone(t *testing.T) {
	t.Parallel()
	e, _ := gbEnv(t)
	files := &fileSite{files: map[string]string{}}
	e.svc.cfg.IPFetch = files
	v, err := e.svc.AddTarget(e.ctx(), "admin@acme.example", KindIP, ipC)
	if err != nil {
		t.Fatal(err)
	}
	files.serve(ipC, "http", v.Token)
	e.advance(DomainCheckEvery)
	if r, err := e.svc.Verify(e.ctx(), "operator@acme.example", v.ID); err != nil || !r.Verified {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := e.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	e.acceptTerms(v.ID, false)
	e.enable()
	st := ScanTarget{ID: v.ID, Kind: KindIP, Value: ipC, User: "operator@acme.example", Mode: modeDeepOnly, Typed: true}
	if run, line, err := e.svc.greenbonePlan(e.ctx(), st); err != nil || !run {
		t.Fatalf("with the proof: %v %q %v", run, line, err)
	}
	files.remove()
	e.advance(10 * time.Minute)
	if run, line, err := e.svc.greenbonePlan(e.ctx(), st); err != nil || run || line != notGBProof {
		t.Fatalf("without it: %v %q %v", run, line, err)
	}
}
