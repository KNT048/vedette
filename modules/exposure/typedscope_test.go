package exposure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/domainfence"
)

// hmacFence gives every domain (and typed IP) its own 16 hex token, like the host's fence.
type hmacFence struct{}

func (hmacFence) Token(_ context.Context, domain string) (string, error) {
	h := sha256.Sum256([]byte("box|" + domain))
	return hex.EncodeToString(h[:])[:16], nil
}

func (hmacFence) Forget(context.Context, string) error { return nil }

func fenceTok(domain string) string {
	t, _ := hmacFence{}.Token(context.Background(), domain)
	return t
}

// scanTyped runs a scan of a typed IP target through the runner and answers what the runner was handed.
func (w *ipWorld) scanTyped(id string) (ScanTarget, error) {
	w.t.Helper()
	run := &fakeRunner{content: Content{}}
	w.svc.SetRunner(run)
	w.advance(ScanEvery)
	_, err := w.svc.Scan(w.ctx(), "admin@acme.example", id)
	return run.last, err
}

func typedWithFence(t *testing.T) (*ipWorld, TargetView) {
	t.Helper()
	w := newIPWorld(t)
	w.svc.cfg.DomainFence = hmacFence{}
	v := w.addIP(ipC)
	if v.Token != fenceTok(ipC) {
		t.Fatalf("the token of a typed IP is the box-bound one: %q", v.Token)
	}
	return w, v
}

func TestTypedScope_AProvedIPReachesTheExecutorsWithItsProof_File(t *testing.T) {
	t.Parallel()
	w, v := typedWithFence(t)
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	w.acceptTerms(v.ID, false)
	st, err := w.scanTyped(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	d := st.Domain
	if d == nil || d.Typed == nil || d.Typed.Method != domainfence.MethodFile || d.Domain != ipC || d.Name != ipC || d.Token != fenceTok(ipC) || !st.Mode.Full || !st.Typed {
		t.Fatalf("the runner got %+v (domain scope %+v)", st, d)
	}
}

func TestTypedScope_AProvedIPReachesTheExecutorsWithItsProof_ReverseDNS(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.svc.cfg.DomainFence = hmacFence{}
	d := w.add("admin@acme.example", "example.com")
	w.dns.put("example.com", txtRecord(d.Token))
	if !w.verify(d.ID).Verified {
		t.Fatal("domain not proved")
	}
	v := w.addIP(ipC)
	w.dns.ptr[ipC] = []string{"edge.example.com."}
	w.dns.a["edge.example.com"] = []netip.Addr{netip.MustParseAddr(ipC)}
	if !w.verify(v.ID).Verified {
		t.Fatal("IP not proved")
	}
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	w.acceptTerms(v.ID, false)
	st, err := w.scanTyped(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	ts := st.Domain
	if ts == nil || ts.Typed == nil || ts.Typed.Method != domainfence.MethodPTR || ts.Typed.PTRName != "edge.example.com" || ts.Typed.CoverDomain != "example.com" || ts.Typed.CoverToken != fenceTok("example.com") {
		t.Fatalf("scope %+v", ts)
	}
}

func TestTypedScope_NoScopeMeansTheStepsSaySoInsteadOfReachingTheBoxOnlyFence(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		setup func(*ipWorld, TargetView)
		want  string
	}{
		"the testing terms are not accepted": {func(*ipWorld, TargetView) {}, typedTerms},
		"no domain fence":                    {func(w *ipWorld, v TargetView) { w.svc.cfg.DomainFence = nil; w.acceptTerms(v.ID, false) }, typedNoFence},
		"a token from before the fence":      {func(w *ipWorld, v TargetView) { w.svc.cfg.DomainFence = otherFence{}; w.acceptTerms(v.ID, false) }, typedOldToken},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w, v := typedWithFence(t)
			w.files.serve(ipC, "http", v.Token)
			w.verify(v.ID)
			if _, err := w.commit(v.ID); err != nil {
				t.Fatal(err)
			}
			c.setup(w, v)
			st, err := w.scanTyped(v.ID)
			if err != nil {
				t.Fatal(err)
			}
			if st.Domain != nil || st.TypedWhy != c.want || st.Mode.Full {
				t.Fatalf("scope %+v, why %q, want %q", st.Domain, st.TypedWhy, c.want)
			}
		})
	}
}

// otherFence answers a token that is not the one the target was added with.
type otherFence struct{ hmacFence }

func (otherFence) Token(context.Context, string) (string, error) { return "0123456789abcdef", nil }

func TestTypedScope_AnUnprovedOrExpiredIPReachesNoExecutor(t *testing.T) {
	t.Parallel()
	w, v := typedWithFence(t)
	run := &fakeRunner{}
	w.svc.SetRunner(run)
	w.advance(ScanEvery)
	if _, err := w.svc.Scan(w.ctx(), "admin@acme.example", v.ID); err == nil || run.calls != 0 {
		t.Fatalf("unproved: %v, runner calls %d", err, run.calls)
	}
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	w.acceptTerms(v.ID, false)
	w.advance(91 * 24 * time.Hour)
	if _, err := w.svc.Scan(w.ctx(), "admin@acme.example", v.ID); err == nil || run.calls != 0 {
		t.Fatalf("expired: %v, runner calls %d", err, run.calls)
	}
}

func TestTypedScope_ADomainDeepStepToATypedAddressCarriesTheTypedProof(t *testing.T) {
	t.Parallel()
	w, v := typedWithFence(t)
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	w.acceptTerms(v.ID, false)
	w.advance(6 * time.Minute) // the result of the verify is out of its window
	got, ok := w.svc.typedAddr(w.ctx(), netip.MustParseAddr(ipC))
	if !ok || got.ID != v.ID {
		t.Fatalf("typedAddr: %v %v", got.ID, ok)
	}
	scope, why := w.svc.typedScope(w.ctx(), got)
	if scope != nil || why != typedGone { // no live result yet in this window: nothing is handed over on a guess
		t.Fatalf("%+v %q", scope, why)
	}
	if ok, _ := w.svc.ScannableIP(w.ctx(), "admin@acme.example", netip.MustParseAddr(ipC)); !ok { // the gate looks, and keeps the result
		t.Fatal("not scannable")
	}
	scope, why = w.svc.typedScope(w.ctx(), got)
	if scope == nil || why != "" || scope.Typed == nil {
		t.Fatalf("%+v %q", scope, why)
	}
}

// A domain's deep scan that reaches a typed IP uses the stricter of the two targets' terms: the IP is a separate asset with its own consent.
func TestTypedScope_ADomainDeepStepToATypedAddressUsesTheStricterTerms(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	files := &fileSite{files: map[string]string{}}
	d.svc.cfg.IPFetch = files
	v, err := d.svc.AddTarget(d.ctx(), "admin@acme.example", KindIP, ipB)
	if err != nil {
		t.Fatal(err)
	}
	files.serve(ipB, "http", v.Token)
	d.advance(DomainCheckEvery)
	if r, err := d.svc.Verify(d.ctx(), "operator@acme.example", v.ID); err != nil || !r.Verified {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := d.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	d.acceptTerms(d.dom.ID, true) // the domain accepted the deep scan and the disruptive checks
	st := ScanTarget{ID: d.dom.ID, Kind: KindDomain, Value: d.dom.Value, User: "admin@acme.example", Mode: ScanMode{Full: true, Disruptive: true}}
	ip := netip.MustParseAddr(ipB)
	if _, why, err := d.svc.deepGate(d.ctx(), st, ip, []string{"www.acme.example"}); err != nil || why != deepTerms {
		t.Fatalf("the IP has no terms: %q %v", why, err)
	}
	d.acceptTerms(v.ID, false) // deep, not disruptive
	out, why, err := d.svc.deepGate(d.ctx(), st, ip, []string{"www.acme.example"})
	if err != nil || why != "" || out.Domain == nil || out.Domain.Typed == nil || !out.Mode.Full || out.Mode.Disruptive {
		t.Fatalf("the stricter of the two: %+v %q %v", out, why, err)
	}
}
