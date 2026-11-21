package exposure

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
)

// cnameDNS is fakeResolver with CNAMEs, wildcards, names that do not exist and per-name failures, the way a real resolver answers:
// the TXT lookup of a CNAME follows it; a wildcard "*.zone" answers every name under zone that has no record of its own (RFC 4592),
// the dedicated _vedette-verify name included; a name that does not exist is "no such host" (NXDOMAIN).
type cnameDNS struct {
	*fakeResolver
	mu        sync.Mutex
	cname     map[string]string   // name -> canonical name
	wildCNAME map[string]string   // zone -> the target of "*.zone CNAME target"
	wildTXT   map[string][]string // zone -> the values of "*.zone TXT"
	nx        map[string]bool     // names that do not exist
	fail      map[string]error    // TXT lookups that fail
	onTXT     func(name string)   // runs on every TXT lookup (a test changes the world while a check runs)
}

func (d *cnameDNS) own(name string) bool {
	_, ok := d.txt[name]
	_, c := d.cname[name]
	return ok || c
}

// canonical is the name's CNAME target, explicit or through a wildcard CNAME, or "".
func (d *cnameDNS) canonical(name string) string {
	if c, ok := d.cname[name]; ok {
		return c
	}
	if d.own(name) {
		return ""
	}
	for zone, c := range d.wildCNAME {
		if strings.HasSuffix(name, "."+zone) {
			return c
		}
	}
	return ""
}

func (d *cnameDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	name = strings.TrimSuffix(name, ".")
	if d.onTXT != nil {
		d.onTXT(name)
	}
	d.mu.Lock()
	err, nx, c := d.fail[name], d.nx[name], d.canonical(name)
	var wild []string
	if !d.own(name) && c == "" {
		for zone, v := range d.wildTXT {
			if strings.HasSuffix(name, "."+zone) {
				wild = v
			}
		}
	}
	d.mu.Unlock()
	switch {
	case err != nil:
		return nil, err
	case nx:
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	case wild != nil:
		return wild, nil
	case c != "":
		name = c
	}
	v, ferr := d.fakeResolver.LookupTXT(ctx, name)
	if ferr == nil && len(v) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return v, ferr
}

func (d *cnameDNS) LookupCNAME(_ context.Context, name string) (string, error) {
	name = strings.TrimSuffix(name, ".")
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nx[name] {
		return "", &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	if c := d.canonical(name); c != "" {
		return c + ".", nil
	}
	return name + ".", nil
}

// newProofEnv is newEnv with the CNAME-aware resolver: git.example.org is a CNAME to example.ddns.net (a real-world case).
func newProofEnv(t *testing.T) (*env, *cnameDNS) {
	t.Helper()
	e := newEnv(t)
	d := &cnameDNS{fakeResolver: e.dns, cname: map[string]string{"git.example.org": "example.ddns.net"}, wildCNAME: map[string]string{},
		wildTXT: map[string][]string{}, nx: map[string]bool{}, fail: map[string]error{}}
	e.useService(Config{DB: e.db, Audit: audit.New(e.clock.Now), Resolver: d, Prober: e.prober, Publisher: e.pub, Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now, Location: time.UTC})
	return e, d
}

func (e *env) add(user, name string) TargetView {
	e.t.Helper()
	v, err := e.svc.AddDomain(e.ctx(), user, name)
	if err != nil {
		e.t.Fatalf("add %s: %v", name, err)
	}
	return v
}

func (e *env) verify(id string) VerifyResult {
	e.t.Helper()
	e.advance(DomainCheckEvery) // a target is checked at most once every DomainCheckEvery
	r, err := e.svc.Verify(e.ctx(), "operator@acme.example", id)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// A verified example.org covers git.example.org with no record of its own; a child added before
// its parent was verified is covered when the parent is; another user's target of the same box covers too; the scan of the child
// tells the executors to check the parent's record; the parent removed from the box, or its record removed,
// covers the child no more at its next check (the one right before a scan).
func TestProof_ParentCoversChild(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	child := e.add("alice@acme.example", "git.example.org") // added first, by one user
	deep := e.add("alice@acme.example", "a.b.git.example.org")
	parent := e.add("bob@acme.example", "example.org") // the parent, by another user of the box
	if r := e.verify(child.ID); r.Verified {
		t.Fatalf("nothing published yet: %+v", r)
	}
	e.dns.put("example.org", "v=spf1 -all", txtRecord(parent.Token))
	if r := e.verify(parent.ID); !r.Verified || r.Message != "Found the TXT record vedette-verify="+parent.Token+" on example.org." {
		t.Fatalf("parent: %+v", r)
	}
	// Only a domain whose own record is on its own name covers the names under it: git is verified by its parent's
	// record, so it covers nothing, and a.b.git is covered by example.org
	for id, by := range map[string]string{child.ID: "example.org", deep.ID: "example.org"} {
		v := e.target(id)
		if v.Status != "verified" || v.LastCheck == nil || !v.LastCheck.OK || !strings.Contains(v.LastCheck.Message, "Covered by the TXT record on example.org") {
			t.Fatalf("a target added before its parent was verified is covered when it is: %+v %+v", v, v.LastCheck)
		}
		if v.Proof == nil || v.Proof.CoveredBy == nil || *v.Proof.CoveredBy != by {
			t.Fatalf("covered_by: %+v", v.Proof)
		}
	}
	if r := e.verify(child.ID); !r.Verified || r.Message != "Found the TXT record of example.org on example.org: it proves example.org and every name under it, git.example.org included." {
		t.Fatalf("child's own check: %+v", r)
	}
	// the scan of the child names the parent's domain and token, the record the executors' fence checks (one rule)
	run := &fakeRunner{content: Content{}}
	e.svc.SetRunner(run)
	if _, err := e.commit(child.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", child.ID); err != nil {
		t.Fatal(err)
	}
	if p := run.last.Proof; p == nil || p.Domain != "example.org" || p.Token != parent.Token || run.last.Value != "git.example.org" {
		t.Fatalf("scan target %+v proof %+v", run.last, run.last.Proof)
	}
	// the parent's record goes: the child is covered no more right before its next scan
	e.dns.put("example.org", "v=spf1 -all")
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), "scan", child.ID); ok || why != BlockedTxtMissing {
		t.Fatalf("parent's record removed: %v %v", ok, why)
	}
	// the record is back but the parent target is removed from the box: its token proves nothing for the box any more
	e.dns.put("example.org", txtRecord(parent.Token))
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", parent.ID); err != nil {
		t.Fatal(err)
	}
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), "scan", child.ID); ok || why != BlockedTxtMissing {
		t.Fatalf("parent target removed: %v %v", ok, why)
	}
	// Not only the target at that name: the child's own token on a parent name proves the child
	e.dns.put("example.org", txtRecord(child.Token))
	if r := e.verify(child.ID); !r.Verified || !strings.Contains(r.Message, "this target's own record on a parent name") {
		t.Fatalf("the child's token on its parent: %+v", r)
	}
}

// A parent removed from the box while the child's check runs covers nothing in that check.
func TestProof_ParentRemovedDuringTheCheck(t *testing.T) {
	t.Parallel()
	e, d := newProofEnv(t)
	parent := e.add("admin@acme.example", "example.org")
	child := e.add("admin@acme.example", "www.example.org")
	e.dns.put("example.org", txtRecord(parent.Token))
	var once sync.Once
	d.onTXT = func(name string) {
		if name == "example.org" {
			once.Do(func() {
				if err := e.svc.Delete(context.WithoutCancel(e.ctx()), "admin@acme.example", parent.ID); err != nil {
					t.Error(err)
				}
			})
		}
	}
	if r := e.verify(child.ID); r.Verified || !strings.Contains(r.Message, "was removed from the box while it was checked") {
		t.Fatalf("%+v", r)
	}
}

// A public suffix covers nothing. ICANN's (co.uk) and private ones (ddns.net, github.io): one customer never covers another's.
func TestProof_PublicSuffixCoversNothing(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		proven, name string
		want         bool
	}{
		{"example.org", "git.example.org", true},
		{"example.org", "example.org", true},
		{"git.example.org", "example.org", false}, // never upward
		{"example.org", "evilexample.org", false},
		{"com", "example.org", false},
		{"co.uk", "acme.co.uk", false},
		{"ddns.net", "example.ddns.net", false},
		{"github.io", "acme.github.io", false},
		{"example.ddns.net", "git.example.ddns.net", true},
		{"acme.github.io", "other.github.io", false},
	} {
		if got := Covers(c.proven, c.name); got != c.want {
			t.Errorf("Covers(%s, %s) = %v, want %v", c.proven, c.name, got, c.want)
		}
	}
	e, _ := newProofEnv(t)
	for _, suffix := range []string{"co.uk", "ddns.net", "github.io", "com.vn"} {
		if _, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", suffix); !errors.Is(err, ErrPublicSuffix) {
			t.Fatalf("%s added: %v", suffix, err)
		}
	}
	v := e.add("admin@acme.example", "example.ddns.net")
	e.dns.put("ddns.net", txtRecord(v.Token))
	if r := e.verify(v.ID); r.Verified {
		t.Fatalf("a record on a public suffix verified %s: %+v", v.Value, r)
	}
	if ch := proofChain("x.example.ddns.net"); strings.Join(ch, ",") != "x.example.ddns.net,example.ddns.net" {
		t.Fatalf("chain %v", ch)
	}
	if p := v.Proof; p == nil || p.Zone != "example.ddns.net" || p.Host != "@" {
		t.Fatalf("hint %+v", p)
	}
	// A public suffix stored by an older release is refused as one, not with "add the record back"
	err := e.svc.refusal(Target{Kind: KindDomain, Value: "ddns.net", Token: "0123456789abcdef"}, BlockedTxtMissing, t0)
	if err == nil || !strings.Contains(err.Error(), "ddns.net is a public suffix") || strings.Contains(err.Error(), "Add the record back") {
		t.Fatalf("stored public suffix: %v", err)
	}
}

// git.example.org is a CNAME, so its provider refuses a TXT beside it ("Record could not be added"); the record on
// _vedette-verify.git.example.org proves it, and the scan gate accepts it. A record reached through the CNAME is not git's.
func TestProof_VerifyLabelUnderACNAME(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	v := e.add("admin@acme.example", "git.example.org")
	if p := v.Proof; p == nil || p.Zone != "example.org" || p.Host != "@" || p.AltHost == nil || *p.AltHost != "_vedette-verify.git" || p.CoveredBy != nil {
		t.Fatalf("hint %+v", p)
	}
	e.dns.put("example.ddns.net", txtRecord(v.Token)) // answered through git's CNAME: the ddns.net name's record, not git's
	if r := e.verify(v.ID); r.Verified || !strings.Contains(r.Message, "git.example.org is a CNAME to another name, so its TXT record is not its own") {
		t.Fatalf("through the CNAME: %+v", r)
	}
	e.dns.put("_vedette-verify.git.example.org", txtRecord(v.Token))
	if r := e.verify(v.ID); !r.Verified || r.Message != "Found the TXT record vedette-verify="+v.Token+" on _vedette-verify.git.example.org." {
		t.Fatalf("%+v", r)
	}
	if _, why, err := e.svc.CheckScannable(e.ctx(), "scan", v.ID); err != nil || why == BlockedTxtMissing {
		t.Fatalf("gate: %v %v", why, err)
	}
	a := e.add("admin@acme.example", "example.org")
	if p := a.Proof; p == nil || p.Host != "@" || p.AltHost == nil || *p.AltHost != "_vedette-verify" {
		t.Fatalf("apex hint %+v", p)
	}
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 48) + ".example.org"
	if p := proofHint(Target{ID: "x", Kind: KindDomain, Value: long}, nil); p == nil || p.AltHost != nil {
		t.Fatalf("a name too long for the dedicated label gets no alt_host: %+v", p)
	}
}

// A wildcard on the zone never proves it. "*.example.org CNAME lb.lapsed-vendor.example" makes
// _vedette-verify.example.org a CNAME to a name whoever registers the lapsed domain controls; "*.example.org TXT"
// answers any name beside it too. And a parent that is a CNAME (b.… CNAME tenant.vendor.example) does not prove names under it.
func TestProof_WildcardsAndCNAMEdParentsProveNothing(t *testing.T) {
	t.Parallel()
	e, d := newProofEnv(t)
	zone := e.add("admin@acme.example", "example.org")
	e.dns.put("example.org", "v=spf1 -all")
	d.wildCNAME["example.org"] = "lb.lapsed-vendor.example"
	e.dns.put("lb.lapsed-vendor.example", txtRecord(zone.Token)) // the attacker's record on the name they registered
	if r := e.verify(zone.ID); r.Verified || !strings.Contains(r.Message, "_vedette-verify.example.org is a CNAME to another name") {
		t.Fatalf("wildcard CNAME: %+v", r)
	}
	delete(d.wildCNAME, "example.org")
	d.wildTXT["example.org"] = []string{txtRecord(zone.Token)}
	if r := e.verify(zone.ID); r.Verified || !strings.Contains(r.Message, "answers through a wildcard") {
		t.Fatalf("wildcard TXT: %+v", r)
	}
	delete(d.wildTXT, "example.org")
	b := e.add("admin@acme.example", "b.example.org")
	api := e.add("admin@acme.example", "api.b.example.org")
	d.cname["b.example.org"] = "tenant.vendor.example"
	e.dns.put("tenant.vendor.example", txtRecord(b.Token))
	if r := e.verify(b.ID); r.Verified {
		t.Fatalf("a CNAME'd parent: %+v", r)
	}
	if r := e.verify(api.ID); r.Verified {
		t.Fatalf("a name under a CNAME'd parent: %+v", r)
	}
}

// A failed check says which names were asked and what came back: a CNAME to another name (and why no TXT can sit there),
// a name that does not exist, a timeout, a TXT record that is not this one (cleaned and bounded: an answer from DNS is untrusted).
func TestProof_TheErrorSaysWhatWasAskedAndWhatCameBack(t *testing.T) {
	t.Parallel()
	e, d := newProofEnv(t)
	git := e.add("admin@acme.example", "git.example.org")
	r := e.verify(git.ID)
	for _, want := range []string{
		"No TXT record vedette-verify=" + git.Token + " was found. Vedette asked git.example.org, _vedette-verify.git.example.org, example.org, _vedette-verify.example.org.",
		"git.example.org: a CNAME to example.ddns.net, so a TXT record cannot sit on this name: put it on @ of the zone (the registered domain) or on _vedette-verify.git.example.org instead.",
		"_vedette-verify.git.example.org: no TXT record.",
		"example.org: no TXT record.",
		"No domain of this box above it covers it.",
	} {
		if r.Verified || !strings.Contains(r.Message, want) {
			t.Fatalf("missing %q in %q", want, r.Message)
		}
	}
	e.add("admin@acme.example", "example.org")
	if r := e.verify(git.ID); !strings.Contains(r.Message, "The box's example.org would cover it only with its own record on that name itself (or _vedette-verify before it); there is none there now.") {
		t.Fatalf("parent named: %q", r.Message)
	}
	nx := e.add("admin@acme.example", "nope.example.org")
	d.nx["nope.example.org"] = true
	if r := e.verify(nx.ID); !strings.Contains(r.Message, "nope.example.org: the name does not exist (NXDOMAIN), or has no address or TXT record.") {
		t.Fatalf("nxdomain: %q", r.Message)
	}
	slow := e.add("admin@acme.example", "slow.example.org")
	d.fail["slow.example.org"] = &net.DNSError{Err: "i/o timeout", Name: "slow.example.org", IsTimeout: true}
	if r := e.verify(slow.ID); !strings.Contains(r.Message, "slow.example.org: no answer within 5 seconds (timeout).") {
		t.Fatalf("timeout: %q", r.Message)
	}
	other := e.add("admin@acme.example", "www.example.org")
	e.dns.put("www.example.org", "google-site-verification=abc\x1b[31m\u202e"+strings.Repeat("x", 200))
	r = e.verify(other.ID)
	if !strings.Contains(r.Message, `www.example.org: one TXT record, not this one: "google-site-verification=abc [31m `) || strings.ContainsAny(r.Message, "\x1b\u202e") || len(r.Message) > 1500 {
		t.Fatalf("other TXT: %q", r.Message)
	}
}
