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

// newProofEnv is newEnv with the CNAME-aware resolver: git.beyondnetglobal.com is a CNAME to beyondhcm.ddns.net (kien's case).
func newProofEnv(t *testing.T) (*env, *cnameDNS) {
	t.Helper()
	e := newEnv(t)
	d := &cnameDNS{fakeResolver: e.dns, cname: map[string]string{"git.beyondnetglobal.com": "beyondhcm.ddns.net"}, wildCNAME: map[string]string{},
		wildTXT: map[string][]string{}, nx: map[string]bool{}, fail: map[string]error{}}
	svc, err := NewService(Config{DB: e.db, Audit: audit.New(e.clock.Now), Resolver: d, Prober: e.prober, Publisher: e.pub, Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
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
	r, err := e.svc.Verify(e.ctx(), "operator@acme.example", id)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// D-628 (kien G10): a verified beyondnetglobal.com covers git.beyondnetglobal.com with no record of its own; a child added before
// its parent was verified is covered when the parent is; another user's target of the same box covers too; the scan of the child
// tells the executors to check the parent's record (review r1 M of #941); the parent removed from the box, or its record removed,
// covers the child no more at its next check (the one right before a scan).
func TestProof_D628_ParentCoversChild(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	child := e.add("kien@acme.example", "git.beyondnetglobal.com") // added first, by one user
	deep := e.add("kien@acme.example", "a.b.git.beyondnetglobal.com")
	parent := e.add("mlee@acme.example", "beyondnetglobal.com") // the parent, by another user of the box
	if r := e.verify(child.ID); r.Verified {
		t.Fatalf("nothing published yet: %+v", r)
	}
	e.dns.put("beyondnetglobal.com", "v=spf1 -all", txtRecord(parent.Token))
	if r := e.verify(parent.ID); !r.Verified || r.Message != "Found the TXT record vedette-verify="+parent.Token+" on beyondnetglobal.com." {
		t.Fatalf("parent: %+v", r)
	}
	for id, by := range map[string]string{child.ID: "beyondnetglobal.com", deep.ID: "git.beyondnetglobal.com"} { // the nearest verified one
		v := e.target(id)
		if v.Status != "verified" || v.LastCheck == nil || !v.LastCheck.OK || !strings.Contains(v.LastCheck.Message, "Covered by the TXT record on beyondnetglobal.com") {
			t.Fatalf("a target added before its parent was verified is covered when it is: %+v %+v", v, v.LastCheck)
		}
		if v.Proof == nil || v.Proof.CoveredBy == nil || *v.Proof.CoveredBy != by {
			t.Fatalf("covered_by: %+v", v.Proof)
		}
	}
	if r := e.verify(child.ID); !r.Verified || r.Message != "Found the TXT record of beyondnetglobal.com on beyondnetglobal.com: it proves beyondnetglobal.com and every name under it, git.beyondnetglobal.com included." {
		t.Fatalf("child's own check: %+v", r)
	}
	// the scan of the child names the parent's domain and token, the record the executors' fence checks (one rule, D-628)
	run := &fakeRunner{content: Content{}}
	e.svc.SetRunner(run)
	if _, err := e.commit(child.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", child.ID); err != nil {
		t.Fatal(err)
	}
	if p := run.last.Proof; p == nil || p.Domain != "beyondnetglobal.com" || p.Token != parent.Token || run.last.Value != "git.beyondnetglobal.com" {
		t.Fatalf("scan target %+v proof %+v", run.last, run.last.Proof)
	}
	// the parent's record goes: the child is covered no more right before its next scan
	e.dns.put("beyondnetglobal.com", "v=spf1 -all")
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), "scan", child.ID); ok || why != BlockedTxtMissing {
		t.Fatalf("parent's record removed: %v %v", ok, why)
	}
	// the record is back but the parent target is removed from the box: its token proves nothing for the box any more
	e.dns.put("beyondnetglobal.com", txtRecord(parent.Token))
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", parent.ID); err != nil {
		t.Fatal(err)
	}
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), "scan", child.ID); ok || why != BlockedTxtMissing {
		t.Fatalf("parent target removed: %v %v", ok, why)
	}
	// the child's own token on a parent name is not the parent's record: one rule with the executors' fence, which checks a domain's
	// own token on that domain
	e.dns.put("beyondnetglobal.com", txtRecord(child.Token))
	if r := e.verify(child.ID); r.Verified {
		t.Fatalf("the child's token on its parent: %+v", r)
	}
}

// Review r1 L of #941: a parent removed from the box while the child's check runs covers nothing in that check.
func TestProof_D628_ParentRemovedDuringTheCheck(t *testing.T) {
	t.Parallel()
	e, d := newProofEnv(t)
	parent := e.add("admin@acme.example", "beyondnetglobal.com")
	child := e.add("admin@acme.example", "www.beyondnetglobal.com")
	e.dns.put("beyondnetglobal.com", txtRecord(parent.Token))
	var once sync.Once
	d.onTXT = func(name string) {
		if name == "beyondnetglobal.com" {
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

// D-628: a public suffix covers nothing. ICANN's (co.uk) and private ones (ddns.net, github.io): one customer never covers another's.
func TestProof_D628_PublicSuffixCoversNothing(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		proven, name string
		want         bool
	}{
		{"beyondnetglobal.com", "git.beyondnetglobal.com", true},
		{"beyondnetglobal.com", "beyondnetglobal.com", true},
		{"git.beyondnetglobal.com", "beyondnetglobal.com", false}, // never upward
		{"beyondnetglobal.com", "evilbeyondnetglobal.com", false},
		{"com", "beyondnetglobal.com", false},
		{"co.uk", "acme.co.uk", false},
		{"ddns.net", "beyondhcm.ddns.net", false},
		{"github.io", "acme.github.io", false},
		{"beyondhcm.ddns.net", "git.beyondhcm.ddns.net", true},
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
	v := e.add("admin@acme.example", "beyondhcm.ddns.net")
	e.dns.put("ddns.net", txtRecord(v.Token))
	if r := e.verify(v.ID); r.Verified {
		t.Fatalf("a record on a public suffix verified %s: %+v", v.Value, r)
	}
	if ch := proofChain("x.beyondhcm.ddns.net"); strings.Join(ch, ",") != "x.beyondhcm.ddns.net,beyondhcm.ddns.net" {
		t.Fatalf("chain %v", ch)
	}
	if p := v.Proof; p == nil || p.Zone != "beyondhcm.ddns.net" || p.Host != "@" {
		t.Fatalf("hint %+v", p)
	}
	// review r1 L of #941: a public suffix stored before D-628 is refused as one, not with "add the record back"
	err := e.svc.refusal(Target{Kind: KindDomain, Value: "ddns.net", Token: "0123456789abcdef"}, BlockedTxtMissing, t0)
	if err == nil || !strings.Contains(err.Error(), "ddns.net is a public suffix") || strings.Contains(err.Error(), "Add the record back") {
		t.Fatalf("stored public suffix: %v", err)
	}
}

// D-628: git.beyondnetglobal.com is a CNAME, so its provider refuses a TXT beside it ("Record could not be added"); the record on
// _vedette-verify.git.beyondnetglobal.com proves it, and the scan gate accepts it. A record reached through the CNAME is not git's.
func TestProof_D628_VerifyLabelUnderACNAME(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	v := e.add("admin@acme.example", "git.beyondnetglobal.com")
	if p := v.Proof; p == nil || p.Zone != "beyondnetglobal.com" || p.Host != "git" || p.AltHost == nil || *p.AltHost != "_vedette-verify.git" || p.CoveredBy != nil {
		t.Fatalf("hint %+v", p)
	}
	e.dns.put("beyondhcm.ddns.net", txtRecord(v.Token)) // answered through git's CNAME: the ddns.net name's record, not git's
	if r := e.verify(v.ID); r.Verified || !strings.Contains(r.Message, "git.beyondnetglobal.com is a CNAME to another name, so its TXT record is not its own") {
		t.Fatalf("through the CNAME: %+v", r)
	}
	e.dns.put("_vedette-verify.git.beyondnetglobal.com", txtRecord(v.Token))
	if r := e.verify(v.ID); !r.Verified || r.Message != "Found the TXT record vedette-verify="+v.Token+" on _vedette-verify.git.beyondnetglobal.com." {
		t.Fatalf("%+v", r)
	}
	if _, why, err := e.svc.CheckScannable(e.ctx(), "scan", v.ID); err != nil || why == BlockedTxtMissing {
		t.Fatalf("gate: %v %v", why, err)
	}
	a := e.add("admin@acme.example", "beyondnetglobal.com")
	if p := a.Proof; p == nil || p.Host != "@" || p.AltHost == nil || *p.AltHost != "_vedette-verify" {
		t.Fatalf("apex hint %+v", p)
	}
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 40) + ".beyondnetglobal.com"
	if p := proofHint(Target{ID: "x", Kind: KindDomain, Value: long}, nil); p == nil || p.AltHost != nil {
		t.Fatalf("a name too long for the dedicated label gets no alt_host: %+v", p)
	}
}

// Review r1 High of #941: a wildcard on the zone never proves it. "*.beyondnetglobal.com CNAME lb.lapsed-vendor.example" makes
// _vedette-verify.beyondnetglobal.com a CNAME to a name whoever registers the lapsed domain controls; "*.beyondnetglobal.com TXT"
// answers any name beside it too. And a parent that is a CNAME (b.… CNAME tenant.vendor.example) does not prove names under it.
func TestProof_D628_WildcardsAndCNAMEdParentsProveNothing(t *testing.T) {
	t.Parallel()
	e, d := newProofEnv(t)
	zone := e.add("admin@acme.example", "beyondnetglobal.com")
	e.dns.put("beyondnetglobal.com", "v=spf1 -all")
	d.wildCNAME["beyondnetglobal.com"] = "lb.lapsed-vendor.example"
	e.dns.put("lb.lapsed-vendor.example", txtRecord(zone.Token)) // the attacker's record on the name they registered
	if r := e.verify(zone.ID); r.Verified || !strings.Contains(r.Message, "_vedette-verify.beyondnetglobal.com is a CNAME to another name") {
		t.Fatalf("wildcard CNAME: %+v", r)
	}
	delete(d.wildCNAME, "beyondnetglobal.com")
	d.wildTXT["beyondnetglobal.com"] = []string{txtRecord(zone.Token)}
	if r := e.verify(zone.ID); r.Verified || !strings.Contains(r.Message, "answers through a wildcard") {
		t.Fatalf("wildcard TXT: %+v", r)
	}
	delete(d.wildTXT, "beyondnetglobal.com")
	b := e.add("admin@acme.example", "b.beyondnetglobal.com")
	api := e.add("admin@acme.example", "api.b.beyondnetglobal.com")
	d.cname["b.beyondnetglobal.com"] = "tenant.vendor.example"
	e.dns.put("tenant.vendor.example", txtRecord(b.Token))
	if r := e.verify(b.ID); r.Verified {
		t.Fatalf("a CNAME'd parent: %+v", r)
	}
	if r := e.verify(api.ID); r.Verified {
		t.Fatalf("a name under a CNAME'd parent: %+v", r)
	}
}

// D-628 (4): a failed check says which names were asked and what came back: a CNAME to another name (and why no TXT can sit there),
// a name that does not exist, a timeout, a TXT record that is not this one (cleaned and bounded: an answer from DNS is untrusted).
func TestProof_D628_TheErrorSaysWhatWasAskedAndWhatCameBack(t *testing.T) {
	t.Parallel()
	e, d := newProofEnv(t)
	git := e.add("admin@acme.example", "git.beyondnetglobal.com")
	r := e.verify(git.ID)
	for _, want := range []string{
		"No TXT record vedette-verify=" + git.Token + " was found. Vedette asked git.beyondnetglobal.com, _vedette-verify.git.beyondnetglobal.com.",
		"git.beyondnetglobal.com: a CNAME to beyondhcm.ddns.net, so a TXT record cannot sit on this name: put it on _vedette-verify.git.beyondnetglobal.com instead, or verify a parent domain.",
		"_vedette-verify.git.beyondnetglobal.com: no TXT record.",
		"No domain of this box above it covers it.",
	} {
		if r.Verified || !strings.Contains(r.Message, want) {
			t.Fatalf("missing %q in %q", want, r.Message)
		}
	}
	e.add("admin@acme.example", "beyondnetglobal.com")
	if r := e.verify(git.ID); !strings.Contains(r.Message, "The box's beyondnetglobal.com, which would cover it, has no record of its own now either.") {
		t.Fatalf("parent named: %q", r.Message)
	}
	nx := e.add("admin@acme.example", "nope.beyondnetglobal.com")
	d.nx["nope.beyondnetglobal.com"] = true
	if r := e.verify(nx.ID); !strings.Contains(r.Message, "nope.beyondnetglobal.com: the name does not exist (NXDOMAIN), or has no address or TXT record.") {
		t.Fatalf("nxdomain: %q", r.Message)
	}
	slow := e.add("admin@acme.example", "slow.beyondnetglobal.com")
	d.fail["slow.beyondnetglobal.com"] = &net.DNSError{Err: "i/o timeout", Name: "slow.beyondnetglobal.com", IsTimeout: true}
	if r := e.verify(slow.ID); !strings.Contains(r.Message, "slow.beyondnetglobal.com: no answer within 5 seconds (timeout).") {
		t.Fatalf("timeout: %q", r.Message)
	}
	other := e.add("admin@acme.example", "www.beyondnetglobal.com")
	e.dns.put("www.beyondnetglobal.com", "google-site-verification=abc\x1b[31m\u202e"+strings.Repeat("x", 200))
	r = e.verify(other.ID)
	if !strings.Contains(r.Message, `www.beyondnetglobal.com: one TXT record, not this one: "google-site-verification=abc [31m `) || strings.ContainsAny(r.Message, "\x1b\u202e") || len(r.Message) > 1500 {
		t.Fatalf("other TXT: %q", r.Message)
	}
}
