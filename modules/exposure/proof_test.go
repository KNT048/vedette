package exposure

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
)

// cnameDNS is fakeResolver with CNAMEs, names that do not exist and per-name failures, the way a real resolver answers: the TXT lookup
// of a CNAME follows it, a name that does not exist is "no such host" (NXDOMAIN).
type cnameDNS struct {
	*fakeResolver
	cname map[string]string // name -> canonical name
	nx    map[string]bool   // names that do not exist
	fail  map[string]error  // TXT lookups that fail
}

func (d *cnameDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if err := d.fail[name]; err != nil {
		return nil, err
	}
	if d.nx[name] {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	if c, ok := d.cname[name]; ok {
		name = c
	}
	v, err := d.fakeResolver.LookupTXT(ctx, name)
	if err == nil && len(v) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return v, err
}

func (d *cnameDNS) LookupCNAME(_ context.Context, name string) (string, error) {
	if d.nx[name] {
		return "", &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	if c, ok := d.cname[name]; ok {
		return c + ".", nil
	}
	return name + ".", nil
}

// newProofEnv is newEnv with the CNAME-aware resolver: git.beyondnetglobal.com is a CNAME to beyondhcm.ddns.net (kien's case).
func newProofEnv(t *testing.T) (*env, *cnameDNS) {
	t.Helper()
	e := newEnv(t)
	d := &cnameDNS{fakeResolver: e.dns, cname: map[string]string{"git.beyondnetglobal.com": "beyondhcm.ddns.net"}, nx: map[string]bool{}, fail: map[string]error{}}
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
// its parent was verified is covered when the parent is; another user's target of the same box covers too; the parent removed from
// the box, or its record removed, covers the child no more at its next check (the one right before a scan).
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
	if r := e.verify(child.ID); !r.Verified || !strings.HasPrefix(r.Message, "Found the TXT record of beyondnetglobal.com on beyondnetglobal.com: it proves beyondnetglobal.com and every name under it, git.beyondnetglobal.com included.") {
		t.Fatalf("child's own check: %+v", r)
	}
	if ok, why, err := e.svc.CheckScannable(e.ctx(), "scan", child.ID); err != nil || why == BlockedTxtMissing || why == BlockedUnverified {
		t.Fatalf("covered child at the scan gate: %v %v %v", ok, why, err)
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
	// the child's own token on its parent proves the parent's zone, so the child too
	e.dns.put("beyondnetglobal.com", txtRecord(child.Token))
	if r := e.verify(child.ID); !r.Verified || !strings.Contains(r.Message, "on beyondnetglobal.com: it proves beyondnetglobal.com and every name under it") {
		t.Fatalf("own token on the parent: %+v", r)
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
	// a record on ddns.net with this box's own token proves nothing for a name under it
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
}

// D-628: git.beyondnetglobal.com is a CNAME, so its provider refuses a TXT beside it ("Record could not be added"); the record on
// _vedette-verify.git.beyondnetglobal.com proves it, and the scan gate accepts it.
func TestProof_D628_VerifyLabelUnderACNAME(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	v := e.add("admin@acme.example", "git.beyondnetglobal.com")
	if p := v.Proof; p == nil || p.Zone != "beyondnetglobal.com" || p.Host != "git" || p.AltHost != "_vedette-verify.git" || p.CoveredBy != nil {
		t.Fatalf("hint %+v", p)
	}
	e.dns.put("_vedette-verify.git.beyondnetglobal.com", txtRecord(v.Token))
	r := e.verify(v.ID)
	if !r.Verified || r.Message != "Found the TXT record vedette-verify="+v.Token+" on _vedette-verify.git.beyondnetglobal.com." {
		t.Fatalf("%+v", r)
	}
	if _, why, err := e.svc.CheckScannable(e.ctx(), "scan", v.ID); err != nil || why == BlockedTxtMissing {
		t.Fatalf("gate: %v %v", why, err)
	}
	a := e.add("admin@acme.example", "beyondnetglobal.com")
	if p := a.Proof; p == nil || p.Host != "@" || p.AltHost != "_vedette-verify" {
		t.Fatalf("apex hint %+v", p)
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
		"No TXT record vedette-verify=" + git.Token + " was found. Vedette asked git.beyondnetglobal.com, _vedette-verify.git.beyondnetglobal.com, beyondnetglobal.com, _vedette-verify.beyondnetglobal.com.",
		"git.beyondnetglobal.com: a CNAME to beyondhcm.ddns.net, so a TXT record cannot sit on this name: put it on _vedette-verify.git.beyondnetglobal.com instead, or verify a parent domain.",
		"_vedette-verify.git.beyondnetglobal.com: no TXT record.",
		"beyondnetglobal.com: no TXT record.",
	} {
		if r.Verified || !strings.Contains(r.Message, want) {
			t.Fatalf("missing %q in %q", want, r.Message)
		}
	}
	nx := e.add("admin@acme.example", "nope.beyondnetglobal.com")
	d.nx["nope.beyondnetglobal.com"] = true
	if r := e.verify(nx.ID); !strings.Contains(r.Message, "nope.beyondnetglobal.com: the name does not exist (NXDOMAIN).") {
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
	if !strings.Contains(r.Message, `www.beyondnetglobal.com: one TXT record, not this one: "google-site-verification=abc [31m `) || strings.ContainsAny(r.Message, "\x1b\u202e") || len(r.Message) > 1200 {
		t.Fatalf("other TXT: %q", r.Message)
	}
}
