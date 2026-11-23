package exposure

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A target is proved by its OWN token on a parent name down to its registered domain, the zone apex first:
// git.example.org (a CNAME, so no TXT can sit on it) is proved by vedette-verify=<git's token> at "@" of example.org,
// among the zone's other TXT records, with no second domain target. Every rule of the record still holds there.
func TestProof_OwnTokenOnAParentName(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		target string
		setup  func(e *env, d *cnameDNS, own string, others map[string]TargetView)
		ok     bool
		say    string // in the check message
	}{
		{"on the apex, among SPF, Google, Microsoft and a split value", "git.example.org", func(e *env, _ *cnameDNS, own string, _ map[string]TargetView) {
			e.dns.put("example.org", "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all", "google-site-verification=abc123def456",
				"MS=ms12345678",
				txtRecord(own),
				// a value published as several strings of one record: the resolver joins them (Go's LookupTXT)
				"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"+strings.Repeat("Q", 300))
		}, true, "Found the TXT record vedette-verify="},
		{"on an intermediate parent", "a.b.example.org", func(e *env, _ *cnameDNS, own string, _ map[string]TargetView) {
			e.dns.put("b.example.org", txtRecord(own))
		}, true, "on b.example.org: this target's own record on a parent name"},
		{"the apex answers through a CNAME", "git.example.org", func(e *env, d *cnameDNS, own string, _ map[string]TargetView) {
			d.cname["example.org"] = "lb.lapsed-vendor.example"
			e.dns.put("lb.lapsed-vendor.example", txtRecord(own))
		}, false, "example.org is a CNAME to another name"},
		{"a parent that answers through a CNAME", "a.b.example.org", func(e *env, d *cnameDNS, own string, _ map[string]TargetView) {
			d.cname["b.example.org"] = "tenant.vendor.example"
			e.dns.put("tenant.vendor.example", txtRecord(own))
		}, false, "b.example.org is a CNAME to another name"},
		{"the apex has TXT records, none ours", "git.example.org", func(e *env, _ *cnameDNS, _ string, _ map[string]TargetView) {
			e.dns.put("example.org", "v=spf1 include:_spf.google.com ~all", "google-site-verification=abc123def456", "MS=ms12345678")
		}, false, `example.org: 3 TXT records, none of them this one (the first is "v=spf1 include:_spf.google.com ~all")`},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e, d := newProofEnv(t)
			v := e.add("admin@acme.example", c.target)
			others := map[string]TargetView{"www.example.org": e.add("admin@acme.example", "www.example.org")}
			c.setup(e, d, v.Token, others)
			r := e.verify(v.ID)
			if r.Verified != c.ok || !strings.Contains(r.Message, c.say) {
				t.Fatalf("verified %v, message %q", r.Verified, r.Message)
			}
			if !c.ok && strings.Contains(r.Message, "Found") {
				t.Fatalf("a record that is not ours was taken for ours: %q", r.Message)
			}
		})
	}
}

// The scan gate (INV-1 (c)) accepts the apex record the same way, and the scan tells the executors to check that record:
// ZAP gets the apex and this target's own token (ScanTarget.Proof); a public suffix is never asked.
func TestProof_TheGateAndTheScanUseTheApexRecord(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	git := e.add("admin@acme.example", "git.example.org")
	e.dns.put("example.org", "v=spf1 -all", txtRecord(git.Token)) // an apex with an SPF record: nothing else changes
	if r := e.verify(git.ID); !r.Verified {
		t.Fatalf("%+v", r)
	}
	if ok, why, err := e.svc.CheckScannable(e.ctx(), "scan", git.ID); err != nil || why == BlockedTxtMissing || why == BlockedUnverified {
		t.Fatalf("gate: %v %v %v", ok, why, err)
	}
	run := &fakeRunner{content: Content{}}
	e.svc.SetRunner(run)
	if _, err := e.commit(git.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", git.ID); err != nil {
		t.Fatal(err)
	}
	// ZAP is told the target itself, its own token and where its record sits, never the apex as the domain
	if p := run.last.Proof; p == nil || p.Domain != "git.example.org" || p.ProofAt != "example.org" || p.Token != git.Token {
		t.Fatalf("scan proof %+v", run.last.Proof)
	}
	e.dns.put("example.org", "v=spf1 -all") // the record goes: blocked at the next gate
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), "scan", git.ID); ok || why != BlockedTxtMissing {
		t.Fatalf("record gone: %v %v", ok, why)
	}

	// a public suffix is never asked: example.ddns.net's own token on ddns.net proves nothing and ddns.net is not looked up
	e2, _ := newProofEnv(t)
	dd := e2.add("admin@acme.example", "x.example.ddns.net")
	e2.dns.put("ddns.net", txtRecord(dd.Token))
	if r := e2.verify(dd.ID); r.Verified {
		t.Fatalf("a public suffix: %+v", r)
	}
	e2.dns.mu.Lock()
	asked := slices.Clone(e2.dns.asks)
	e2.dns.mu.Unlock()
	for _, n := range asked {
		if n = strings.TrimSuffix(n, "."); n == "ddns.net" || strings.HasSuffix(n, "_vedette-verify.ddns.net") || strings.Count(n, ".") < 2 {
			t.Fatalf("asked %q (all %v)", n, asked)
		}
	}
	if p := dd.Proof; p == nil || p.Zone != "example.ddns.net" || p.Host != "@" || p.AltHost == nil || *p.AltHost != "_vedette-verify.x" {
		t.Fatalf("hint %+v", p)
	}
}

// The deep step of a target proved by its own token on the apex goes out for the target itself (its box-bound token, the
// name the host listed) with ProofAt = the apex, so the executors' fence looks for that token there.
func TestContract_INV28_Deep_OwnTokenOnTheApexSetsProofAt(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	child, err := d.svc.AddDomain(d.ctx(), "admin@acme.example", "git.acme.example")
	if err != nil {
		t.Fatal(err)
	}
	d.dns.put("acme.example", txtRecord(d.dom.Token), txtRecord(child.Token)) // the child's own token at the apex comes first
	if r := d.verify(child.ID); !r.Verified || !strings.Contains(r.Message, "this target's own record on a parent name") {
		t.Fatalf("%+v", r)
	}
	if _, err := d.commit(child.ID); err != nil {
		t.Fatal(err)
	}
	d.acceptTerms(child.ID, false)
	d.dns.point("git.acme.example", ipB)
	st := ScanTarget{ID: child.ID, Kind: KindDomain, Value: "git.acme.example", User: "admin@acme.example", Mode: ScanMode{Full: true}}
	out, why, err := d.svc.deepGate(d.ctx(), st, netip.MustParseAddr(ipB), []string{"git.acme.example"})
	if err != nil || why != "" || out.Domain == nil || out.Domain.Domain != "git.acme.example" || out.Domain.ProofAt != "acme.example" || out.Domain.Name != "git.acme.example" {
		t.Fatalf("scope %+v %q %v", out.Domain, why, err)
	}
}

// deadlineDNS records the deadline of every lookup; names in block wait until their context ends and report how it ended.
type deadlineDNS struct {
	*cnameDNS
	mu        sync.Mutex
	deadlines []time.Time
	block     map[string]bool
	ended     chan error
}

func (d *deadlineDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	dl, _ := ctx.Deadline()
	d.mu.Lock()
	d.deadlines = append(d.deadlines, dl)
	d.mu.Unlock()
	if d.block[strings.TrimSuffix(name, ".")] {
		<-ctx.Done()
		d.ended <- ctx.Err()
		return nil, ctx.Err()
	}
	return d.cnameDNS.LookupTXT(ctx, name)
}

// A check has one DNS budget (every lookup ends by the same deadline), and as soon as the nearest valid record
// is known the lookups still running are stopped.
func TestProof_OneBudgetAndTheRestStop(t *testing.T) {
	t.Parallel()
	e, c := newProofEnv(t)
	d := &deadlineDNS{cnameDNS: c, block: map[string]bool{}, ended: make(chan error, 8)}
	e.svc.cfg.Resolver = d
	v := e.add("admin@acme.example", "a.b.example.org")
	r := e.verify(v.ID) // nothing anywhere: every lookup, the explanation's included
	d.mu.Lock()
	all := slices.Clone(d.deadlines)
	d.deadlines = nil
	d.mu.Unlock()
	if r.Verified || len(all) < 6 {
		t.Fatalf("%+v, %d lookups", r, len(all))
	}
	for _, dl := range all {
		if dl.IsZero() || !dl.Equal(all[0]) {
			t.Fatalf("deadlines %v: not one budget", all)
		}
	}
	e.dns.put("a.b.example.org", txtRecord(v.Token)) // the nearest record; the apex never answers
	d.block["example.org"] = true
	if r := e.verify(v.ID); !r.Verified || !strings.Contains(r.Message, "on a.b.example.org") {
		t.Fatalf("%+v", r)
	}
	select {
	case err := <-d.ended:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the apex lookup ended with %v, want cancelled", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the apex lookup was not stopped")
	}
}

// A target whose stored token is older than the value the box binds to it (added by an older release, or while the
// host gave none) keeps passing Check on its stored token, and the message names the bound value the deep steps check.
func TestProof_AnOlderTokenNamesTheBoundValue(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	git := e.add("admin@acme.example", "git.example.org") // random token: no fence at add time
	e.svc.cfg.DomainFence = &fakeFence{}
	e.dns.put("example.org", txtRecord(git.Token))
	r := e.verify(git.ID)
	if !r.Verified || !strings.Contains(r.Message, "add the TXT record vedette-verify="+deepToken+" on example.org too, keeping the current one") {
		t.Fatalf("%+v", r)
	}
}
