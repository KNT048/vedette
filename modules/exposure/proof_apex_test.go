package exposure

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// D-632 (kien G10 reopen): a target is proved by its OWN token on a parent name down to its registered domain, the zone apex first:
// git.beyondnetglobal.com (a CNAME, so no TXT can sit on it) is proved by vedette-verify=<git's token> at "@" of beyondnetglobal.com,
// among the zone's other TXT records, with no second domain target. Every rule of the record still holds there.
func TestProof_D632_OwnTokenOnAParentName(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		target string
		setup  func(e *env, d *cnameDNS, own string, others map[string]TargetView)
		ok     bool
		say    string // in the check message
	}{
		{"on the apex, among SPF, Google, Microsoft and a split value", "git.beyondnetglobal.com", func(e *env, _ *cnameDNS, own string, _ map[string]TargetView) {
			e.dns.put("beyondnetglobal.com", "v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all", "google-site-verification=abc123def456",
				"MS=ms12345678",
				txtRecord(own),
				// a value published as several strings of one record: the resolver joins them (Go's LookupTXT)
				"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"+strings.Repeat("Q", 300))
		}, true, "Found the TXT record vedette-verify="},
		{"on an intermediate parent", "a.b.beyondnetglobal.com", func(e *env, _ *cnameDNS, own string, _ map[string]TargetView) {
			e.dns.put("b.beyondnetglobal.com", txtRecord(own))
		}, true, "on b.beyondnetglobal.com: this target's own record on a parent name"},
		{"another target's token on the apex, that target not on the apex", "git.beyondnetglobal.com", func(e *env, _ *cnameDNS, _ string, o map[string]TargetView) {
			e.dns.put("beyondnetglobal.com", txtRecord(o["www.beyondnetglobal.com"].Token))
		}, false, "beyondnetglobal.com: one TXT record, not this one"},
		{"the apex answers through a CNAME", "git.beyondnetglobal.com", func(e *env, d *cnameDNS, own string, _ map[string]TargetView) {
			d.cname["beyondnetglobal.com"] = "lb.lapsed-vendor.example"
			e.dns.put("lb.lapsed-vendor.example", txtRecord(own))
		}, false, "beyondnetglobal.com is a CNAME to another name"},
		{"a parent that answers through a CNAME", "a.b.beyondnetglobal.com", func(e *env, d *cnameDNS, own string, _ map[string]TargetView) {
			d.cname["b.beyondnetglobal.com"] = "tenant.vendor.example"
			e.dns.put("tenant.vendor.example", txtRecord(own))
		}, false, "b.beyondnetglobal.com is a CNAME to another name"},
		{"the apex has TXT records, none ours", "git.beyondnetglobal.com", func(e *env, _ *cnameDNS, _ string, _ map[string]TargetView) {
			e.dns.put("beyondnetglobal.com", "v=spf1 include:_spf.google.com ~all", "google-site-verification=abc123def456", "MS=ms12345678")
		}, false, `beyondnetglobal.com: 3 TXT records, none of them this one (the first is "v=spf1 include:_spf.google.com ~all")`},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e, d := newProofEnv(t)
			v := e.add("admin@acme.example", c.target)
			others := map[string]TargetView{"www.beyondnetglobal.com": e.add("admin@acme.example", "www.beyondnetglobal.com")}
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

// D-632: the scan gate (INV-1 (c)) accepts the apex record the same way, and the scan tells the executors to check that record:
// ZAP gets the apex and this target's own token (ScanTarget.Proof); a public suffix is never asked.
func TestProof_D632_TheGateAndTheScanUseTheApexRecord(t *testing.T) {
	t.Parallel()
	e, _ := newProofEnv(t)
	git := e.add("admin@acme.example", "git.beyondnetglobal.com")
	e.dns.put("beyondnetglobal.com", "v=spf1 -all", txtRecord(git.Token)) // kien's apex: nothing else changes
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
	if p := run.last.Proof; p == nil || p.Domain != "beyondnetglobal.com" || p.Token != git.Token {
		t.Fatalf("scan proof %+v", run.last.Proof)
	}
	e.dns.put("beyondnetglobal.com", "v=spf1 -all") // the record goes: blocked at the next gate
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), "scan", git.ID); ok || why != BlockedTxtMissing {
		t.Fatalf("record gone: %v %v", ok, why)
	}

	// a public suffix is never asked: beyondhcm.ddns.net's own token on ddns.net proves nothing and ddns.net is not looked up
	e2, _ := newProofEnv(t)
	dd := e2.add("admin@acme.example", "x.beyondhcm.ddns.net")
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
	if p := dd.Proof; p == nil || p.Zone != "beyondhcm.ddns.net" || p.Host != "@" || p.AltHost == nil || *p.AltHost != "_vedette-verify.x" {
		t.Fatalf("hint %+v", p)
	}
}

// D-632: the deep step of a target proved by its own token on the apex goes out for the target itself (its box-bound token, the
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
