package exposure

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/domainfence"
)

// authDNS is the box's resolver (fakeResolver, its answers possibly cached and stale) with the zone's own name servers behind it:
// auth is what they answer for a name (rooted or not), none for a name they do not hold.
type authDNS struct {
	*fakeResolver
	mu    sync.Mutex
	auth  map[string]domainfence.AuthAnswer
	asked int
}

func (d *authDNS) AuthTXT(_ context.Context, name string) (domainfence.AuthAnswer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked++
	if a, ok := d.auth[strings.TrimSuffix(name, ".")]; ok {
		return a, nil
	}
	return domainfence.AuthAnswer{Servers: []string{"ns1.dns-host.example", "ns2.dns-host.example"}}, nil
}

func (d *authDNS) serve(name string, all, some []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.auth[name] = domainfence.AuthAnswer{Servers: []string{"ns1.dns-host.example", "ns2.dns-host.example"}, TXT: all, Some: some}
}

func newAuthEnv(t *testing.T) (*env, *authDNS) {
	t.Helper()
	e := newEnv(t)
	d := &authDNS{fakeResolver: e.dns, auth: map[string]domainfence.AuthAnswer{}}
	e.useService(Config{DB: e.db, Audit: audit.New(e.clock.Now), Resolver: d, Prober: e.prober, Publisher: e.pub, Log: slog.New(slog.DiscardHandler), Clock: e.clock.Now, Location: time.UTC})
	return e, d
}

// A record just put in place counts as soon as the zone's own name servers all serve it, while the box's resolver still answers
// the previous install's token from its cache; the scan gate agrees. Servers without it, or only some of them with it, prove
// nothing, and the message says which, instead of asking the person to check what they pasted.
func TestProof_ZoneServersPastAStaleResolver(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		serve    func(d *authDNS, tok string)
		verified bool
		says     string
	}{
		{name: "every server serves it", serve: func(d *authDNS, tok string) {
			d.serve("example.org", []string{"v=spf1 -all", txtRecord(tok)}, []string{"v=spf1 -all", txtRecord(tok)})
		}, verified: true, says: "Read from the zone's own name servers: this box's DNS resolver still has an older answer cached."},
		{name: "on the _vedette-verify name", serve: func(d *authDNS, tok string) {
			d.serve("_vedette-verify.example.org", []string{txtRecord(tok)}, []string{txtRecord(tok)})
		}, verified: true, says: "on _vedette-verify.example.org. Read from the zone's own name servers"},
		{name: "no server serves it", serve: func(d *authDNS, _ string) {
			d.serve("example.org", []string{"vedette-verify=0000000000000000"}, []string{"vedette-verify=0000000000000000"})
		}, says: "The zone's own name servers (ns1.dns-host.example, ns2.dns-host.example) were asked directly too, and they do not serve it either"},
		{name: "only some of them serve it", serve: func(d *authDNS, tok string) {
			d.serve("example.org", []string{"v=spf1 -all"}, []string{"v=spf1 -all", txtRecord(tok)})
		}, says: "Your DNS provider serves the record on some of the zone's name servers"},
		{name: "the name is a CNAME at its servers", serve: func(d *authDNS, tok string) {
			d.mu.Lock()
			d.auth["example.org"] = domainfence.AuthAnswer{Servers: []string{"ns1.dns-host.example"}, TXT: []string{txtRecord(tok)}, Some: []string{txtRecord(tok)}, CNAME: true}
			d.mu.Unlock()
		}, says: "Not counted: example.org is a CNAME"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e, d := newAuthEnv(t)
			tg := e.add("admin@acme.example", "example.org")
			e.dns.put("example.org", "v=spf1 -all", "vedette-verify=0000000000000000") // the previous install's token, cached
			c.serve(d, tg.Token)
			r := e.verify(tg.ID)
			if r.Verified != c.verified || !strings.Contains(r.Message, c.says) || strings.Contains(r.Message, "extra quotes") {
				t.Fatalf("%+v", r)
			}
			if !c.verified {
				return
			}
			if _, err := e.commit(tg.ID); err != nil {
				t.Fatal(err)
			}
			if ok, why, _ := e.svc.CheckScannable(e.ctx(), "scan", tg.ID); !ok || why != "" {
				t.Fatalf("the scan gate disagrees: %v %q", ok, why)
			}
		})
	}
}

// The resolver's own answer, when it proves the name, is enough: the zone's servers are not asked.
func TestProof_ZoneServersOnlyWhenTheResolverProvesNothing(t *testing.T) {
	t.Parallel()
	e, d := newAuthEnv(t)
	tg := e.add("admin@acme.example", "example.org")
	e.dns.put("example.org", txtRecord(tg.Token))
	if r := e.verify(tg.ID); !r.Verified || strings.Contains(r.Message, "name servers") {
		t.Fatalf("%+v", r)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.asked != 0 {
		t.Fatalf("the zone's servers were asked %d times", d.asked)
	}
}

// A failed lookup is no answer: the zone's servers are asked only after a definite answer of the resolver (a validating resolver
// fails on a forged answer, and the servers asked directly are not validated), so the check stays unverified and they are not asked.
func TestProof_ZoneServersNotAskedWhenTheResolverFails(t *testing.T) {
	t.Parallel()
	e, d := newAuthEnv(t)
	tg := e.add("admin@acme.example", "example.org")
	d.serve("example.org", []string{txtRecord(tg.Token)}, []string{txtRecord(tg.Token)})
	e.dns.mu.Lock()
	e.dns.err = &net.DNSError{Err: "server misbehaving", Name: "example.org", IsTemporary: true}
	e.dns.mu.Unlock()
	if r := e.verify(tg.ID); r.Verified {
		t.Fatalf("%+v", r)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.asked != 0 {
		t.Fatalf("the zone's servers were asked %d times after the resolver failed", d.asked)
	}
}

// A resolver that cannot ask the zone's servers keeps the old behaviour, and the hint names the resolver's cache, not the person.
func TestProof_NoZoneServersHintNamesTheCache(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tg := e.add("admin@acme.example", "example.org")
	e.dns.put("example.org", "vedette-verify=0000000000000000")
	r := e.verify(tg.ID)
	if r.Verified || !strings.Contains(r.Message, "a resolver may keep an older answer until the record's TTL runs out") || strings.Contains(r.Message, "name servers") {
		t.Fatalf("%+v", r)
	}
}
