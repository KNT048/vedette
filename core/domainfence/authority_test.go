package domainfence

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeServer is one name server of the fake world: what it serves and how it misbehaves.
type fakeServer struct {
	zone      string              // the zone it answers for with authority
	txt       map[string][]string // name -> its TXT values (each one record of one string)
	cname     map[string]string   // name -> canonical name (answered in place of the TXT)
	wild      []string            // TXT values a wildcard "*.zone" answers for every name with no record of its own
	delegated string              // a child zone it only refers to (a referral without authority)
	noAA      bool                // answers without the authoritative flag (a recursive resolver listed as a name server)
	silent    bool                // never answers (a timeout)
	badID     bool                // answers with another message id
	otherName string              // answers a TXT record carrying the token on this owner name instead of the name asked
	otherQ    string              // answers a question about this name instead of the one asked
	refused   bool                // answers REFUSED (a lame server)
	squat     string              // a more specific zone it also hosts for someone else: names under it are answered from it
}

// apex is the zone the server answers name from: its squat zone for a name under that, else its own zone.
func (s *fakeServer) apex(name string) string {
	if s.squat != "" && (name == s.squat || strings.HasSuffix(name, "."+s.squat)) {
		return s.squat
	}
	return s.zone
}

// fakeZones is the zone's own name servers as the box would reach them: NS records and addresses through the box's resolver
// (ns, addr), then one exchange per server (servers). It records every server asked.
type fakeZones struct {
	mu      sync.Mutex
	ns      map[string][]string     // zone -> its name server host names (the box resolver's NS answer)
	cname   map[string]string       // name -> canonical name: an NS question for it is answered with the target's NS records
	addr    map[string][]netip.Addr // name server host -> addresses
	servers map[netip.Addr]*fakeServer
	asked   []netip.Addr
	nsAsked []string
}

func (z *fakeZones) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	name = strings.TrimSuffix(name, ".")
	z.mu.Lock()
	defer z.mu.Unlock()
	z.nsAsked = append(z.nsAsked, name)
	if cn, ok := z.cname[name]; ok { // a recursive resolver follows the CNAME, and LookupNS takes every NS record of the answer
		name = cn
	}
	hosts, ok := z.ns[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	var out []*net.NS
	for _, h := range hosts {
		out = append(out, &net.NS{Host: h + "."})
	}
	return out, nil
}

func (z *fakeZones) LookupCNAME(_ context.Context, name string) (string, error) {
	name = strings.TrimSuffix(name, ".")
	z.mu.Lock()
	defer z.mu.Unlock()
	if cn, ok := z.cname[name]; ok {
		return cn + ".", nil
	}
	if _, ok := z.ns[name]; ok {
		return name + ".", nil
	}
	return "", &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (z *fakeZones) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(host, ".")
	z.mu.Lock()
	defer z.mu.Unlock()
	if a, ok := z.addr[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (z *fakeZones) exchange(ctx context.Context, server netip.Addr, q []byte) ([]byte, error) {
	z.mu.Lock()
	z.asked = append(z.asked, server)
	s := z.servers[server]
	z.mu.Unlock()
	if s == nil || s.silent {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil, err
	}
	question, err := p.Question()
	if err != nil {
		return nil, err
	}
	if h.RecursionDesired {
		return nil, errorf("the query asks for recursion")
	}
	name := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	id := h.ID
	if s.badID {
		id++
	}
	rh := dnsmessage.Header{ID: id, Response: true, Authoritative: !s.noAA}
	if s.otherQ != "" {
		question.Name = dnsmessage.MustNewName(s.otherQ + ".")
	}
	var answers, authority []dnsmessage.Resource
	soaRR := func(owner string) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner + "."), Class: dnsmessage.ClassINET, TTL: 300},
			Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns1.dns-host.example."), MBox: dnsmessage.MustNewName("hostmaster.dns-host.example."), Serial: 1}}
	}
	apex := s.apex(name)
	txtRR := func(owner, v string) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(owner + "."), Class: dnsmessage.ClassINET, TTL: 300},
			Body: &dnsmessage.TXTResource{TXT: []string{v}}}
	}
	switch {
	case s.refused:
		rh.RCode = dnsmessage.RCodeRefused
		rh.Authoritative = false
	case s.delegated != "" && (name == s.delegated || strings.HasSuffix(name, "."+s.delegated)):
		rh.Authoritative = false // a referral: the authority section would hold the child's NS records
	case question.Type == dnsmessage.TypeSOA && s.cname[name] != "":
		answers = append(answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name + "."), Class: dnsmessage.ClassINET, TTL: 300},
			Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(s.cname[name] + ".")}})
	case question.Type == dnsmessage.TypeSOA && name == apex:
		answers = append(answers, soaRR(apex))
	case question.Type == dnsmessage.TypeSOA && strings.HasSuffix(name, "."+apex):
		authority = append(authority, soaRR(apex)) // no SOA at the name: the zone's SOA comes in the authority section
		if s.txt[name] == nil && s.wild == nil {
			rh.RCode = dnsmessage.RCodeNameError
		}
	case question.Type == dnsmessage.TypeSOA:
		rh.RCode = dnsmessage.RCodeRefused
		rh.Authoritative = false
	case s.otherName != "":
		answers = append(answers, txtRR(s.otherName, s.txt[s.otherName][0]))
	case s.cname[name] != "":
		cn := s.cname[name]
		answers = append(answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name + "."), Class: dnsmessage.ClassINET, TTL: 300},
			Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(cn + ".")}})
		for _, v := range s.txt[cn] { // the target's records too, when the server holds them
			answers = append(answers, txtRR(cn, v))
		}
	case s.txt[name] != nil:
		for _, v := range s.txt[name] {
			answers = append(answers, txtRR(name, v))
		}
	case s.wild != nil && strings.HasSuffix(name, "."+s.zone):
		for _, v := range s.wild {
			answers = append(answers, txtRR(name, v))
		}
	case name != s.zone && !strings.HasSuffix(name, "."+s.zone):
		rh.RCode = dnsmessage.RCodeRefused
		rh.Authoritative = false
	default:
		rh.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, rh)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(question); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, a := range answers {
		switch body := a.Body.(type) {
		case *dnsmessage.TXTResource:
			err = b.TXTResource(a.Header, *body)
		case *dnsmessage.CNAMEResource:
			err = b.CNAMEResource(a.Header, *body)
		case *dnsmessage.SOAResource:
			err = b.SOAResource(a.Header, *body)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := b.StartAuthorities(); err != nil {
		return nil, err
	}
	for _, a := range authority {
		if err := b.SOAResource(a.Header, *a.Body.(*dnsmessage.SOAResource)); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func (z *fakeZones) askedServers() []netip.Addr {
	z.mu.Lock()
	defer z.mu.Unlock()
	return slices.Clone(z.asked)
}

type testErr string

func (e testErr) Error() string { return string(e) }

func errorf(s string) error { return testErr(s) }

// staleDNS is the box's resolver with an older answer cached (the previous token) and the zone's own name servers behind it.
type staleDNS struct {
	*fakeDNS
	auth *Authoritative
}

func (d staleDNS) AuthTXT(ctx context.Context, name string) (AuthAnswer, error) {
	return d.auth.AuthTXT(ctx, name)
}

var (
	ns1 = netip.MustParseAddr("97.74.104.44")
	ns2 = netip.MustParseAddr("173.201.72.44")
	nsA = netip.MustParseAddr("45.79.0.53") // a public name server of another zone
)

// authWorld is acme.example: the box's resolver still answers the previous install's token (cached), while the zone's two name
// servers already serve this box's token. Each case changes what it needs.
func authWorld(token string) (*fakeDNS, *fakeZones) {
	r := world()
	r.txt["acme.example"] = []string{"v=spf1 -all", "vedette-verify=0000000000000000"}
	serve := func() *fakeServer {
		return &fakeServer{zone: "acme.example", txt: map[string][]string{"acme.example": {"v=spf1 -all", "vedette-verify=" + token}}, cname: map[string]string{}}
	}
	z := &fakeZones{
		ns:      map[string][]string{"acme.example": {"ns1.dns-host.example", "ns2.dns-host.example"}, "attacker.example": {"ns.attacker.example"}},
		addr:    map[string][]netip.Addr{"ns1.dns-host.example": {ns1}, "ns2.dns-host.example": {ns2}, "ns.attacker.example": {nsA}},
		servers: map[netip.Addr]*fakeServer{ns1: serve(), ns2: serve()},
	}
	return r, z
}

func ownedWith(t *testing.T, r *fakeDNS, z *fakeZones, domain, token string) Proof {
	t.Helper()
	d := staleDNS{fakeDNS: r, auth: &Authoritative{R: z, Exchange: z.exchange}}
	return Owned(t.Context(), d, domain, token, 2*time.Second)
}

// The class matrix of the authoritative check: a resolver's stale answer is overruled only by the zone's own name servers, all of
// those that answer with authority agreeing, for the name asked itself, never through a CNAME or a wildcard.
func TestOwnedAsksTheZonesOwnServers(t *testing.T) {
	t.Parallel()
	tok := Token(key1, "acme.example")
	cases := []struct {
		name        string
		domain      string
		change      func(r *fakeDNS, z *fakeZones)
		at          string
		auth        bool // At found by the zone's own servers
		propagating bool
		servers     bool // the zone's own servers answered (Servers set)
		unchecked   bool
		refused     bool
		notAsked    bool // the zone's own servers must not be asked at all
	}{
		{name: "stale resolver, both servers serve the record", domain: "acme.example", at: "acme.example", auth: true, servers: true},
		{name: "the resolver already has it: the servers are not asked", domain: "acme.example",
			change: func(r *fakeDNS, z *fakeZones) {
				r.txt["acme.example"] = []string{"vedette-verify=" + tok}
				z.servers = nil
			}, at: "acme.example"},
		{name: "the servers do not serve it either", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				for _, s := range z.servers {
					s.txt["acme.example"] = []string{"vedette-verify=0000000000000000"}
				}
			}, servers: true},
		{name: "one server has it, the other not yet", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) { z.servers[ns2].txt["acme.example"] = []string{"v=spf1 -all"} }, propagating: true, servers: true},
		{name: "one server times out, the other has it", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) { z.servers[ns2].silent = true }, at: "acme.example", auth: true, servers: true},
		{name: "a lame server refuses, the other has it", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) { z.servers[ns2].refused = true }, at: "acme.example", auth: true, servers: true},
		{name: "every server times out", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) { z.servers[ns1].silent, z.servers[ns2].silent = true, true }},
		{name: "answers without authority (a recursive resolver listed as a server)", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) { z.servers[ns1].noAA, z.servers[ns2].noAA = true, true }},
		{name: "a server answering for a parent only (a referral)", domain: "git.acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				for _, s := range z.servers {
					s.delegated = "git.acme.example"
					s.txt["git.acme.example"] = []string{"vedette-verify=" + tok}
				}
			}},
		{name: "the record answered on another owner name", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				for _, s := range z.servers {
					s.txt["evil.example"] = []string{"vedette-verify=" + tok}
					s.otherName = "evil.example"
				}
			}, servers: true},
		{name: "an answer to another question", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				for _, s := range z.servers {
					s.otherQ = "evil.example"
				}
			}},
		{name: "an answer with another message id", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) { z.servers[ns1].badID, z.servers[ns2].badID = true, true }},
		{name: "a server on a private address is never asked", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				z.addr["ns1.dns-host.example"] = []netip.Addr{netip.MustParseAddr("10.0.0.53")}
				z.addr["ns2.dns-host.example"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
			}},
		{name: "the parent zone's servers claim every name, the zone's own deny it", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				// a public server of the parent zone answers every name under it with authority: it is not a server of acme.example,
				// so it is never asked, and acme.example's own servers decide
				z.ns["example"] = []string{"ns.attacker.example"}
				z.servers[nsA] = &fakeServer{zone: "example", cname: map[string]string{}, txt: map[string][]string{
					"acme.example": {"vedette-verify=" + tok}, "_vedette-verify.acme.example": {"vedette-verify=" + tok}}}
				for _, s := range []netip.Addr{ns1, ns2} {
					z.servers[s].txt["acme.example"] = []string{"v=spf1 -all"}
				}
			}, servers: true},
		{name: "the zone has no NS of its own: the parent's servers are not asked in its place", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				delete(z.ns, "acme.example")
				z.ns["example"] = []string{"ns.attacker.example"}
				z.servers[nsA] = &fakeServer{zone: "example", cname: map[string]string{}, txt: map[string][]string{
					"acme.example": {"vedette-verify=" + tok}, "_vedette-verify.acme.example": {"vedette-verify=" + tok}}}
			}},
		{name: "another customer's zone for the _vedette-verify name on the same servers", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				// shared DNS hosting: someone created the zone _vedette-verify.acme.example at the provider. acme.example does not
				// delegate it, so a resolver never reaches it, but the provider's servers answer its names with authority.
				for _, s := range z.servers {
					s.txt["acme.example"] = []string{"v=spf1 -all"}
					s.squat = "_vedette-verify.acme.example"
					s.txt["_vedette-verify.acme.example"] = []string{"vedette-verify=" + tok}
				}
			}, servers: true},
		{name: "another customer's zone for the checked name itself on the same servers", domain: "git.acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				for _, s := range z.servers {
					s.squat = "git.acme.example"
					s.txt["git.acme.example"] = []string{"vedette-verify=" + tok}
				}
			}},
		{name: "the registered domain is a CNAME: its target's servers are not the zone's", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				// a dangling CNAME to a domain someone else registers: its servers claim acme.example's names with authority
				z.cname = map[string]string{"acme.example": "attacker.example"}
				z.servers[nsA] = &fakeServer{zone: "acme.example", cname: map[string]string{}, txt: map[string][]string{
					"acme.example": {"vedette-verify=" + tok}, "_vedette-verify.acme.example": {"vedette-verify=" + tok}}}
			}},
		{name: "the name is a CNAME at its servers: its target's record does not count", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				for _, s := range z.servers {
					s.cname["acme.example"] = "acme.vendor.example"
					s.txt["acme.vendor.example"] = []string{"vedette-verify=" + tok}
					s.zone = "example"
				}
				for _, s := range z.servers {
					delete(s.txt, "acme.example")
				}
			}, servers: true},
		{name: "a wildcard answers the _vedette-verify name", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				for _, s := range z.servers {
					s.txt["acme.example"] = []string{"v=spf1 -all"}
					s.wild = []string{"vedette-verify=" + tok}
				}
			}, servers: true, refused: true},
		{name: "the record on the _vedette-verify name", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) {
				for _, s := range z.servers {
					s.txt["acme.example"] = []string{"v=spf1 -all"}
					s.txt["_vedette-verify.acme.example"] = []string{"vedette-verify=" + tok}
				}
			}, at: "_vedette-verify.acme.example", auth: true, servers: true},
		{name: "no NS answer for the zone", domain: "acme.example",
			change: func(_ *fakeDNS, z *fakeZones) { delete(z.ns, "acme.example") }},
		// A failed lookup is no answer: a validating resolver answers SERVFAIL for a forged (DNSSEC-bogus) answer, and the zone's
		// servers asked directly are not validated, so they are asked only after a definite answer (records, or no such name).
		{name: "the resolver fails and the servers serve it", domain: "acme.example",
			change: func(r *fakeDNS, _ *fakeZones) { r.fail["acme.example"] = true }, unchecked: true, notAsked: true},
		{name: "the resolver fails on the _vedette-verify name only", domain: "acme.example",
			change: func(r *fakeDNS, z *fakeZones) {
				r.fail["_vedette-verify.acme.example"] = true
				for _, s := range z.servers {
					s.txt["acme.example"] = []string{"v=spf1 -all"}
					s.txt["_vedette-verify.acme.example"] = []string{"vedette-verify=" + tok}
				}
			}, unchecked: true, notAsked: true},
		{name: "the resolver fails and the servers do not answer", domain: "acme.example",
			change: func(r *fakeDNS, z *fakeZones) {
				r.fail["acme.example"] = true
				z.servers[ns1].silent, z.servers[ns2].silent = true, true
			}, unchecked: true, notAsked: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) { // a silent server times out on the bubble's clock
				r, z := authWorld(tok)
				if c.change != nil {
					c.change(r, z)
				}
				p := ownedWith(t, r, z, c.domain, tok)
				if p.At != c.at || p.Authoritative != c.auth || p.Propagating != c.propagating || (len(p.Servers) > 0) != c.servers ||
					p.Unchecked != c.unchecked || p.Refused != c.refused {
					t.Fatalf("got %+v", p)
				}
				if c.notAsked && len(z.askedServers()) > 0 {
					t.Fatalf("asked %v after the resolver failed", z.askedServers())
				}
				for _, a := range z.askedServers() {
					if a != ns1 && a != ns2 {
						t.Fatalf("asked %s, not a name server of acme.example", a)
					}
				}
			})
		})
	}
}

// The name servers asked are always those of the registered domain of the name checked, looked up by the box's resolver: never
// those of a zone named in an answer.
func TestAuthTXTAsksTheRegisteredDomainsServers(t *testing.T) {
	t.Parallel()
	_, z := authWorld(Token(key1, "acme.example"))
	a := &Authoritative{R: z, Exchange: z.exchange}
	if _, err := a.AuthTXT(t.Context(), "_vedette-verify.git.acme.example."); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(z.nsAsked, []string{"acme.example"}) {
		t.Fatalf("NS asked for %v", z.nsAsked)
	}
	for _, bad := range []string{"com", "example", "", "a..b.example", strings.Repeat("a", 64) + ".acme.example"} {
		if _, err := a.AuthTXT(t.Context(), bad); err == nil {
			t.Fatalf("%q: asked", bad)
		}
	}
}

// Every name server of the zone is asked, up to 8: one that lacks the record keeps it unproved whatever its name sorts as. A zone
// that lists more is not asked at all (fail closed to the resolver's answer).
func TestAuthTXTAsksEveryServerUpToTheBound(t *testing.T) {
	t.Parallel()
	tok := "vedette-verify=" + Token(key1, "acme.example")
	zones := func(n int) *fakeZones {
		_, z := authWorld(tok)
		z.ns["acme.example"], z.servers = nil, map[netip.Addr]*fakeServer{}
		for i := range n {
			h := "ns" + string(rune('a'+i)) + ".dns-host.example"
			ad := netip.AddrFrom4([4]byte{97, 74, 104, byte(i + 1)})
			z.ns["acme.example"] = append(z.ns["acme.example"], h)
			z.addr[h] = []netip.Addr{ad}
			z.servers[ad] = &fakeServer{zone: "acme.example", txt: map[string][]string{"acme.example": {tok}}}
		}
		return z
	}
	z := zones(8)
	z.servers[netip.AddrFrom4([4]byte{97, 74, 104, 8})].txt["acme.example"] = []string{"v=spf1 -all"} // the last by name
	got, err := (&Authoritative{R: z, Exchange: z.exchange}).AuthTXT(t.Context(), "acme.example")
	if err != nil || len(got.Servers) != 8 || slices.Contains(got.TXT, tok) || !slices.Contains(got.Some, tok) {
		t.Fatalf("8 servers: %+v %v, asked %v", got, err, z.askedServers())
	}
	z = zones(9)
	if got, err := (&Authoritative{R: z, Exchange: z.exchange}).AuthTXT(t.Context(), "acme.example"); err == nil || len(z.askedServers()) > 0 {
		t.Fatalf("9 servers: %+v %v, asked %v", got, err, z.askedServers())
	}
}

// The executors' fence accepts what the core check accepts: a stale resolver does not refuse a job the zone's servers prove.
func TestCheckAgreesWithTheZonesServers(t *testing.T) {
	t.Parallel()
	r, z := authWorld(Token(key1, "acme.example"))
	f := newFence(t, staleDNS{fakeDNS: r, auth: &Authoritative{R: z, Exchange: z.exchange}}, nil)
	if o := f.Check(t.Context(), job(), false); o.Reason != "" {
		t.Fatalf("%+v", o)
	}
	for _, s := range z.servers {
		s.txt["acme.example"] = []string{"v=spf1 -all"}
	}
	if o := f.Check(t.Context(), job(), false); o.Reason != NotOwned {
		t.Fatalf("the record gone from the zone's servers: %+v", o)
	}
	// Without the zone's servers (a resolver that cannot ask them) the stale answer refuses, as before.
	if o := newFence(t, r, nil).Check(t.Context(), job(), false); o.Reason != NotOwned {
		t.Fatalf("without the authority: %+v", o)
	}
}

// The real exchange over UDP: a query without recursion, the answer read back; tested against a local listener, never the network.
func TestExchangeUDP(t *testing.T) {
	t.Parallel()
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	z := &fakeZones{servers: map[netip.Addr]*fakeServer{{}: {zone: "acme.example", txt: map[string][]string{"acme.example": {"vedette-verify=0123456789abcdef"}}}}}
	go func() {
		buf := make([]byte, 1500)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// a stray datagram with another id first: it must be skipped, not taken for the answer
		var p dnsmessage.Parser
		h, _ := p.Start(buf[:n])
		stray := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID + 1, Response: true, Authoritative: true})
		sb, _ := stray.Finish()
		_, _ = pc.WriteTo(sb, from)
		resp, err := z.exchange(t.Context(), netip.Addr{}, buf[:n])
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(resp, from)
	}()
	q, id, err := query("acme.example", dnsmessage.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resp, err := roundTrip(ctx, "udp", pc.LocalAddr().String(), q, id)
	if err != nil {
		t.Fatal(err)
	}
	ans, ok := parseAnswer(resp, id, "acme.example")
	if !ok || !slices.Equal(ans.txt, []string{"vedette-verify=0123456789abcdef"}) {
		t.Fatalf("%+v %v", ans, ok)
	}
}
