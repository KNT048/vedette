package surface

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// fakeDNS is the box's resolver in the discovery tests: no DNS query is sent. wildcard answers every name under it that the maps do
// not hold; fail gives a server failure (not "no such name") for the addresses of those names; hang makes lookups of unknown names
// wait for their context (a resolver that does not answer); unrooted counts names not asked fully qualified.
type fakeDNS struct {
	a        map[string][]netip.Addr
	cname    map[string]string
	mx       []*net.MX
	ns       []*net.NS
	wildcard string
	fail     map[string]bool
	hang     bool // lookups of names the maps do not hold, after the first hangAfter of them, wait for their context
	hanged   int
	mu       sync.Mutex
	asked    int
	unrooted int

	hangAfter int
}

var errServFail = &net.DNSError{Err: "server misbehaving", IsTemporary: true}

func (f *fakeDNS) name(host string) string {
	n, err := rootedName(host)
	if err != nil {
		f.mu.Lock()
		f.unrooted++
		f.mu.Unlock()
	}
	return n
}

func (f *fakeDNS) count() {
	f.mu.Lock()
	f.asked++
	f.mu.Unlock()
}

func (f *fakeDNS) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.count()
	host = f.name(host)
	if network != "ip" {
		return nil, fmt.Errorf("network %q", network)
	}
	if f.fail[host] {
		return nil, errServFail
	}
	if a, ok := f.a[host]; ok {
		return slices.Clone(a), nil
	}
	if f.hang {
		f.mu.Lock()
		f.hanged++
		wait := f.hanged > f.hangAfter
		f.mu.Unlock()
		if wait {
			<-ctx.Done()
			return nil, &net.DNSError{Err: "i/o timeout", IsTimeout: true}
		}
	}
	if f.wildcard != "" && strings.HasSuffix(host, "."+f.wildcard) {
		return addrs("198.51.100.99"), nil
	}
	return nil, notFound(host)
}

func (f *fakeDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	f.count()
	host = f.name(host)
	if c, ok := f.cname[host]; ok {
		return c, nil
	}
	if _, ok := f.a[host]; ok {
		return host + ".", nil
	}
	return "", notFound(host)
}

func (f *fakeDNS) LookupMX(_ context.Context, n string) ([]*net.MX, error) {
	f.count()
	f.name(n)
	return f.mx, nil
}

func (f *fakeDNS) LookupNS(_ context.Context, n string) ([]*net.NS, error) {
	f.count()
	f.name(n)
	return f.ns, nil
}

func ctNames(names ...string) string {
	var b strings.Builder
	b.WriteString("[")
	for i, n := range names {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name_value":%q}`, n)
	}
	return b.String() + "]"
}

func hostLines(hs []Host) []string {
	var out []string
	for _, h := range hs {
		line := h.Name + " " + h.Source + " cname=" + h.CNAME
		for _, a := range h.Addrs {
			line += fmt.Sprintf(" %s/%s", a.IP, a.Class)
			if a.Contacted {
				line += "/contacted"
			}
		}
		out = append(out, line)
	}
	return out
}

// INV-27: CT names, the apex's MX and NS under the domain (another company's mail or DNS server is not listed), the common
// names that resolve, the final CNAME of each, and one kind per (name, address). Nothing beyond the checks by name is dialed.
func TestDiscoveryAndKinds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		dns := &fakeDNS{
			a: map[string][]netip.Addr{
				"acme.example":          addrs("198.51.100.20"),
				"www.acme.example":      addrs("104.16.1.2", "104.16.1.1"),
				"shop.acme.example":     addrs("23.227.38.65"),
				"v6only.acme.example":   addrs("2606:4700::5", "fd00::1"),
				"intranet.acme.example": addrs("10.0.0.5"),
				"mail.acme.example":     addrs("3.5.140.1"),
				"ns1.acme.example":      addrs("198.51.100.53"),
				"vpn.acme.example":      addrs("203.0.113.10"),
			},
			cname: map[string]string{
				"www.acme.example":  "acme.example.cdn.cloudflare.net.", // the final name of a chain (www → edge → cloudflare)
				"shop.acme.example": "shops.myshopify.com.",
				"docs.acme.example": "acme.github.io.", // a CNAME that leads nowhere is still listed
			},
			mx: []*net.MX{{Host: "mail.acme.example.", Pref: 10}, {Host: "ASPMX.L.GOOGLE.COM.", Pref: 20}, {Host: ".", Pref: 0}},
			ns: []*net.NS{{Host: "dana.ns.cloudflare.com."}, {Host: "ns1.acme.example."}, {Host: "ns.unknown-dns.example."}},
		}
		var asked []string
		n := &fakeNet{open: map[string]handler{}}
		log := &probeLog{}
		got, err := newScanner(t, n, dns, ctAnswer(200, ctNames("www.acme.example", "shop.acme.example", "docs.acme.example", "v6only.acme.example", "intranet.acme.example", "old.acme.example"), &asked), log).
			Domain(t.Context(), "acme.example", Every, func(_ context.Context, a netip.Addr) bool { return a.String() == "203.0.113.10" })
		if err != nil {
			t.Fatal(err)
		}
		want := []string{
			"acme.example dns cname= 198.51.100.20/public/contacted",
			"docs.acme.example ct cname=acme.github.io",
			"intranet.acme.example ct cname= 10.0.0.5/private",
			"mail.acme.example mx cname= 3.5.140.1/public/contacted",
			"ns1.acme.example ns cname= 198.51.100.53/public/contacted",
			"shop.acme.example ct cname=shops.myshopify.com 23.227.38.65/public/contacted",
			"v6only.acme.example ct cname= 2606:4700::5/public fd00::1/private",
			"vpn.acme.example wordlist cname= 203.0.113.10/box/contacted",
			"www.acme.example ct cname=acme.example.cdn.cloudflare.net 104.16.1.1/public/contacted 104.16.1.2/public",
		}
		if g := hostLines(got.Hosts); !slices.Equal(g, want) {
			t.Fatalf("hosts:\n%s\nwant:\n%s", strings.Join(g, "\n"), strings.Join(want, "\n"))
		}
		if got.Wordlist != "" || len(got.Unresolved) != 0 || dns.unrooted != 0 {
			t.Fatalf("wordlist %q, unresolved %v, %d names not asked fully qualified", got.Wordlist, got.Unresolved, dns.unrooted)
		}
		for _, h := range got.Hosts {
			if (h.Name == "v6only.acme.example" || h.Name == "docs.acme.example") && h.IP.IsValid() {
				t.Fatalf("%s has no IPv4 but IP %s", h.Name, h.IP)
			}
		}
		// Only the box's own address is port-scanned; the rest get the checks by name on 80 and 443, as before.
		for _, d := range n.dialed {
			if host, port, _ := net.SplitHostPort(d); host != "203.0.113.10" && port != "80" && port != "443" {
				t.Fatalf("dialed %s", d)
			}
			if strings.HasPrefix(d, "10.") || strings.Contains(d, ":") && strings.Count(d, ":") > 1 {
				t.Fatalf("dialed a private or IPv6 address: %s", d)
			}
		}
		dnsRows := 0
		for _, r := range log.requests() {
			if strings.HasPrefix(r, "dns acme.example ") && strings.Contains(r, "DNS lookups via the box's resolver") {
				dnsRows++
			}
		}
		if dnsRows != 1 {
			t.Fatalf("probe log %q: want one dns row", log.requests())
		}
	})
}

// A domain that answers any name (wildcard DNS) would make every common name look real: the wordlist is skipped and the scan says so.
func TestWildcardSkipsTheWordlist(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		dns := &fakeDNS{a: map[string][]netip.Addr{"acme.example": addrs("198.51.100.20")}, wildcard: "acme.example"}
		var asked []string
		got, err := newScanner(t, &fakeNet{open: map[string]handler{}}, dns, ctAnswer(200, "[]", &asked), &probeLog{}).
			Domain(t.Context(), "acme.example", Every, func(context.Context, netip.Addr) bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		if got.Wordlist != WordlistWildcard || len(got.Hosts) != 1 || dns.asked > 10 {
			t.Fatalf("wordlist %q, hosts %v, %d lookups", got.Wordlist, hostLines(got.Hosts), dns.asked)
		}
	})
}

// The 300-name rule counts every source and stays whole or nothing: CT names plus MX names over the limit stop the scan
// before anything is dialed.
func TestNameCapCountsEverySource(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var ct []string
		for i := range maxNames - 2 { // with the domain: 299 names from CT
			ct = append(ct, fmt.Sprintf("h%d.acme.example", i))
		}
		for _, mx := range []int{1, 2} {
			dns := &fakeDNS{mx: []*net.MX{{Host: "mx1.acme.example."}, {Host: "mx2.acme.example."}}[:mx]}
			n := &fakeNet{open: map[string]handler{}}
			var asked []string
			_, err := newScanner(t, n, dns, ctAnswer(200, ctNames(ct...), &asked), &probeLog{}).
				Domain(t.Context(), "acme.example", Every, func(context.Context, netip.Addr) bool { return true })
			if mx == 1 && err != nil || mx == 2 && !errors.Is(err, ErrTooManyNames) || len(n.dialed) != 0 {
				t.Fatalf("%d MX names: err %v, %d dials", mx, err, len(n.dialed))
			}
		}
	})
}

// DNS answers are untrusted (SYS-6): names that are not host names are dropped, long lists are clipped.
func TestHostileDNSAnswers(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var many []netip.Addr
		for i := range 100 {
			many = append(many, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
		}
		var mxs []*net.MX
		for i := range 50 {
			mxs = append(mxs, &net.MX{Host: fmt.Sprintf("mx%d.acme.example.", i)})
		}
		mxs[0] = &net.MX{Host: strings.Repeat("a", 300) + ".acme.example."}
		mxs[1] = &net.MX{Host: "evil\x00name.acme.example."}
		mxs[2] = &net.MX{Host: "<script>.acme.example."}
		dns := &fakeDNS{
			a:     map[string][]netip.Addr{"acme.example": many, "www.acme.example": addrs("198.51.100.7")},
			cname: map[string]string{"www.acme.example": strings.Repeat("x.", 200) + "example."},
			mx:    mxs,
		}
		var asked []string
		log := &probeLog{}
		got, err := newScanner(t, &fakeNet{open: map[string]handler{}}, dns, ctAnswer(200, ctNames("www.acme.example"), &asked), log).
			Domain(t.Context(), "acme.example", Every, func(context.Context, netip.Addr) bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		// Only the first maxMailNS MX hosts are read and the three hostile ones among them are dropped: 2 + 7 names in all, the 7 MX
		// names resolving to nothing (not shown).
		if len(got.Hosts) != 2 || got.Hosts[1].CNAME != "" || !slices.ContainsFunc(log.requests(), func(r string) bool { return strings.HasPrefix(r, "dns acme.example 9 names listed; ") }) {
			t.Fatalf("hosts %v", hostLines(got.Hosts))
		}
		apex := got.Hosts[0]
		if len(apex.Addrs) != maxAddrs {
			t.Fatalf("apex: %d addresses, want %d", len(apex.Addrs), maxAddrs)
		}
	})
}

// Review r1 L1, M1: only "no such name" means no wildcard. A wildcard check that gets no answer skips the wordlist (fail closed); a
// wordlist whose lookups time out is cut and says so; neither stops the scan, and the DNS phase stays within dnsBudget.
func TestWordlistFailsClosedAndStaysInItsBudget(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name      string
		hangAfter int
		want      string
	}{{"wildcard check unanswered", 0, WordlistNoAnswer}, {"common names time out", 2, WordlistCut}} {
		synctest.Test(t, func(t *testing.T) {
			dns := &fakeDNS{a: map[string][]netip.Addr{"acme.example": addrs("198.51.100.20")}, hang: true, hangAfter: c.hangAfter}
			var asked []string
			start := time.Now()
			got, err := newScanner(t, &fakeNet{open: map[string]handler{}}, dns, ctAnswer(200, "[]", &asked), &probeLog{}).
				Domain(t.Context(), "acme.example", Every, func(context.Context, netip.Addr) bool { return false })
			if err != nil || got.Wordlist != c.want || len(got.Hosts) != 1 {
				t.Fatalf("%s: err %v, wordlist %q, hosts %v", c.name, err, got.Wordlist, hostLines(got.Hosts))
			}
			if took := time.Since(start); took > dnsBudget+2*pageTimeout {
				t.Fatalf("%s: took %v", c.name, took)
			}
		})
	}
}

// Review r1 L4 (INV-22): a name whose address lookup fails (a server failure, not "no such name") is left out and counted, even when
// its CNAME answered, so exposure keeps its earlier state instead of reading it as moved.
func TestFailedLookupIsLeftOutNotMoved(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		dns := &fakeDNS{
			a:     map[string][]netip.Addr{"acme.example": addrs("198.51.100.20")},
			cname: map[string]string{"www.acme.example": "edge.cdn.example."},
			fail:  map[string]bool{"www.acme.example": true},
		}
		var asked []string
		got, err := newScanner(t, &fakeNet{open: map[string]handler{}}, dns, ctAnswer(200, ctNames("www.acme.example"), &asked), &probeLog{}).
			Domain(t.Context(), "acme.example", Every, func(context.Context, netip.Addr) bool { return false })
		if err != nil || !slices.Equal(got.Unresolved, []string{"www.acme.example"}) || len(got.Hosts) != 1 || got.Hosts[0].Name != "acme.example" {
			t.Fatalf("err %v, unresolved %v, hosts %v", err, got.Unresolved, hostLines(got.Hosts))
		}
		// Review r2 M3: the domain itself without a clear answer (the resolver is down) stops the scan: nothing to compare with.
		dns.fail["acme.example"] = true
		n := &fakeNet{open: map[string]handler{}}
		if _, err := newScanner(t, n, dns, ctAnswer(200, ctNames("www.acme.example"), &asked), &probeLog{}).
			Domain(t.Context(), "acme.example", Every, func(context.Context, netip.Addr) bool { return true }); !errors.Is(err, ErrDNS) || len(n.dialed) != 0 {
			t.Fatalf("apex failed: err %v, %d dials", err, len(n.dialed))
		}
	})
}

// Review r1 L6: the IPv6 special-purpose ranges are not public addresses (display only: IPv6 is never dialed).
func TestPublicV6(t *testing.T) {
	t.Parallel()
	for a, want := range map[string]bool{
		"2606:4700::5": true, "2a00:1450:4001::1": true,
		"64:ff9b::a00:1": false, "2002:a00:1::1": false, "2001:0:4136::1": false, "100::1": false, "2001:db8::1": false,
		"3fff::1": false, "fec0::1": false, "fd00::1": false, "fe80::1": false, "::1": false, "::ffff:8.8.8.8": false,
	} {
		if got := publicV6(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v, want %v", a, got, want)
		}
	}
}

// The 300-name rule counts the names the scan reaches: a child target's names do not count for its parent. A scope of "only this name"
// looks nothing up but the domain, whatever the size of the domain; a scope of chosen names on a domain with too many names to list
// falls back to the chosen ones and says so.
func TestNameCapCountsOnlyTheNamesTheScopeReaches(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		var ct []string
		for i := range maxNames + 50 { // more than one scan reads, all under shop.acme.example but 10
			ct = append(ct, fmt.Sprintf("h%d.shop.acme.example", i))
		}
		for i := range 10 {
			ct = append(ct, fmt.Sprintf("w%d.acme.example", i))
		}
		a := map[string][]netip.Addr{"acme.example": addrs("203.0.113.10"), "w1.acme.example": addrs("203.0.113.10")}
		may := func(context.Context, netip.Addr) bool { return false }
		notShop := func(n string) bool { return n != "shop.acme.example" && !strings.HasSuffix(n, ".shop.acme.example") }

		// every name but a child's: 11 names to scan, the child's 350 listed apart, never looked up
		dns := &fakeDNS{a: a}
		var asked []string
		got, err := newScanner(t, &fakeNet{open: map[string]handler{}}, dns, ctAnswer(200, ctNames(ct...), &asked), &probeLog{}).
			Domain(t.Context(), "acme.example", Names{Scans: notShop, Find: true}, may)
		if err != nil || len(got.Skipped) != maxNames || got.NamesCut {
			t.Fatalf("with the child's names apart: err %v, %d skipped, cut %v", err, len(got.Skipped), got.NamesCut)
		}
		// the same domain with every name: refused, nothing dialed
		if _, err := newScanner(t, &fakeNet{open: map[string]handler{}}, &fakeDNS{a: a}, ctAnswer(200, ctNames(ct...), &asked), &probeLog{}).
			Domain(t.Context(), "acme.example", Every, may); !errors.Is(err, ErrTooManyNames) {
			t.Fatalf("every name: %v", err)
		}
		// only this name: no certificate search, one name looked up
		asked = nil
		dns = &fakeDNS{a: a}
		got, err = newScanner(t, &fakeNet{open: map[string]handler{}}, dns, ctAnswer(200, ctNames(ct...), &asked), &probeLog{}).
			Domain(t.Context(), "acme.example", Names{Scans: func(n string) bool { return n == "acme.example" }}, may)
		if err != nil || len(asked) != 0 || len(got.Hosts) != 1 || got.Hosts[0].Name != "acme.example" || len(got.Skipped) != 0 {
			t.Fatalf("only this name: err %v, CT asked %v, hosts %+v", err, asked, got.Hosts)
		}
		// the names chosen, on a domain with too many names to list: the chosen ones only, and the result says why
		var many []string
		for i := range maxNames + 1 {
			many = append(many, fmt.Sprintf("x%d.acme.example", i))
		}
		got, err = newScanner(t, &fakeNet{open: map[string]handler{}}, &fakeDNS{a: a}, ctAnswer(200, ctNames(many...), &asked), &probeLog{}).
			Domain(t.Context(), "acme.example", Names{Scans: func(string) bool { return true }, Find: true, Choose: true, Chosen: []string{"w1.acme.example"}}, may)
		if err != nil || !got.NamesCut || len(got.Hosts) != 2 || got.Hosts[1].Name != "w1.acme.example" {
			t.Fatalf("chosen names, too many to list: err %v, cut %v, hosts %+v", err, got.NamesCut, got.Hosts)
		}
		// the names chosen on a domain that lists: the common names are not tried for the names nobody chose, and the result says so
		got, err = newScanner(t, &fakeNet{open: map[string]handler{}}, &fakeDNS{a: a}, ctAnswer(200, ctNames("w1.acme.example", "w2.acme.example"), &asked), &probeLog{}).
			Domain(t.Context(), "acme.example", Names{Scans: func(n string) bool { return n == "w1.acme.example" }, Find: true, Choose: true, Chosen: []string{"w1.acme.example"}}, may)
		if err != nil || got.NamesCut || got.Wordlist != WordlistChosen || len(got.Skipped) != 1 {
			t.Fatalf("chosen names: err %v, wordlist %q, skipped %+v", err, got.Wordlist, got.Skipped)
		}
	})
}
