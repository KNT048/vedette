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
)

// fakeDNS is the box's resolver in the discovery tests: no DNS query is sent. wildcard answers every name under it that the maps do
// not hold.
type fakeDNS struct {
	a        map[string][]netip.Addr
	cname    map[string]string
	mx       []*net.MX
	ns       []*net.NS
	wildcard string
	mu       sync.Mutex
	asked    int
}

func (f *fakeDNS) count() {
	f.mu.Lock()
	f.asked++
	f.mu.Unlock()
}

func (f *fakeDNS) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.count()
	if network != "ip" {
		return nil, fmt.Errorf("network %q", network)
	}
	if a, ok := f.a[host]; ok {
		return slices.Clone(a), nil
	}
	if f.wildcard != "" && strings.HasSuffix(host, "."+f.wildcard) {
		return addrs("198.51.100.99"), nil
	}
	return nil, notFound(host)
}

func (f *fakeDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	f.count()
	if c, ok := f.cname[host]; ok {
		return c, nil
	}
	if _, ok := f.a[host]; ok {
		return host + ".", nil
	}
	return "", notFound(host)
}

func (f *fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) { f.count(); return f.mx, nil }
func (f *fakeDNS) LookupNS(context.Context, string) ([]*net.NS, error) { f.count(); return f.ns, nil }

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
		}
		out = append(out, line)
	}
	return out
}

// D-567 (1), INV-27: CT names, the apex's MX and NS under the domain (another company's mail or DNS server is not listed), the common
// names that resolve, the final CNAME of each, and one kind per (name, address). Nothing beyond the D-229 checks is dialed.
func TestDiscoveryAndKinds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		dns := &fakeDNS{
			a: map[string][]netip.Addr{
				"acme.example":          addrs("198.51.100.20"),
				"www.acme.example":      addrs("104.16.1.1"),
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
			Domain(t.Context(), "acme.example", func(_ context.Context, a netip.Addr) bool { return a.String() == "203.0.113.10" })
		if err != nil {
			t.Fatal(err)
		}
		want := []string{
			"acme.example dns cname= 198.51.100.20/public",
			"docs.acme.example ct cname=acme.github.io",
			"intranet.acme.example ct cname= 10.0.0.5/private",
			"mail.acme.example mx cname= 3.5.140.1/public",
			"ns1.acme.example ns cname= 198.51.100.53/public",
			"shop.acme.example ct cname=shops.myshopify.com 23.227.38.65/public",
			"v6only.acme.example ct cname= 2606:4700::5/public fd00::1/private",
			"vpn.acme.example wordlist cname= 203.0.113.10/box",
			"www.acme.example ct cname=acme.example.cdn.cloudflare.net 104.16.1.1/public",
		}
		if g := hostLines(got.Hosts); !slices.Equal(g, want) {
			t.Fatalf("hosts:\n%s\nwant:\n%s", strings.Join(g, "\n"), strings.Join(want, "\n"))
		}
		if got.WordlistSkipped {
			t.Fatal("wordlist skipped without a wildcard")
		}
		for _, h := range got.Hosts {
			if (h.Name == "v6only.acme.example" || h.Name == "docs.acme.example") && h.IP.IsValid() {
				t.Fatalf("%s has no IPv4 but IP %s", h.Name, h.IP)
			}
		}
		// Only the box's own address is port-scanned; the rest get the D-229 checks by name on 80 and 443, as before.
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
			if strings.HasPrefix(r, "dns acme.example DNS lookups via the box's resolver") {
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
			Domain(t.Context(), "acme.example", func(context.Context, netip.Addr) bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		if !got.WordlistSkipped || len(got.Hosts) != 1 || dns.asked > 10 {
			t.Fatalf("skipped %v, hosts %v, %d lookups", got.WordlistSkipped, hostLines(got.Hosts), dns.asked)
		}
	})
}

// The 300-name rule counts every source and stays whole or nothing (D-229 (6)): CT names plus MX names over the limit stop the scan
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
				Domain(t.Context(), "acme.example", func(context.Context, netip.Addr) bool { return true })
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
			Domain(t.Context(), "acme.example", func(context.Context, netip.Addr) bool { return false })
		if err != nil {
			t.Fatal(err)
		}
		// Only the first maxMailNS MX hosts are read and the three hostile ones among them are dropped: 2 + 7 names in all, the 7 MX
		// names resolving to nothing (not shown).
		if len(got.Hosts) != 2 || got.Hosts[1].CNAME != "" || !slices.ContainsFunc(log.requests(), func(r string) bool { return strings.HasSuffix(r, "; 9 names true") }) {
			t.Fatalf("hosts %v", hostLines(got.Hosts))
		}
		apex := got.Hosts[0]
		if len(apex.Addrs) != maxAddrs {
			t.Fatalf("apex: %d addresses, want %d", len(apex.Addrs), maxAddrs)
		}
	})
}
