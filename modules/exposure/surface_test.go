package exposure

import (
	"slices"
	"strings"
	"testing"
)

// INV-27: a domain's surface is stored as the scan module found it, bounded and checked like any other content (INV-10): a kind or
// source that is not on its list, an address that does not parse, a CNAME that is not a host name are dropped, and the family is
// read from the address. The snapshot says what was not scanned: names on other public addresses (by name only), IPv6.
func TestContract_INV27_SurfaceIsStoredAndSaysWhatWasNotScanned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	dom := e.committedDomain()
	e.svc.SetRunner(&fakeRunner{content: Content{
		Hosts: []HostRow{
			{Name: "acme.example", IP: ipA, Source: "dns", IPs: []HostIP{{IP: ipA, Family: "ipv6", Class: ClassBox}, {IP: "2606:4700::5", Family: "ipv4", Class: ClassPublic}}},
			{Name: "www.acme.example", IP: ipB, Source: "ct", CNAME: "acme.example.cdn.cloudflare.net", IPs: []HostIP{{IP: ipB, Class: ClassPublic, Contacted: true}}},
			{Name: "docs.acme.example", Source: "wordlist", CNAME: "acme.github.io"},
			{Name: "mail.acme.example", IP: "8.8.4.5", Source: "zone-walk", CNAME: "<script>", IPs: []HostIP{{IP: "8.8.4.5", Class: "edge"}, {IP: "not-an-ip", Class: ClassPublic}, {IP: "8.8.4.5", Class: ClassPublic}}},
			{Name: "intra.acme.example", IP: "10.0.0.5", Source: "ct", IPs: []HostIP{{IP: "10.0.0.5", Class: ClassPrivate, Contacted: true}}},
		},
		Ports: []PortRow{},
	}})
	snap, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.SnapshotOf(e.ctx(), dom.ID, snap.Date)
	if err != nil {
		t.Fatal(err)
	}
	h := got.Hosts
	if len(h) != 5 || h[0].Source != "dns" || len(h[0].IPs) != 2 || h[0].IPs[0].Family != "ipv4" || h[0].IPs[1].Family != "ipv6" {
		t.Fatalf("apex = %+v", h[0])
	}
	if h[1].CNAME != "acme.example.cdn.cloudflare.net" || h[1].IPs[0].Class != ClassPublic || h[2].CNAME != "acme.github.io" || len(h[2].IPs) != 0 {
		t.Fatalf("www, docs = %+v %+v", h[1], h[2])
	}
	if !h[1].IPs[0].Contacted || h[4].IPs[0].Contacted { // a private address is never contacted, whatever the runner says
		t.Fatalf("contacted: %+v %+v", h[1].IPs, h[4].IPs)
	}
	if h[3].Source != "" || h[3].CNAME != "" || len(h[3].IPs) != 1 || h[3].IPs[0].Class != ClassPublic {
		t.Fatalf("hostile row = %+v", h[3])
	}
	if got.Counts.Subdomains != 5 || got.Counts.IPs != 5 {
		t.Fatalf("counts = %+v", got.Counts)
	}
	n := notChecked(got)
	for _, want := range []string{"Names on public addresses that are not this box's (2 names): checked by name on ports 80 and 443 only", "IPv6 addresses (1 listed): IPv6 is not scanned yet."} {
		if !slices.ContainsFunc(n, func(s string) bool { return strings.Contains(s, want) }) {
			t.Errorf("not checked %q: missing %q", n, want)
		}
	}
}
