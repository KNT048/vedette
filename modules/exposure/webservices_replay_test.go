package exposure

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// TestReplayEveryHTTPAnswerIsScannedOrListed replays the stored scans of a test network and counts the scans in which a service
// answered HTTP and the passive web scan neither took it nor said it left it out. The test network's addresses are documentation
// addresses, which a domain scan refuses to send pages to, so they are mapped to public stand-ins first.
func TestReplayEveryHTTPAnswerIsScannedOrListed(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/scans-anon.json")
	if err != nil {
		t.Fatal(err)
	}
	var f replayFile
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), "198.51.100.", "52.1.1.")), &f); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]ScanTarget{}
	for _, x := range f.Targets {
		kinds[x.ID] = ScanTarget{ID: x.ID, Kind: Kind(x.Kind), Value: x.Value}
	}
	missed, scans := 0, 0
	for i, s := range f.Scans {
		st, c := kinds[s.Target], s.Content.content()
		pages, skipped := webPages(st, c)
		covered := map[string]bool{}
		for _, p := range append(pages, skipped...) {
			covered[fmt.Sprintf("%s:%d", p.IP, p.Port)] = true
		}
		silent := []string{}
		for _, p := range c.Ports {
			if answeredHTTP(sanitizePortIdent(PortRow{IP: p.IP, Port: p.Port, Service: p.Service, Product: p.Product, Ident: p.Ident}, p), serviceAt(c.Services, p)) && !covered[fmt.Sprintf("%s:%d", p.IP, p.Port)] && (st.Kind == KindDomain || p.IP == st.Value) {
				silent = append(silent, fmt.Sprintf("%s:%d", p.IP, p.Port))
			}
		}
		if len(silent) > 0 {
			missed++
			t.Logf("scan %d of %s: HTTP answered on %v, not scanned and not listed", i, st.Value, silent)
		}
		scans++
	}
	t.Logf("scans: %d, scans with an HTTP answer ZAP skipped without saying: %d", scans, missed)
	if missed != 0 {
		t.Fatalf("%d of %d scans skipped a service that answered HTTP", missed, scans)
	}
}

// A service that answered HTTP on a port that is not a usual web port is a page of an IP scan and of a domain scan alike, and a scan
// with no such service names the ports it looked at.
func TestWebPagesAnyPortAndTheHonestNone(t *testing.T) {
	t.Parallel()
	ip := "8.8.8.8"
	c := Content{
		Hosts: []HostRow{{Name: "git.acme.example", IP: ip}},
		Ports: []PortRow{{IP: ip, Port: 10443, Service: "https", Title: "Sign in", CertNames: []string{"git.acme.example"}}, {IP: ip, Port: 22, Service: "ssh"}},
	}
	for _, st := range []ScanTarget{{Kind: KindIP, Value: ip}, {Kind: KindDomain, Value: "acme.example"}} {
		pages, skipped := webPages(st, c)
		want := "https://" + ip + ":10443/"
		if st.Kind == KindDomain {
			want = "https://git.acme.example:10443/"
		}
		if len(pages) != 1 || pages[0].URL != want || pages[0].IP.String() != ip || len(skipped) != 0 {
			t.Errorf("%s: pages = %+v, skipped = %+v", st.Kind, pages, skipped)
		}
	}
	c.Ports = c.Ports[1:]
	if pages, _ := webPages(ScanTarget{Kind: KindIP, Value: ip}, c); len(pages) != 0 {
		t.Errorf("pages = %+v", pages)
	}
	if got := checkedWebPorts(ScanTarget{Kind: KindIP, Value: ip}, c); got != "open ports checked: 22" {
		t.Errorf("checked = %q", got)
	}
}

func serviceAt(rows []ServiceRow, p PortRow) ServiceRow {
	for _, r := range rows {
		if r.IP == p.IP && r.Port == p.Port {
			return r
		}
	}
	return ServiceRow{}
}

// A bare HTTP answer (no title, header or redirect) is a page; a name's second address is looked at and listed like the first; a
// page that only redirects ranks after one with content; and a title too long to store does not make the port web in one place only.
func TestWebPagesBareAnswerSecondAddressAndRank(t *testing.T) {
	t.Parallel()
	a, b := "8.8.8.8", "8.8.4.4"
	c := Content{
		Hosts: []HostRow{{Name: "api.acme.example", IP: a, IPs: []HostIP{{IP: a}, {IP: b}}}},
		Ports: []PortRow{
			{IP: a, Port: 443, Service: "https", HTTP: true},
			{IP: a, Port: 80, Service: "http", Location: "https://api.acme.example/"},
			{IP: b, Port: 8443, Service: "https", Title: "App"},
			{IP: b, Port: 9000, Service: "http", Title: strings.Repeat("x", 300)},
		},
	}
	pages, skipped := webPages(ScanTarget{Kind: KindDomain, Value: "acme.example"}, c)
	var got []string
	for _, p := range append(pages, skipped...) {
		got = append(got, p.URL)
	}
	want := []string{"https://api.acme.example:8443/", "https://api.acme.example/", "http://api.acme.example/"}
	if !slices.Equal(got, want) {
		t.Errorf("pages = %q, want %q", got, want)
	}
	if got := checkedWebPorts(ScanTarget{Kind: KindDomain, Value: "acme.example"}, c); got != "open ports checked: 80, 443, 8443, 9000" {
		t.Errorf("checked = %q", got)
	}
}
