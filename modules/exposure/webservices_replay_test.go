package exposure

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// httpAnswered is an independent reading of "this open port answered HTTP", for the count below: a page title, a Server header or a
// redirect read on it, or a product read by the page request, or a probe that named an HTTP service.
func httpAnswered(p PortRow, svc []ServiceRow) bool {
	if p.Title != "" || p.Server != "" || p.Location != "" {
		return true
	}
	family := func(n string) bool {
		n = strings.TrimPrefix(n, "ssl/")
		return n == "http" || n == "https" || n == "http-alt" || n == "https-alt"
	}
	if p.Product != "" && family(p.Service) {
		return true
	}
	for _, r := range svc {
		if r.IP == p.IP && r.Port == p.Port && family(r.Name) && r.Method == "probed" {
			return true
		}
	}
	return false
}

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
			if httpAnswered(p, c.Services) && !covered[fmt.Sprintf("%s:%d", p.IP, p.Port)] && (st.Kind == KindDomain || p.IP == st.Value) {
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
