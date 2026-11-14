package exposure

import (
	"context"
	"encoding/xml"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

// nmapServices reads the open ports of an nmap -oX fixture the way the scan container's ServiceScanner hands them over: one row per
// <port>, nmap's service name, product, version and its first application CPE, as printed (sanitize is exposure's job).
func nmapServices(t *testing.T, file string) []ServiceRow {
	t.Helper()
	b, err := os.ReadFile("testdata/" + file) //nolint:gosec // a testdata name given by the test itself
	if err != nil {
		t.Fatal(err)
	}
	var run struct {
		Hosts []struct {
			Addr []struct {
				Addr string `xml:"addr,attr"`
			} `xml:"address"`
			Ports []struct {
				Port    int `xml:"portid,attr"`
				Service struct {
					Name    string   `xml:"name,attr"`
					Product string   `xml:"product,attr"`
					Version string   `xml:"version,attr"`
					Extra   string   `xml:"extrainfo,attr"`
					CPE     []string `xml:"cpe"`
				} `xml:"service"`
			} `xml:"ports>port"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal(b, &run); err != nil {
		t.Fatal(err)
	}
	var out []ServiceRow
	for _, h := range run.Hosts {
		for _, p := range h.Ports {
			r := ServiceRow{IP: h.Addr[0].Addr, Port: p.Port, Name: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version, Extra: p.Service.Extra}
			if len(p.Service.CPE) > 0 {
				r.CPE = p.Service.CPE[0]
			}
			out = append(out, r)
		}
	}
	return out
}

// fakeServices is the ServiceScanner seam with a canned answer (the scan container is not in this test).
type fakeServices struct {
	scan  ServiceScan
	err   error
	calls []ScanTarget
}

func (f *fakeServices) ScanServices(_ context.Context, t ScanTarget, ip netip.Addr) (ServiceScan, error) {
	if ip.String() != t.Value {
		return ServiceScan{}, errors.New("asked for another address than the target")
	}
	f.calls = append(f.calls, t)
	return f.scan, f.err
}

// fakeMatcher answers what it is told and records the services it was asked about.
type fakeMatcher struct {
	m     Matches
	err   error
	asked [][]ServiceRow
}

func (f *fakeMatcher) Match(_ context.Context, s []ServiceRow) (Matches, error) {
	f.asked = append(f.asked, s)
	return f.m, f.err
}

// scanIP verifies ipA, records its commitment and scans it once; it returns the snapshot as GET …/snapshots/{date} reads it.
func (e *env) scanIP(content Content) Snapshot {
	e.t.Helper()
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		e.t.Fatal(err)
	}
	e.svc.SetRunner(&fakeRunner{content: content})
	snap, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
	if err != nil {
		e.t.Fatal(err)
	}
	got, err := e.svc.SnapshotOf(e.ctx(), ips[0].ID, snap.Date)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func notChecked(s Snapshot) []string {
	var out []string
	for _, n := range s.NotChecked {
		out = append(out, n.Text)
	}
	return out
}

func checkKinds(s Snapshot) []string {
	var out []string
	for _, c := range s.Checks {
		out = append(out, c.Kind)
	}
	return out
}

// INV-19: with no service scanner wired (today: the scan container's nmap -sV is not), a scan of the box's IP is stored as before
// and says so; what the surface scan checked and what a scan never checks are listed. Nothing is compared.
func TestContract_INV19_NoServiceScannerSaysNotSetUp(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	m := &fakeMatcher{}
	e.svc.cfg.Matcher = m
	s := e.scanIP(Content{Ports: []PortRow{{ipA, 443, "https", "nginx", ""}}})
	if len(s.Ports) != 1 || len(s.Services) != 0 || len(s.Vulns) != 0 || len(s.VersionGaps) != 0 {
		t.Fatalf("snapshot = %+v", s)
	}
	if !slices.Contains(notChecked(s), "Service identification (nmap -sV) is not set up on this box yet.") {
		t.Fatalf("not checked = %q", notChecked(s))
	}
	for _, want := range []string{notUDP, notOtherPortsIP, notNonExploited} {
		if !slices.Contains(notChecked(s), want) {
			t.Errorf("missing %q in %q", want, notChecked(s))
		}
	}
	if !slices.Equal(checkKinds(s), []string{"ports"}) || !strings.Contains(s.Checks[0].Text, ": 1 port open.") {
		t.Fatalf("checks = %+v", s.Checks)
	}
	if len(m.asked) != 0 {
		t.Fatal("the matcher was asked with nothing identified")
	}
}

// INV-19, INV-20: the services of the nmap fixture go through the seam, are stored, and are compared on read; the vulns are not
// stored. A domain is never handed to the service scanner.
func TestContract_INV19_ServicesThroughTheSeamAndComparedOnRead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sv := &fakeServices{scan: ServiceScan{Services: nmapServices(t, "nmap-external.xml"), Ports: 98}}
	d := "2021-11-03"
	m := &fakeMatcher{m: Matches{Compared: 2, Listed: 1500,
		Vulns: []VulnRow{{IP: "203.0.113.10", Port: 18443, CVE: "CVE-2021-41773", Name: "Apache HTTP Server Path Traversal Vulnerability", Basis: "version", DateAdded: &d}},
		Gaps:  []GapRow{{IP: "203.0.113.10", Port: 443, Software: "nginx", CVEs: []string{"CVE-2099-0001"}}}}}
	e.svc.cfg.Services, e.svc.cfg.Matcher = sv, m

	// The fixture's address is a documentation address; the target is ipA, so the rows are moved onto it as the real scanner would.
	for i := range sv.scan.Services {
		sv.scan.Services[i].IP = ipA
	}
	sv.scan.Services = append(sv.scan.Services, ServiceRow{IP: ipB, Port: 22, Name: "ssh"}) // another address: never the target's
	s := e.scanIP(Content{})
	if len(sv.calls) != 1 || sv.calls[0].Kind != KindIP || sv.calls[0].User != "admin@acme.example" {
		t.Fatalf("scanner calls = %+v", sv.calls)
	}
	want := []ServiceRow{
		{IP: ipA, Port: 443, Name: "http", Product: "nginx", CPE: "cpe:/a:igor_sysoev:nginx"},
		{IP: ipA, Port: 8443, Name: "tcpwrapped"},
		{IP: ipA, Port: 18443, Name: "http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49", Extra: "(Unix)"},
	}
	if !slices.Equal(s.Services, want) {
		t.Fatalf("services = %+v", s.Services)
	}
	if len(m.asked) != 1 || !slices.Equal(m.asked[0], want) {
		t.Fatalf("matcher asked = %+v", m.asked)
	}
	if len(s.Vulns) != 1 || s.Vulns[0].CVE != "CVE-2021-41773" || len(s.VersionGaps) != 1 {
		t.Fatalf("vulns = %+v, gaps = %+v", s.Vulns, s.VersionGaps)
	}
	if !slices.Equal(checkKinds(s), []string{"ports", "services", "cve"}) {
		t.Fatalf("checks = %+v", s.Checks)
	}
	if got := s.Checks[1].Text; got != "Service identification (nmap -sV) on 98 TCP ports: 3 services identified." {
		t.Fatalf("services line = %q", got)
	}
	if got := s.Checks[2].Text; got != "2 identified services of 3 compared with today's CISA list of exploited vulnerabilities (1500 entries) and its NVD version ranges: 1 exploited CVE matched. 1 service could not be checked: no version was read. 1 service gave no product to look up, so not compared." {
		t.Fatalf("compare line = %q", got)
	}
	var stored string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT services FROM exp_snapshot`).Scan(&stored); err != nil || !strings.Contains(stored, "Apache httpd") {
		t.Fatalf("stored services = %q, %v", stored, err)
	}
	if e.count(`SELECT count(*) FROM exp_snapshot WHERE checks LIKE '%CVE%' OR services LIKE '%41773%'`) != 0 {
		t.Fatal("the comparison is stored; it must be computed on read")
	}

	dom := e.committedDomain()
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", dom.ID); err != nil {
		t.Fatal(err)
	}
	if len(sv.calls) != 1 {
		t.Fatal("a domain went to the service scanner")
	}
}

// INV-19, INV-20: a scanner or a list that cannot run is a "Not checked" line with its reason; a failure is a line without its text;
// the rest of the scan is kept.
func TestContract_INV19_UnavailableAndFailedSteps(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		svcErr   error
		matchErr error
		noMatch  bool
		want     string
	}{
		{name: "scanner off", svcErr: &Unavailable{Reason: "the Active scan module is off."}, want: "Service identification (nmap -sV) did not run: the Active scan module is off."},
		{name: "scanner failed", svcErr: errors.New("nmap: exit 1 at /secret/path"), want: notServicesFail},
		{name: "list off", matchErr: &Unavailable{Reason: "the Feeds module is off."}, want: "The identified services were not compared with exploited vulnerabilities: the Feeds module is off."},
		{name: "list failed", matchErr: errors.New("sqlite: disk I/O error"), want: notMatchFail},
		{name: "no matcher", noMatch: true, want: notMatcher},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: []ServiceRow{{IP: ipA, Port: 22, Name: "ssh", Product: "OpenSSH", Version: "9.6p1", CPE: "cpe:/a:openbsd:openssh:9.6p1"}}}, err: tc.svcErr}
			if !tc.noMatch {
				e.svc.cfg.Matcher = &fakeMatcher{err: tc.matchErr}
			}
			s := e.scanIP(Content{Ports: []PortRow{{ipA, 22, "ssh", "", ""}}})
			if !slices.Contains(notChecked(s), tc.want) || len(s.Ports) != 1 || len(s.Vulns) != 0 {
				t.Fatalf("snapshot = %+v", s)
			}
			for _, n := range notChecked(s) {
				if strings.Contains(n, "secret") || strings.Contains(n, "sqlite") {
					t.Fatalf("an internal error reached the page: %q", n)
				}
			}
		})
	}
}

// INV-19: what nmap printed is untrusted. A field with a control or format character, or longer than its limit, is dropped, not
// cut; a CPE must be printable ASCII; ports outside 1..65535 and a second row of one port are dropped; the rows are bounded.
func TestContract_INV19_SanitizeLimits(t *testing.T) {
	t.Parallel()
	got := sanitizeServices(nmapServices(t, "nmap-hostile.xml"))
	want := []ServiceRow{
		{IP: "203.0.113.10", Port: 80, Name: "http", Version: "1.0"},
		{IP: "203.0.113.10", Port: 81, Name: "http", Product: "Long version", CPE: "cpe:/a:long:version"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
	many := make([]ServiceRow, 0, 70000)
	for p := 1; p <= 70000; p++ {
		many = append(many, ServiceRow{IP: "203.0.113.10", Port: p, Name: "x"})
	}
	if n := len(sanitizeServices(many)); n != maxServices {
		t.Fatalf("kept %d rows", n)
	}
	if got := sanitizeServices([]ServiceRow{{IP: "::1", Port: 1}, {IP: "not an ip", Port: 1}, {IP: "203.0.113.10", Port: 0}}); len(got) != 0 {
		t.Fatalf("kept %+v", got)
	}
	lines := sanitizeChecks([]CheckRow{{Kind: "ports", Text: "ok", At: "2026-11-13T10:00:00Z"}, {Kind: "Bad Kind", Text: "x", At: "2026-11-13T10:00:00Z"},
		{Kind: "ports", Text: "no time"}, {Kind: "ports", Text: "\x1b[2J", At: "2026-11-13T10:00:00Z"}})
	if len(lines) != 1 || lines[0].At != "2026-11-13T10:00:00.000Z" {
		t.Fatalf("checks = %+v", lines)
	}
	if n := sanitizeNotChecked([]NotCheckedRow{{Kind: "udp", Text: strings.Repeat("x", maxLineText+1)}, {Kind: "udp", Text: "UDP"}}); len(n) != 1 {
		t.Fatalf("not checked = %+v", n)
	}
}

// INV-20: the diff of two days says when a service changed version and when an exploited CVE appeared or went away with it.
func TestContract_INV20_DiffServiceAndVuln(t *testing.T) {
	t.Parallel()
	a := Snapshot{Date: "2026-11-12", Content: Content{Services: []ServiceRow{{IP: ipA, Port: 18443, Name: "http", Product: "Apache httpd", Version: "2.4.49"}}},
		Vulns: []VulnRow{{IP: ipA, Port: 18443, CVE: "CVE-2021-41773", Name: "Apache HTTP Server Path Traversal Vulnerability"}}}
	b := Snapshot{Date: "2026-11-13", Content: Content{Services: []ServiceRow{{IP: ipA, Port: 18443, Name: "http", Product: "Apache httpd", Version: "2.4.51"},
		{IP: ipA, Port: 22, Name: "ssh", Product: "OpenSSH", Version: "9.6p1"}}}}
	d := diff(a, b)
	if len(d.Changed) != 1 || d.Changed[0].Kind != "service" || d.Changed[0].From != "Apache httpd 2.4.49" || d.Changed[0].To != "Apache httpd 2.4.51" {
		t.Fatalf("changed = %+v", d.Changed)
	}
	if len(d.Added) != 1 || d.Added[0].Kind != "service" || d.Added[0].Label != ipA+":22" {
		t.Fatalf("added = %+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Kind != "vuln" || d.Removed[0].Label != "CVE-2021-41773 on "+ipA+":18443" {
		t.Fatalf("removed = %+v", d.Removed)
	}
}

// INV-20 (review MED-1): a match by version on a service that names its distribution says the fix may be backported; the basis
// stays "version", the row carries the distribution and the compare line counts it apart. Exim 4.89 as Debian 9 packaged it.
// (review MED-2) A service whose product name the list has no entry under is a "Not checked" line, not "compared".
func TestContract_INV20_BackportsAndUnlistedNames(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: []ServiceRow{
		{IP: ipA, Port: 25, Name: "smtp", Product: "Exim smtpd", Version: "4.89", Extra: "Debian", CPE: "cpe:/a:exim:exim:4.89"},
		{IP: ipA, Port: 443, Name: "http", Product: "nginx", Version: "1.10.3", Extra: "(Ubuntu)", CPE: "cpe:/a:igor_sysoev:nginx:1.10.3"},
	}}}
	sum := "8.8.8.8 runs Exim smtpd 4.89. Its version is inside the range affected by CVE-2019-10149 (>= 4.87, <= 4.91); no scan has confirmed it yet, so this is only suspected."
	e.svc.cfg.Matcher = &fakeMatcher{m: Matches{Compared: 1, Listed: 1500, Unlisted: []string{"nginx (igor_sysoev:nginx)"},
		Vulns: []VulnRow{{IP: ipA, Port: 25, CVE: "CVE-2019-10149", Basis: "version", Summary: sum}}}}
	s := e.scanIP(Content{})
	if len(s.Vulns) != 1 || s.Vulns[0].Backport != "Debian" || s.Vulns[0].Basis != "version" ||
		s.Vulns[0].Summary != sum+" Debian may have backported the fix without changing the version: check the installed package version against Debian's security tracker." {
		t.Fatalf("vuln = %+v", s.Vulns)
	}
	if got := s.Checks[len(s.Checks)-1].Text; got != "1 identified service of 2 compared with today's CISA list of exploited vulnerabilities (1500 entries) and its NVD version ranges: 1 exploited CVE matched, 1 of them on a distribution package that may carry a backported fix." {
		t.Fatalf("compare line = %q", got)
	}
	if !slices.Contains(notChecked(s), "nginx (igor_sysoev:nginx): not compared. The list of exploited vulnerabilities has no entry under the product name nmap reports for it, so Vedette cannot tell.") {
		t.Fatalf("not checked = %q", notChecked(s))
	}
}

// INV-20 (review LOW-5): a version not read this time is not a change of version, and the CVEs it matched are not "gone".
func TestContract_INV20_DiffVersionNotRead(t *testing.T) {
	t.Parallel()
	apache := ServiceRow{IP: ipA, Port: 18443, Name: "http", Product: "Apache httpd", Version: "2.4.49"}
	a := Snapshot{Date: "2026-11-12", Content: Content{Services: []ServiceRow{apache}}, Vulns: []VulnRow{{IP: ipA, Port: 18443, CVE: "CVE-2021-41773"}}}
	unread := apache
	unread.Version = ""
	b := Snapshot{Date: "2026-11-13", Content: Content{Services: []ServiceRow{unread}}}
	d := diff(a, b)
	if len(d.Removed) != 0 || len(d.Added) != 0 || len(d.Changed) != 1 || d.Changed[0].From != "Apache httpd 2.4.49" || d.Changed[0].To != VersionNotRead {
		t.Fatalf("diff = %+v", d)
	}
	if d := diff(b, a); len(d.Changed) != 0 || len(d.Removed) != 0 || len(d.Added) != 1 || d.Added[0].Kind != "vuln" { // read again: the CVE is new knowledge
		t.Fatalf("version read again: %+v", d)
	}
}
