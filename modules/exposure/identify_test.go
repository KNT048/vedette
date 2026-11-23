package exposure

import (
	"context"
	"encoding/xml"
	"errors"
	"maps"
	"net/netip"
	"os"
	"regexp"
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

// scanIP verifies ipA, records its commitment and scans it once; it returns what the scan found and wrote.
func (e *env) scanIP(content Content) ScanResult {
	e.t.Helper()
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		e.t.Fatal(err)
	}
	if e.terms != nil {
		e.acceptTerms(ips[0].ID, *e.terms)
	}
	e.svc.SetRunner(&fakeRunner{content: content})
	snap, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return snap
}

func notChecked(s ScanResult) []string {
	var out []string
	for _, n := range s.NotChecked {
		out = append(out, n.Text)
	}
	return out
}

func checkKinds(s ScanResult) []string {
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
	s := e.scanIP(Content{Ports: []PortRow{{ipA, 443, "https", "nginx", "", 0, false, "", nil, "", "", "", nil, false}}})
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
	if got := s.Checks[1].Text; got != "Service identification (nmap -sV) on 98 TCP ports: 2 services identified, 1 not identified." {
		t.Fatalf("services line = %q", got)
	}
	if got := s.Checks[2].Text; got != "2 of 3 services compared with today's CISA list of exploited vulnerabilities (1500 entries) and its NVD version ranges: 1 exploited CVE matched. 1 service could not be checked: no version was read. 1 service gave no product to look up, so not compared." {
		t.Fatalf("compare line = %q", got)
	}
	if n := e.count(`SELECT count(*) FROM exp_service WHERE product = 'Apache httpd' AND state = 'open'`); n != 1 {
		t.Fatalf("%d stored Apache services", n)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'match' AND state = 'open'`); n != len(s.Vulns) || n == 0 {
		t.Fatalf("%d match issues for %d matched CVEs", n, len(s.Vulns))
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
			s := e.scanIP(Content{Ports: []PortRow{{ipA, 22, "ssh", "", "", 0, false, "", nil, "", "", "", nil, false}}})
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
	if got := s.Checks[len(s.Checks)-1].Text; got != "1 of 2 services compared with today's CISA list of exploited vulnerabilities (1500 entries) and its NVD version ranges: 1 exploited CVE matched, 1 of them on a distribution package that may carry a backported fix." {
		t.Fatalf("compare line = %q", got)
	}
	if !slices.Contains(notChecked(s), "nginx (igor_sysoev:nginx): not compared. The list of exploited vulnerabilities has no entry under the product name nmap reports for it, so Vedette cannot tell.") {
		t.Fatalf("not checked = %q", notChecked(s))
	}
}

// INV-20: an exploited CVE the matcher ruled out because the service names another platform is not listed, and
// a "checked" line says which and why.
func TestContract_INV20_RuledOutByPlatformIsACheckLine(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Services: []ServiceRow{
		{IP: ipA, Port: 10022, Name: "ssh", Product: "OpenSSH", Version: "9.6p1 Ubuntu 3ubuntu13.20", Extra: "Ubuntu Linux; protocol 2.0", CPE: "cpe:/a:openbsd:openssh:9.6p1"},
	}}}
	why := "CVE-2026-123158 affects only OpenSSH built with musl libc and without PAM; the software reports 9.6p1 Ubuntu 3ubuntu13.20 Ubuntu Linux; protocol 2.0."
	e.svc.cfg.Matcher = &fakeMatcher{m: Matches{Compared: 1, Listed: 1500, RuledOut: []RuledOutRow{{IP: ipA, Port: 10022, CVE: "CVE-2026-123158", Reason: why}}}}
	s := e.scanIP(Content{})
	if len(s.Vulns) != 0 {
		t.Fatalf("vulns = %+v", s.Vulns)
	}
	if got := s.Checks[len(s.Checks)-1].Text; got != "CVE-2026-123158 on port 10022 is not listed: "+why {
		t.Fatalf("last check line = %q", got)
	}
}

// A port that only service identification found (the deep scan's nmap probes every TCP port; the runner a fixed list) is an
// open port of the snapshot, so the counts, the first sentence and the outside view (INV-21 scan_ports) name it.
func TestServicePortsAreOpenPorts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	deep := false
	e.terms = &deep
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 65535, Services: []ServiceRow{
		{IP: ipA, Port: 5060, Name: "sip"}, {IP: ipA, Port: 10022, Name: "ssh", Product: "OpenSSH", Version: "9.6p1"}, {IP: ipA, Port: 2000, Name: "cisco-sccp"}}}}
	s := e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 5060, Service: "sip"}}})
	var got []int
	for _, p := range s.Ports {
		got = append(got, p.Port)
	}
	if !slices.Equal(got, []int{5060, 10022, 2000}) || s.Counts.Ports != 3 || s.Ports[1].Product != "OpenSSH 9.6p1" {
		t.Fatalf("ports %+v counts %+v", s.Ports, s.Counts)
	}
}

// Each open port says how its service was named. A probe's answer is "probed" (the surface's port-list name stays when
// it is the same service), nmap's table name is "port" (not confirmed), "unknown", a bare TLS layer and tcpwrapped are "none" and
// replace the port list's guess; a surface GET that read a product keeps the port identified. The deep scan's ssl-cert, http-title
// and http-server-header outputs become the port's certificate names, title and Server header, which are sanitized when stored.
// nmap prints the bytes outside printable ASCII as \xNN; a run that forms UTF-8 is the text the service sent, one that
// does not stays as nmap printed it.
func TestNmapTextDecodesEscapedUTF8(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		`Sign in \xC2\xB7 GitLab`:  "Sign in · GitLab",
		`\xE6\x97\xA5\xE6\x9C\xAC`: "日本",
		`bad \xFF\xFE end`:         `bad \xFF\xFE end`,
		`half \xC2 then`:           `half \xC2 then`,
		`plain \x4 and \\path`:     `plain \x4 and \\path`,
		`a\x0Ab \x2C c`:            `a\x0Ab \x2C c`,   // r1 L2: nmap never escapes ASCII, so this is the page's own text
		`mixed \xC2\xB7\xFF end`:   `mixed ·\xFF end`, // r1 L3: the valid part is decoded
	} {
		if got := nmapText(in); got != want {
			t.Errorf("nmapText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPortIdentFromMethodAndScripts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	deep := false
	e.terms = &deep
	cert := "Subject: commonName=gw.example.net/organizationName=Example\nSubject Alternative Name: DNS:gw.example.net, DNS:vpn.example.net, IP Address:203.0.113.10\nIssuer: commonName=gw.example.net"
	e.svc.cfg.Services = &fakeServices{scan: ServiceScan{Ports: 65535, Services: []ServiceRow{
		{IP: ipA, Port: 10022, Name: "ssh", Product: "OpenSSH", Version: "9.6p1 Ubuntu 3ubuntu13.20", Method: "probed", Conf: 10},
		{IP: ipA, Port: 10443, Name: "ssl/http", Product: "nginx", Method: "probed", Conf: 10},
		{IP: ipA, Port: 5060, Name: "sip", Method: "table", Conf: 3},
		{IP: ipA, Port: 2000, Name: "cisco-sccp", Method: "table", Conf: 3},
		{IP: ipA, Port: 11080, Name: "unknown", Method: "table", Conf: 3},
		{IP: ipA, Port: 11443, Name: "ssl/unknown", Method: "table", Conf: 3},
		{IP: ipA, Port: 8443, Name: "tcpwrapped", Method: "probed", Conf: 8},
		{IP: ipA, Port: 8080, Name: "http-proxy", Method: "table", Conf: 3},
		{IP: ipA, Port: 9000, Name: "http", Product: "Go", Method: "bogus", Conf: 99},
		{IP: ipA, Port: 2222, Name: "ssh", Product: "OpenSSH", Version: "9.6", Method: "probed", Conf: 10},
		{IP: ipA, Port: 23, Name: "telnet"}, // no method word: the intake's guess mark stays
	}, Scripts: []ScriptRow{
		{IP: ipA, Port: 11443, ID: "ssl-cert", Output: cert},
		{IP: ipA, Port: 10443, ID: "http-title", Output: `Sign in \xC2\xB7 GitLab` + "\nRequested resource was /users/sign_in"}, // As nmap prints it
		{IP: ipA, Port: 11080, ID: "http-title", Output: "Site doesn't have a title (text/html)."},
		{IP: ipA, Port: 11080, ID: "http-server-header", Output: "Caddy"},
		{IP: ipA, Port: 8080, ID: "http-title", Output: "Did not follow redirect to https://203.0.113.10:10443/remote/login?lang=en"},
		{IP: ipB, Port: 11443, ID: "ssl-cert", Output: "Subject: commonName=other.example"},
	}}}
	s := e.scanIP(Content{Ports: []PortRow{
		{IP: ipA, Port: 10443, Service: "https", Product: "nginx"}, {IP: ipA, Port: 5060, Service: "sip"},
		{IP: ipA, Port: 8443, Service: "https"}, {IP: ipA, Port: 8080, Service: "http", Product: "Jetty"}, {IP: ipA, Port: 2222, Service: "http"},
		{IP: ipA, Port: 23, Service: "telnet", Ident: IdentPort},
	}})
	type row struct{ service, ident, title, server, certs string }
	got := map[int]row{}
	for _, p := range s.Ports {
		got[p.Port] = row{p.Service, p.Ident, p.Title, p.Server, strings.Join(p.CertNames, ",")}
		if p.Port == 2222 && p.Product != "OpenSSH 9.6" { // the product follows the service the probe named
			t.Errorf("2222 product %q", p.Product)
		}
		if want := map[int]string{8080: "https://203.0.113.10:10443/remote/login?lang=en"}[p.Port]; p.Location != want { // a redirect nmap did not follow
			t.Errorf("%d location %q, want %q", p.Port, p.Location, want)
		}
	}
	want := map[int]row{
		2222:  {"ssh", IdentProbed, "", "", ""},
		23:    {"telnet", IdentPort, "", "", ""},
		10022: {"ssh", IdentProbed, "", "", ""},
		10443: {"https", IdentProbed, "Sign in · GitLab", "", ""}, // the same service: the surface's name stays
		5060:  {"sip", IdentPort, "", "", ""},
		2000:  {"cisco-sccp", IdentPort, "", "", ""},
		11080: {"unknown", IdentNone, "", "Caddy", ""},
		11443: {"ssl/unknown", IdentNone, "", "", "gw.example.net,vpn.example.net"},
		8443:  {"tcpwrapped", IdentNone, "", "", ""}, // the port list's "https" is not kept
		8080:  {"http", IdentProbed, "", "", ""},     // the surface's GET read Jetty
		9000:  {"http", "", "", "", ""},              // a method nmap never prints is not trusted either way
	}
	if !maps.Equal(got, want) {
		t.Fatalf("ports:\n got %+v\nwant %+v", got, want)
	}
	for _, r := range s.Services {
		if r.Port == 9000 && (r.Method != "" || r.Conf != 10) {
			t.Fatalf("service 9000 kept method %q conf %d", r.Method, r.Conf)
		}
	}
	// a hostile row is cut to what sanitize allows
	bad := sanitizePortIdent(PortRow{}, PortRow{Ident: "maybe", Title: "a\u202eb", Server: strings.Repeat("x", maxHint+1), Location: "/a\nb", CertNames: []string{"a", "b", "c", "d", "e", "f", "\x00"}})
	if bad.Ident != "" || bad.Title != "" || bad.Server != "" || bad.Location != "" || len(bad.CertNames) != maxCertNames {
		t.Fatalf("sanitized = %+v", bad)
	}
}

// A surface port only the port number named stays a guess when nmap -sV does not run (here: unavailable), so
// the page says "Probably SIP 5060"; the "New open port" alert says the same in words (L3).
func TestSurfaceGuessStaysAGuessWithoutServiceIdentification(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.cfg.Services = &fakeServices{err: &Unavailable{Reason: "the Active scan module is off."}}
	s := e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 5060, Service: "sip", Ident: IdentPort}, {IP: ipA, Port: 443, Service: "https", Product: "nginx", Ident: IdentProbed}}})
	if len(s.Ports) != 2 || s.Ports[0].Ident != IdentPort || s.Ports[1].Ident != IdentProbed {
		t.Fatalf("ports %+v", s.Ports)
	}
	for _, c := range []struct {
		p    PortRow
		want string
	}{
		{PortRow{Service: "sip", Ident: IdentPort}, "probably SIP"}, {PortRow{Service: "ssl/http", Ident: IdentProbed}, "HTTPS"},
		{PortRow{Service: "ssl/unknown", Ident: IdentNone}, "TLS, service not identified"}, {PortRow{Service: "unknown"}, "service not identified"},
		{PortRow{Service: "cisco-sccp", Ident: IdentPort}, "probably Cisco SCCP (IP phones)"}, {PortRow{Service: "ssl/imap", Ident: IdentProbed}, "IMAPS"},
		{PortRow{Service: "http-alt"}, "HTTP"},
	} {
		if got := ServiceLabel(c.p); got != c.want {
			t.Errorf("ServiceLabel(%+v) = %q, want %q", c.p, got, c.want)
		}
	}
}

// The alert and the page give a service one name: serviceNames is the page's LABEL table, entry for entry.
func TestServiceNamesMatchThePage(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../../web/src/features/exposure/services.ts")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "const LABEL = new Map<string, string>(Object.entries({")
	j := strings.Index(body[i:], "}))")
	if i < 0 || j < 0 {
		t.Fatal("LABEL not found in services.ts")
	}
	page := map[string]string{}
	for _, m := range regexp.MustCompile(`'?([a-z0-9/-]+)'?: '([^']+)'`).FindAllStringSubmatch(body[i:i+j], -1) {
		page[m[1]] = m[2]
	}
	if len(page) < 30 || !maps.Equal(page, serviceNames) {
		t.Fatalf("services.ts LABEL %v\n!= serviceNames %v", page, serviceNames)
	}
	for _, c := range []struct{ service, want string }{{"ssl/imap", "IMAPS"}, {"ssl/rdp", "RDP over TLS"}, {"constructor", "constructor"}, {"x", "x"}} {
		if got := serviceName(c.service); got != c.want {
			t.Errorf("serviceName(%q) = %q, want %q", c.service, got, c.want)
		}
	}
}
