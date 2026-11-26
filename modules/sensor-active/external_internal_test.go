package sensoractive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/modules/scan/commonports"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

var ownIP = netip.MustParseAddr("8.8.8.8")

// externalPorts are the ports of the External shape's -sV run after a discovery that found nothing open outside the fixed list.
var externalPorts = nmapargv.ExtraPortNumbers

// readExternal is the parse of the External shape's -sV run as ScanExternal does it: the XML limits (INV-7), then versionsOf's own
// bounds over every host nmap reported.
func readExternal(data []byte) (External, error) {
	all, err := parseNmapXML(data)
	if err != nil {
		return External{}, err
	}
	ext, err := versionsOf(all, ownIP, externalPorts, false)
	ext.Ports = len(externalPorts)
	return ext, err
}

// readDiscovery is the parse of the External shape's discovery of the fixture's address.
func readDiscovery(data []byte) (scanned, open []int, err error) {
	all, err := parseNmapXML(data)
	if err != nil {
		return nil, nil, err
	}
	return discoveryOf(all, netip.MustParseAddr("198.51.100.7"))
}

// The discovery of the External shape (nmap's --top-ports 1000, SYN only): the ports it probed are read back from nmap's own
// <scaninfo services>, never from a list of Vedette's; its open ports are those of the host. Anything but exactly the 1000 ports
// asked fails closed, as does an open port outside them; more than commonports.MaxBelievableOpen open is ErrAnswersEverywhere
// (the -sV run then reads the fixed list alone); a host nmap gave up on is ErrHostTimedOut.
func TestExternalDiscoveryReadsTheProbedPortsFromScaninfo(t *testing.T) {
	t.Parallel()
	base := string(fixture(t, "external_top_ports.xml"))
	scanned, open, err := readDiscovery([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 1000 || scanned[0] != 1 || scanned[999] != 1000 || !slices.Equal(open, []int{22, 443, 666}) {
		t.Fatalf("scanned %d ports, open %v", len(scanned), open)
	}
	batches, err := nmapargv.ExternalBatches(open)
	if err != nil || !slices.Equal(batches[len(batches)-1], []int{666}) {
		t.Fatalf("-sV batches %v %v", batches, err)
	}
	ports1 := `<port protocol="tcp" portid="22">`
	var many strings.Builder
	for p := range commonports.MaxBelievableOpen + 1 {
		fmt.Fprintf(&many, `<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="tcpwrapped" method="table" conf="3"/></port>`, 100+p)
	}
	for name, c := range map[string]struct {
		data string
		want error
	}{
		"999 ports probed":         {strings.Replace(base, `services="1-1000"`, `services="1-999"`, 1), errXMLInvalid},
		"1001 ports probed":        {strings.Replace(base, `services="1-1000"`, `services="1-1001"`, 1), errXMLInvalid},
		"no scaninfo":              {strings.Replace(base, `services="1-1000"`, `services=""`, 1), errXMLInvalid},
		"an open port not probed":  {strings.Replace(base, ports1, `<port protocol="tcp" portid="2000">`, 1), errXMLInvalid},
		"41 open ports":            {strings.Replace(base, "</ports>", many.String()+"</ports>", 1), ErrAnswersEverywhere},
		"nmap gave up on the host": {strings.Replace(base, `<host starttime`, `<host timedout="true" starttime`, 1), ErrHostTimedOut},
		"another address":          {strings.Replace(base, `addr="198.51.100.7"`, `addr="198.51.100.8"`, 1), errXMLInvalid},
		"the earlier fixed line":   {strings.Replace(base, `services="1-1000"`, `services="`+nmapargv.ExtraPorts+`"`, 1), errXMLInvalid},
	} {
		if _, _, err := readDiscovery([]byte(c.data)); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	// A worker of an earlier release runs its external line (-sV over exactly the surface list) for the discovery job: said as an
	// older worker, never as output to believe. A count other than 1000 is named in the error the probe row reads.
	old := strings.Replace(base, `services="1-1000"`, `services="`+plainList(commonports.Numbers())+`"`, 1)
	if _, _, err := readDiscovery([]byte(old)); !errors.Is(err, errOlderShape) || !errors.Is(err, ErrWorkerRefused) {
		t.Errorf("the earlier line: err = %v", err)
	}
	var count *topPortsError
	if _, _, err := readDiscovery([]byte(strings.Replace(base, `services="1-1000"`, `services="1-999"`, 1))); !errors.As(err, &count) || count.n != 999 {
		t.Errorf("999 ports: err = %v", err)
	}
}

// plainList writes ports as a comma-separated list.
func plainList(ns []int) string {
	ss := make([]string, len(ns))
	for i, n := range ns {
		ss[i] = fmt.Sprint(n)
	}
	return strings.Join(ss, ",")
}

// Count test: the TCP ports the default scan of the box's own public IP probes. Before, the external shape named exactly the
// surface scan's list (commonports, 99 ports); now its discovery probes nmap's 1000 most common ports (here the fixture's
// scaninfo) and its -sV run the fixed list, so the probed set is their union and holds at least 1000 ports.
func TestDefaultPublicScanProbesAtLeastTheTopThousand(t *testing.T) {
	t.Parallel()
	before := len(commonports.Numbers())
	scanned, open, err := readDiscovery(fixture(t, "external_top_ports.xml"))
	if err != nil {
		t.Fatal(err)
	}
	batches, err := nmapargv.ExternalBatches(open)
	if err != nil {
		t.Fatal(err)
	}
	after := unionPorts(scanned, slices.Concat(batches...))
	t.Logf("ports probed by the default public scan: before %d, after %d", before, len(after))
	if before != 99 || len(after) < 1000 {
		t.Fatalf("before %d, after %d", before, len(after))
	}
	for _, p := range commonports.Numbers() {
		if _, ok := slices.BinarySearch(after, p); !ok {
			t.Fatalf("port %d of the surface list is not probed", p)
		}
	}
}

// readFull is readExternal for a full shape: every TCP port and the script results.
func readFull(data []byte) (External, error) {
	all, err := parseNmapXML(data)
	if err != nil {
		return External{}, err
	}
	return externalOf(all, ownIP, nmapargv.ExternalFull)
}

// A full run read from a fixture written by hand after nmap's documented XML (nmap.dtd; the vulns library's output of
// smb-vuln-ms17-010 as nsedoc prints it; structured output per https://nmap.org/book/nse-api.html): a high port is a service, the
// script results of open ports and of the host are kept with the findings of their structured output (state per finding, CVE
// ids from the table key and the ids table), a text output that says "State: NOT VULNERABLE" with no structure makes no finding,
// a script of a closed port is not kept, text is cleaned and cut, a bad script id is dropped. The same XML read as the External
// shape fails closed on the high port.
func TestFullRunReadsPortsAndScripts(t *testing.T) {
	t.Parallel()
	data := fixture(t, "external_full.xml")
	got, err := readFull(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ports != 65535 || len(got.Services) != 3 || got.Services[2].Port != 49152 || got.Services[2].Product != "Jetty" {
		t.Fatalf("services: %d ports %+v", got.Ports, got.Services)
	}
	byID := map[string]ExternalScript{}
	for _, s := range got.Scripts {
		byID[s.ID] = s
	}
	if len(got.Scripts) != 5 || len(byID) != 5 {
		t.Fatalf("scripts: %+v", got.Scripts)
	}
	one := func(id, state string, cves ...string) {
		t.Helper()
		s := byID[id]
		if len(s.Findings) != 1 || s.Findings[0].State != state || !slices.Equal(s.Findings[0].CVEs, cves) || s.Findings[0].Title == "" {
			t.Fatalf("%s: %+v", id, s)
		}
	}
	one("smb-vuln-ms17-010", "vulnerable", "CVE-2017-0143") // the key and the ids table name the same CVE: once
	one("http-vuln-cve2017-5638", "vulnerable", "CVE-2017-5638")
	one("http-vuln-cve2011-3192", "likely", "CVE-2011-3192") // BID:49303 is not a CVE
	if ms := byID["smb-vuln-ms17-010"]; ms.Port != 0 || !strings.Contains(ms.Output, "\n    State: VULNERABLE\n") {
		t.Fatalf("host script: %+v", ms)
	}
	if s := byID["ssl-heartbleed"]; len(s.Findings) != 0 || s.Port != 443 { // text only: no structured finding
		t.Fatalf("text only: %+v", s)
	}
	if s := byID["http-title"]; s.Port != 443 || s.Output != "Site title: Box admin page" || len(s.Findings) != 0 { // a tab and a bidi override in the fixture
		t.Fatalf("plain script: %+v", s)
	}
	for _, s := range got.Scripts {
		if s.ID == "ftp-anon" || s.ID == "Bad Id" {
			t.Fatalf("kept %q", s.ID)
		}
	}
	if _, err := readExternal(data); !errors.Is(err, errXMLInvalid) {
		t.Fatalf("the External shape believed port 49152: %v", err)
	}
	ext, err := readExternal(fixture(t, "external.xml"))
	if err != nil || ext.Scripts != nil {
		t.Fatalf("the External shape keeps no scripts: %+v %v", ext.Scripts, err)
	}
}

// INV-7 for scripts: more script results on one host than maxScriptsPerHost fail the whole run, as too many ports do; a
// port 0 fails a full run; a script output over maxScriptOutput is not read (its port and the run are kept); a long output is cut
// to maxScriptText runes with only printable runes and line breaks left, and the CVE ids it prints are never findings.
func TestFullRunScriptLimits(t *testing.T) {
	t.Parallel()
	base := string(fixture(t, "external.xml"))
	var long strings.Builder
	for i := range 300 {
		fmt.Fprintf(&long, "&#xa;&#x7f;&#x85;[31m&#x200B;CVE-2021-%05d &#x2028;comment", 10000+i) // DEL, NEL (C1), a zero-width space, a line separator
	}
	cut := strings.Replace(base, `<service name="tcpwrapped" method="probed" conf="8"/></port>`,
		`<service name="tcpwrapped" method="probed" conf="8"/><script id="http-comments-displayer" output="`+long.String()+`"/></port>`, 1)
	got, err := readFull([]byte(cut))
	if err != nil || len(got.Scripts) != 1 {
		t.Fatalf("long output: %+v %v", got.Scripts, err)
	}
	s := got.Scripts[0]
	if utf8.RuneCountInString(s.Output) != maxScriptText || strings.ContainsFunc(s.Output, func(r rune) bool { return r != '\n' && unprintable(r) }) ||
		len(s.Findings) != 0 || s.Port != 10443 {
		t.Fatalf("long output: %d runes, findings %v", utf8.RuneCountInString(s.Output), s.Findings)
	}
	script := `<script id="http-date" output="Fri, 13 Nov 2026 10:00:00 GMT"/>`
	many := strings.Replace(base, `<service name="tcpwrapped" method="probed" conf="8"/></port>`,
		`<service name="tcpwrapped" method="probed" conf="8"/>`+strings.Repeat(script, maxScriptsPerHost+1)+`</port>`, 1)
	if _, err := readFull([]byte(many)); !errors.Is(err, errXMLInvalid) {
		t.Fatalf("too many scripts: %v", err)
	}
	zero := strings.Replace(base, `portid="10443"`, `portid="0"`, 1)
	if _, err := readFull([]byte(zero)); !errors.Is(err, errXMLInvalid) {
		t.Fatalf("port 0: %v", err)
	}
	big := strings.Replace(base, `<service name="tcpwrapped" method="probed" conf="8"/></port>`,
		`<service name="tcpwrapped" method="probed" conf="8"/><script id="banner" output="`+strings.Repeat("CVE-2020-1234 ", maxScriptOutput/14+1)+`"/></port>`, 1)
	got, err = readFull([]byte(big))
	if err != nil || len(got.Services) != 4 || len(got.Scripts) != 1 || got.Scripts[0].Output != "" || len(got.Scripts[0].Findings) != 0 {
		t.Fatalf("an output over the limit: %+v %v", got.Scripts, err)
	}
}

// Review r1 M4: a script that can print credentials or hashes (nmapargv.StoresOutput false) keeps no output text, only the
// sentence that says so; its structured findings are still read. Another script keeps its text.
func TestFullRunWithholdsCredentialOutput(t *testing.T) {
	t.Parallel()
	if nmapargv.StoresOutput("http-vuln-wnr1000-creds") || !nmapargv.StoresOutput("http-title") {
		t.Fatal("StoresOutput no longer names http-vuln-wnr1000-creds alone of the two: pick another pair")
	}
	base := string(fixture(t, "external.xml"))
	got, err := readFull([]byte(strings.Replace(base, `<service name="tcpwrapped" method="probed" conf="8"/></port>`,
		`<service name="tcpwrapped" method="probed" conf="8"/><script id="http-vuln-wnr1000-creds" output="admin password: hunter2"><table key="CVE-2009-1234"><elem key="state">VULNERABLE (Exploitable)</elem></table></script>`+
			`<script id="http-title" output="Router login"/></port>`, 1)))
	if err != nil || len(got.Scripts) != 2 {
		t.Fatalf("%+v %v", got.Scripts, err)
	}
	if s := got.Scripts[0]; s.Output != outputWithheld || strings.Contains(s.Output, "hunter2") || len(s.Findings) != 1 || s.Findings[0].State != "vulnerable" {
		t.Fatalf("withheld: %+v", s)
	}
	if s := got.Scripts[1]; s.Output != "Router login" {
		t.Fatalf("kept: %+v", s)
	}
}

// Review r1 M1, L2, L3: findings come only from the vulns library's structured output. A page comment or a banner that prints a
// CVE id and "State: VULNERABLE" makes none; a table under the script without a state is not a finding, nor is an elem "state"
// nested deeper than the finding's own fields; each finding keeps its own state (one VULNERABLE, one LIKELY VULNERABLE in one
// script), and a CVE id longer than CVE syntax allows is not cut into a shorter one.
func TestFullRunFindingsAreStructuredOnly(t *testing.T) {
	t.Parallel()
	base := string(fixture(t, "external.xml"))
	add := func(script string) External {
		t.Helper()
		got, err := readFull([]byte(strings.Replace(base, `<service name="tcpwrapped" method="probed" conf="8"/></port>`,
			`<service name="tcpwrapped" method="probed" conf="8"/>`+script+`</port>`, 1)))
		if err != nil || len(got.Scripts) != 1 {
			t.Fatalf("%+v %v", got.Scripts, err)
		}
		return got
	}
	text := add(`<script id="http-comments-displayer" output="&lt;!-- fixed CVE-2023-4966 --&gt;&#xa;    State: VULNERABLE&#xa;    IDs:  CVE:CVE-2023-4966"><elem key="state">VULNERABLE</elem><table><elem key="state">VULNERABLE</elem><table key="x"><elem key="state">VULNERABLE</elem></table></table></script>`)
	if f := text.Scripts[0].Findings; len(f) != 1 || f[0].State != "vulnerable" || len(f[0].CVEs) != 0 {
		// the one finding is the table whose own state is VULNERABLE; the CVE of the free text and the elems elsewhere are not read
		t.Fatalf("free text: %+v", f)
	}
	none := add(`<script id="banner" output="State: VULNERABLE CVE-2023-4966"><table key="CVE-2023-4966"><elem key="title">no state</elem></table></script>`)
	if f := none.Scripts[0].Findings; len(f) != 0 {
		t.Fatalf("a table without a state: %+v", f)
	}
	two := add(`<script id="smb-vuln-ms17-010"><table key="CVE-2017-0143"><elem key="state">VULNERABLE (Exploitable)</elem><elem key="title">a</elem></table>` +
		`<table key="CVE-2017-0144"><elem key="state">LIKELY VULNERABLE</elem><elem key="title">b</elem><table key="ids"><elem>CVE:CVE-2021-12345678</elem><elem>CVE:CVE-2017-0145</elem></table></table></script>`)
	f := two.Scripts[0].Findings
	if len(f) != 2 || f[0].State != "vulnerable" || !slices.Equal(f[0].CVEs, []string{"CVE-2017-0143"}) ||
		f[1].State != "likely" || !slices.Equal(f[1].CVEs, []string{"CVE-2017-0144", "CVE-2017-0145"}) {
		t.Fatalf("per finding: %+v", f)
	}
}

// What -sV read on each open port of the box's own IP: the application CPE only, the extra info, a service with no
// version (nginx), a tcpwrapped port; Ports is the probed list, not the open ports.
func TestExternalServicesFromTheXML(t *testing.T) {
	t.Parallel()
	got, err := readExternal(fixture(t, "external.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []ExternalService{
		{Port: 22, Name: "ssh", Product: "OpenSSH", Version: "7.4p1 Debian 10+deb9u7", CPE: "cpe:/a:openbsd:openssh:7.4p1", Extra: "protocol 2.0", Method: "probed", Conf: 10},
		{Port: 443, Name: "ssl/http", Product: "nginx", CPE: "cpe:/a:igor_sysoev:nginx", Method: "probed", Conf: 10}, // tunnel="ssl"
		{Port: 8443, Name: "ssl/http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49", Extra: "(Unix)", Method: "probed", Conf: 10},
		{Port: 10443, Name: "tcpwrapped", Method: "probed", Conf: 8},
	}
	if got.Ports != len(externalPorts) || !slices.Equal(got.Services, want) {
		t.Fatalf("got %d ports %+v", got.Ports, got.Services)
	}
}

// An HTTPS page on 4443 (name="http" tunnel="ssl") reaches exposure as "ssl/http", so its templates speak TLS; an
// address with 60 of the -sV run's ports open (a router or SYN proxy answering for all of them) keeps only the ports where -sV
// named a real service, never 60 tcpwrapped services, and says it answers everywhere.
func TestExternalTLSTunnelAndAnswersEverywhere(t *testing.T) {
	t.Parallel()
	base := string(fixture(t, "external.xml"))
	ports := base[strings.Index(base, "<port ") : strings.LastIndex(base, "</port>")+len("</port>")]
	tls := `<port protocol="tcp" portid="4443"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="http" product="lighttpd" tunnel="ssl" method="probed" conf="10"/></port>`
	got, err := readExternal([]byte(strings.Replace(base, ports, tls, 1)))
	if err != nil || len(got.Services) != 1 || got.Services[0] != (ExternalService{Port: 4443, Name: "ssl/http", Product: "lighttpd", Method: "probed", Conf: 10}) {
		t.Fatalf("tunnel: %+v %v", got.Services, err)
	}
	var tarpit strings.Builder
	for _, p := range externalPorts[:60] {
		fmt.Fprintf(&tarpit, `<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="tcpwrapped" method="probed" conf="8"/></port>`, p)
	}
	if got, err := readExternal([]byte(strings.Replace(base, ports, tarpit.String(), 1))); err != nil || !got.AnswersEverywhere || len(got.Services) != 0 {
		t.Fatalf("tarpit: %d services, everywhere %v, %v", len(got.Services), got.AnswersEverywhere, err)
	}
	last := externalPorts[len(externalPorts)-1]
	named := fmt.Sprintf(`<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="http" product="lighttpd" method="probed" conf="10"/></port>`, last)
	if got, err := readExternal([]byte(strings.Replace(base, ports, tarpit.String()+named, 1))); err != nil || !got.AnswersEverywhere || len(got.Services) != 1 || got.Services[0].Port != last {
		t.Fatalf("tarpit with a real service: %+v, %v", got.Services, err)
	}
	var forty strings.Builder // exactly the limit is still believed
	for _, p := range externalPorts[:40] {
		fmt.Fprintf(&forty, `<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="tcpwrapped" method="probed" conf="8"/></port>`, p)
	}
	if got, err := readExternal([]byte(strings.Replace(base, ports, forty.String(), 1))); err != nil || len(got.Services) != 40 || got.AnswersEverywhere {
		t.Fatalf("40 open: %d services, %v", len(got.Services), err)
	}
}

// The output is untrusted (INV-7): an answer outside what was asked fails the whole run, never a part of it; a DOCTYPE with
// an internal subset (an entity) is refused before anything is read; nmap giving up on the host is said, not read as "no service".
func TestExternalOutputFailsClosed(t *testing.T) {
	t.Parallel()
	base := string(fixture(t, "external.xml"))
	host := base[strings.Index(base, "<host ") : strings.Index(base, "</host>")+len("</host>")]
	port := `<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="ssh" method="table" conf="3"/></port>`
	deep := strings.Repeat("<a>", maxXMLDepth) + strings.Repeat("</a>", maxXMLDepth)
	for name, c := range map[string]struct {
		data []byte
		want error
	}{
		"a port that was not probed": {fixture(t, "external_unprobed.xml"), errXMLInvalid},
		"a UDP port":                 {fixture(t, "external_udp.xml"), errXMLInvalid},
		"an entity in the DOCTYPE":   {fixture(t, "external_entity.xml"), errXMLInvalid},
		"nmap gave up on the host":   {fixture(t, "external_timedout.xml"), ErrHostTimedOut},
		"the host twice":             {[]byte(strings.Replace(base, host, host+host, 1)), errXMLInvalid},
		"a port twice":               {[]byte(strings.Replace(base, "</ports>", port+"</ports>", 1)), errXMLInvalid},
		"too deep":                   {[]byte(strings.Replace(base, "<hostnames/>", "<hostnames>"+deep+"</hostnames>", 1)), errXMLInvalid},
		"over the size limit":        {append([]byte(base), bytes.Repeat([]byte(" "), maxOutput)...), errXMLTooBig},
		"cut off":                    {[]byte(base[:len(base)/2]), errXMLInvalid},
		"another charset":            {[]byte(strings.Replace(base, `encoding="UTF-8"`, `encoding="ISO-8859-1"`, 1)), errXMLInvalid},
		"an external DTD":            {[]byte(strings.Replace(base, "<!DOCTYPE nmaprun>", `<!DOCTYPE nmaprun SYSTEM "http://203.0.113.9/x.dtd">`, 1)), errXMLInvalid},
	} {
		if _, err := readExternal(c.data); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	// #723 review L3: a host of another address fails the run, with or without the target's; no usable host is not "0 open ports"
	other := strings.Replace(host, `addr="8.8.8.8"`, `addr="1.1.1.1"`, 1)
	down := strings.Replace(host, `state="up"`, `state="down"`, 1)
	for name, data := range map[string]string{
		"another host as well": strings.Replace(base, host, host+other, 1),
		"only another host":    strings.Replace(base, host, other, 1),
		"no host":              strings.Replace(base, host, "", 1),
		"the host down":        strings.Replace(base, host, down, 1),
	} {
		if got, err := readExternal([]byte(data)); !errors.Is(err, errXMLInvalid) {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
}

// identifiedService keeps a port where -sV named a real service and drops what a SYN proxy prints on every port.
func TestIdentifiedService(t *testing.T) {
	t.Parallel()
	for x, want := range map[ExternalService]bool{
		{Port: 22, Name: "ssh", Product: "OpenSSH", Method: "probed", Conf: 10}: true,
		{Port: 8443, Name: "ssl/http", Version: "2.4.49", Method: "probed"}:     true,
		{Port: 443, Name: "ssl/https", Method: "probed", Conf: 10}:              true,
		{Port: 10443, Name: "tcpwrapped", Method: "probed", Conf: 8}:            false,
		{Port: 10444, Name: "ssl/tcpwrapped", Method: "probed"}:                 false,
		{Port: 9999, Name: "unknown", Method: "probed"}:                         false,
		{Port: 3306, Name: "mysql", Method: "table", Conf: 3}:                   false,
		{Port: 3307}: false,
	} {
		if identifiedService(x) != want {
			t.Errorf("%+v: %v", x, !want)
		}
	}
}

// FuzzExternalOf: whatever the XML, what reaches exposure is at most one row per probed TCP port, printable text of at most 200
// runes, and an application CPE or nothing.
func FuzzExternalOf(f *testing.F) {
	for _, n := range []string{"external.xml", "external_unprobed.xml", "external_udp.xml", "external_timedout.xml", "external_entity.xml", "device.xml"} {
		f.Add(fixture(f, n))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ext, err := readExternal(data)
		if err != nil {
			return
		}
		if ext.Ports != len(externalPorts) || len(ext.Services) > len(externalPorts) {
			t.Fatalf("%d services of %d ports", len(ext.Services), ext.Ports)
		}
		seen := map[int]bool{}
		for _, s := range ext.Services {
			if !slices.Contains(externalPorts, s.Port) || seen[s.Port] {
				t.Fatalf("port %d", s.Port)
			}
			seen[s.Port] = true
			for _, v := range []string{s.Name, s.Product, s.Version, s.Extra} {
				if v != "" && (text(v) != v || utf8.RuneCountInString(v) > maxText) {
					t.Fatalf("unchecked text %q", v)
				}
			}
			if s.CPE != "" && (!strings.HasPrefix(s.CPE, "cpe:/a:") || cpeText(s.CPE) != s.CPE) {
				t.Fatalf("cpe %q", s.CPE)
			}
		}
	})
}

type yesFence struct{}

func (yesFence) OwnEgress(context.Context, netip.Addr) (bool, error) { return true, nil }

// #723 review L4: once the module is turned off (Stop) an external run and a picked identification end before they queue, ask or send
// anything; one already queued or running is stopped by core/run with its module (run.Manager.ModuleChanged).
func TestStopBeforeTheRunIsHonoured(t *testing.T) {
	t.Parallel()
	s := &Service{log: slog.New(slog.DiscardHandler), clock: time.Now}
	s.Stop()
	if _, err := s.ScanExternal(t.Context(), ownIP, nmapargv.External, yesFence{}); !errors.Is(err, ErrStopped) {
		t.Errorf("external: err = %v, want ErrStopped", err)
	}
	if _, err := s.IdentifyDevice(t.Context(), "a-web"); !errors.Is(err, ErrStopped) {
		t.Errorf("identify: err = %v, want ErrStopped", err)
	}
}

// #723 review L5: with less of the caller's time left than the run needs (the worker's fence, nmap's 3-minute host timeout, the
// pickup and the result), the run is skipped before it waits, asks or sends anything.
func TestExternalSkippedWhenTooLittleTimeIsLeft(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := &Service{log: slog.New(slog.DiscardHandler), clock: time.Now}
		ctx, cancel := context.WithTimeout(t.Context(), externalNeed+coreFenceTime-time.Second)
		defer cancel()
		if _, err := s.ScanExternal(ctx, ownIP, nmapargv.External, yesFence{}); !errors.Is(err, ErrNoTime) {
			t.Fatalf("err = %v, want ErrNoTime", err)
		}
		// A full run needs its hour: what was enough for External is not enough for it
		full, cancel := context.WithTimeout(t.Context(), fullNeed+coreFenceTime-time.Second)
		defer cancel()
		if _, err := s.ScanExternal(full, ownIP, nmapargv.ExternalFull, yesFence{}); !errors.Is(err, ErrNoTime) {
			t.Fatalf("full: err = %v, want ErrNoTime", err)
		}
		if _, err := s.ScanExternal(full, ownIP, nmapargv.Normal, yesFence{}); err == nil {
			t.Fatal("a LAN shape ran as an external one")
		}
	})
}

// How nmap named each service reaches exposure. method="probed" is a probe's answer, method="table" only nmap-services'
// usual name of the port number (conf 3), and any other method word is not passed on.
func TestExternalServiceMethodAndConf(t *testing.T) {
	t.Parallel()
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap" version="7.95" xmloutputversion="1.05">
<host><status state="up" reason="user-set"/><address addr="8.8.8.8" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13.20" method="probed" conf="10"/></port>
<port protocol="tcp" portid="2000"><state state="open" reason="syn-ack"/><service name="cisco-sccp" method="table" conf="3"/></port>
<port protocol="tcp" portid="5060"><state state="open" reason="syn-ack"/><service name="sip" method="table" conf="3"/></port>
<port protocol="tcp" portid="11443"><state state="open" reason="syn-ack"/><service name="unknown" tunnel="ssl" method="table" conf="3"/></port>
<port protocol="tcp" portid="11080"><state state="open" reason="syn-ack"/><service name="unknown" method="guessed" conf="11"/></port>
</ports></host></nmaprun>`)
	all, err := parseNmapXML(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := externalOf(all, ownIP, nmapargv.ExternalFull)
	if err != nil {
		t.Fatal(err)
	}
	type mc struct {
		name, method string
		conf         int
	}
	want := map[int]mc{22: {"ssh", "probed", 10}, 2000: {"cisco-sccp", "table", 3}, 5060: {"sip", "table", 3}, 11443: {"ssl/unknown", "table", 3}, 11080: {"unknown", "", 10}}
	if len(got.Services) != len(want) {
		t.Fatalf("services: %+v", got.Services)
	}
	for _, s := range got.Services {
		if w := want[s.Port]; (mc{s.Name, s.Method, s.Conf}) != w {
			t.Errorf("port %d: %q %q %d, want %+v", s.Port, s.Name, s.Method, s.Conf, w)
		}
	}
}

// Each -sV batch's host timeout is what is left once its job overhead is set aside, in whole seconds, at most two minutes; below
// one minute the batch is not started.
func TestBatchTimeout(t *testing.T) {
	t.Parallel()
	for left, want := range map[time.Duration]struct {
		h  time.Duration
		ok bool
	}{
		10 * time.Minute:                       {nmapargv.BatchMaxTimeout, true},
		140 * time.Second:                      {100 * time.Second, true},
		100*time.Second + 900*time.Millisecond: {60 * time.Second, true},
		100 * time.Second:                      {60 * time.Second, true},
		99 * time.Second:                       {59 * time.Second, false},
		0:                                      {-externalStep, false},
	} {
		if h, ok := batchTimeout(left); h != want.h || ok != want.ok {
			t.Errorf("left %s: %s %v, want %s %v", left, h, ok, want.h, want.ok)
		}
	}
}

// The budget of the default scan within its 8-minute step (exposure's ServicesTimeout, externalRun here). Worst case: every
// allowance is used up (the wait for the nmap slot as long as the run's need allows, core's and the worker's own-IP checks at their
// longest, the discovery at its host timeout, the batches' inner margin): one batch still gets a host timeout above the minimum (85 s), and the rest wait for the next
// scan. A SYN proxy that holds every connection with no allowance used (the discovery in 30 s, every batch at its host timeout):
// three batches a run. A normal box finishes every batch in seconds.
func TestBatchBudgetWorstCase(t *testing.T) {
	t.Parallel()
	const step = 8 * time.Minute
	simulate := func(wait, fence, job, discovery time.Duration, batchTakes func(h time.Duration) time.Duration) (hosts []time.Duration) {
		at := wait + fence + job + discovery
		for {
			if step-innerMargin-at < batchNeed { // runBatches' check before the own-IP check
				return hosts
			}
			at += fence
			h, ok := batchTimeout(step - innerMargin - at)
			if !ok {
				return hosts
			}
			hosts = append(hosts, h)
			at += job + batchTakes(h)
		}
	}
	wait := min(busyWait, step-externalNeed-coreFenceTime)
	worst := simulate(wait, coreFenceTime, externalStep, nmapargv.ExternalDiscoveryTimeout, func(h time.Duration) time.Duration { return h })
	proxy := simulate(0, 0, 0, 30*time.Second, func(h time.Duration) time.Duration { return h })
	t.Logf("worst case: slot wait %s, batches %v; SYN proxy: batches %v", wait, worst, proxy)
	if wait != busyWait || len(worst) != 1 || worst[0] != 85*time.Second {
		t.Fatalf("worst case: wait %s, batches %v", wait, worst)
	}
	if len(proxy) != 3 || proxy[0] != nmapargv.BatchMaxTimeout {
		t.Fatalf("SYN proxy: batches %v", proxy)
	}
	if externalNeed+coreFenceTime > step {
		t.Fatalf("the run's need %s does not fit the step", externalNeed+coreFenceTime)
	}
}

// simulateRuns plans and "runs" the batches of runs scans in a row, as probeDefault would, from the probe rows the last run left:
// each run reads its first k batches (fail says which of them fail, by their first port) and does not start the rest. It returns,
// for each run, the first port of every batch that finished.
func simulateRuns(t *testing.T, runs, k int, open, scanned []int, everywhere bool, fail func(first int) bool) [][]int {
	t.Helper()
	var last []lastBatch
	var read [][]int
	for range runs {
		batches, err := planBatches(open, scanned, last, everywhere)
		if err != nil {
			t.Fatal(err)
		}
		last = nil
		var got []int
		for i, b := range batches {
			switch {
			case i >= k:
				last = append(last, lastBatch{ports: b, state: batchNotStarted})
			case fail != nil && fail(b[0]):
				last = append(last, lastBatch{ports: b, state: batchFailed})
			default:
				last = append(last, lastBatch{ports: b, state: batchDone})
				got = append(got, b[0])
			}
		}
		read = append(read, got)
	}
	return read
}

// The rotation is a queue kept in the probe log: whatever the number of batches that fit a run (k) and the path (a normal
// discovery with an extra open port, a cut discovery or an address that answers everywhere: the fixed list only), every batch is
// read at least once in every ceil(n/k) runs in a row (at most 6), so the fixed-list batches are never starved; the first batch of
// the surface list is not always first. A batch that always fails cannot block the others, and is still tried.
func TestRotationReadsEveryBatch(t *testing.T) {
	t.Parallel()
	normal, err := nmapargv.ExternalBatches([]int{50000})
	if err != nil {
		t.Fatal(err)
	}
	fixed, err := nmapargv.ExternalBatches(nil)
	if err != nil {
		t.Fatal(err)
	}
	firsts := func(bs [][]int) []int {
		var out []int
		for _, b := range bs {
			out = append(out, b[0])
		}
		return out
	}
	for name, c := range map[string]struct {
		open, scanned []int
		everywhere    bool
		want          [][]int
	}{
		"normal":             {[]int{50000}, []int{1, 50000}, false, normal},
		"discovery cut":      {nil, nil, false, fixed},
		"answers everywhere": {nil, nil, true, fixed},
	} {
		for _, k := range []int{1, 2} {
			read := simulateRuns(t, 12, k, c.open, c.scanned, c.everywhere, nil)
			window := (len(c.want) + k - 1) / k
			if window > 6 {
				t.Fatalf("%s, k=%d: window %d", name, k, window)
			}
			for _, first := range firsts(c.want) {
				for from := 0; from+window <= len(read); from++ {
					seen := false
					for _, r := range read[from : from+window] {
						seen = seen || slices.Contains(r, first)
					}
					if !seen {
						t.Fatalf("%s, k=%d: the batch starting at port %d is not read in runs %d..%d: %v", name, k, first, from+1, from+window, read)
					}
				}
			}
			if k == 1 && read[1][0] == firsts(c.want)[0] {
				t.Fatalf("%s: the surface list's first batch is first again: %v", name, read)
			}
		}
	}
	// one batch that always fails (the second of the surface list): the others are still each read once in every 6 runs, and it is
	// tried again within those 6 runs too
	bad := normal[1][0]
	tried := 0
	var last []lastBatch
	for range 12 {
		batches, err := planBatches([]int{50000}, []int{1, 50000}, last, false)
		if err != nil {
			t.Fatal(err)
		}
		if batches[0][0] == bad {
			tried++
		}
		last = []lastBatch{}
		for i, b := range batches {
			state := batchNotStarted
			if i == 0 {
				state = batchDone
				if b[0] == bad {
					state = batchFailed
				}
			}
			last = append(last, lastBatch{ports: b, state: state})
		}
	}
	if tried < 2 {
		t.Fatalf("the failing batch was tried %d times in 12 runs", tried)
	}
	read := simulateRuns(t, 12, 1, []int{50000}, []int{1, 50000}, false, func(first int) bool { return first == bad })
	for _, first := range firsts(normal) {
		if first == bad {
			continue
		}
		for from := 0; from+6 <= len(read); from++ {
			seen := false
			for _, r := range read[from : from+6] {
				seen = seen || slices.Contains(r, first)
			}
			if !seen {
				t.Fatalf("a failing batch starved the batch at port %d in runs %d..%d: %v", first, from+1, from+6, read)
			}
		}
	}
}

// The queue order: the batches not started last run first (in that run's order), then those that failed, then the others in their
// usual order; a fixed port the last run wrote no row for (it stopped early) counts as not started, after those that say so.
func TestPlanBatchesQueue(t *testing.T) {
	t.Parallel()
	plain, err := planBatches(nil, nil, nil, false)
	if err != nil || len(plain) != 5 {
		t.Fatalf("plain %v %v", plain, err)
	}
	last := []lastBatch{{plain[0], batchDone}, {plain[1], batchFailed}, {plain[4], batchNotStarted}, {plain[2], batchNotStarted}}
	got, err := planBatches(nil, nil, last, false)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]int{plain[4], plain[2], plain[3], plain[1], plain[0]} // plain[3] has no row: not started, after the rows that say so
	for i := range want {
		if !slices.Equal(got[i], want[i]) {
			t.Fatalf("queue %v, want %v", firstPorts(got), firstPorts(want))
		}
	}
	// a batch only of newly found extras is not started too, after every batch the last run planned and did not finish; it goes
	// before the ones that failed or finished
	got, err = planBatches([]int{50000}, []int{50000}, last, false)
	if err != nil {
		t.Fatal(err)
	}
	want = [][]int{plain[4], plain[2], plain[3], {50000}, plain[1], plain[0]}
	for i := range want {
		if !slices.Equal(got[i], want[i]) {
			t.Fatalf("queue with new extras %v, want %v", firstPorts(got), firstPorts(want))
		}
	}
}

func firstPorts(bs [][]int) []int {
	var out []int
	for _, b := range bs {
		out = append(out, b[0])
	}
	return out
}

// The extras of a run: the open ports the discovery found first, then the last run's unfinished extras the discovery did not see
// closed (still open, or not among the ports it probed); one it saw closed needs no -sV. At most 40 in all, so the ports seen open
// now always fit.
func TestPlanBatchesExtras(t *testing.T) {
	t.Parallel()
	scanned := []int{1000, 1001, 1002, 1003}
	last := []lastBatch{{[]int{1001, 1002, 60000}, batchFailed}}
	got, err := planBatches([]int{1000, 1001}, scanned, last, false)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(got, func(b []int) bool { return slices.Contains(b, 1000) })
	if i < 0 || !slices.Equal(got[i], []int{1000, 1001, 60000}) { // 1002 was seen closed; 60000 was not probed
		t.Fatalf("batches %v", got)
	}
	if extras := got[i]; !slices.Equal(extras, []int{1000, 1001, 60000}) {
		t.Fatalf("extras %v", extras)
	}
	var carried []lastBatch
	for p := range 40 {
		carried = append(carried, lastBatch{[]int{40000 + p}, batchFailed})
	}
	var open []int
	for p := range 40 {
		open = append(open, 50000+p)
	}
	got, err = planBatches(open, nil, carried, false)
	if err != nil {
		t.Fatal(err)
	}
	var all []int
	for _, b := range got {
		all = append(all, b...)
	}
	for _, p := range open {
		if !slices.Contains(all, p) {
			t.Fatalf("open port %d pushed out by carried ports", p)
		}
	}
	if unread := unreadOpen([]int{22, 50000, 50001}, []int{22, 50000}); !slices.Equal(unread, []int{50001}) {
		t.Fatalf("unreadOpen = %v", unread)
	}
}

// runBatches keeps every finished batch whatever happens to a later one: a batch cut at its own bound (its host timeout plus the
// job's overhead) while the run goes on is unfinished and the next one still runs; a lost worker ends the loop with the rest not
// started; the batches that no longer fit before the inner deadline are not started. Only a stop or a fence refusal discards all.
// Time is synctest's: nothing waits for real.
func TestRunBatchesKeepsFinishedOnes(t *testing.T) {
	t.Parallel()
	batches := [][]int{{22}, {80}, {443}, {8443}}
	yes := func(context.Context) error { return nil }
	type call struct {
		ports []int
		host  time.Duration
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
		defer cancel()
		var calls []call
		var notStarted []string
		res, err := runBatches(ctx, batches, batchRunner{
			fence: yes,
			run: func(ctx context.Context, b []int, h time.Duration, _ string) ([]ExternalService, error) {
				calls = append(calls, call{b, h})
				if b[0] == 80 { // holds past its own bound
					<-ctx.Done()
					return nil, ErrStopped
				}
				return []ExternalService{{Port: b[0], Name: "http", Product: "x"}}, nil
			},
			notStarted: func(_ []int, label, why string) { notStarted = append(notStarted, label+": "+why) },
		})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(res.done, []int{22, 443, 8443}) || !slices.Equal(res.unfinished, []int{80}) || len(res.services) != 3 || len(calls) != 4 {
			t.Fatalf("done %v unfinished %v services %d calls %v", res.done, res.unfinished, len(res.services), calls)
		}
		if calls[0].host != nmapargv.BatchMaxTimeout {
			t.Fatalf("first host timeout %s", calls[0].host)
		}

		// little time: the first batch fits at its shortest, the rest are not started
		short, cancel2 := context.WithTimeout(t.Context(), externalStep+nmapargv.BatchMinTimeout+30*time.Second)
		defer cancel2()
		notStarted = nil
		res, err = runBatches(short, batches, batchRunner{fence: yes,
			run: func(ctx context.Context, _ []int, _ time.Duration, _ string) ([]ExternalService, error) {
				<-ctx.Done() // the batch takes its whole bound
				return nil, ErrHostTimedOut
			},
			notStarted: func(_ []int, label, why string) { notStarted = append(notStarted, label+": "+why) },
		})
		if !errors.Is(err, ErrHostTimedOut) || len(notStarted) != 3 || notStarted[0] != "batch 2 of 4: "+whyNoTime {
			t.Fatalf("err %v, not started %v", err, notStarted)
		}

		// a lost worker on batch 2: batch 1 is kept, batches 3 and 4 are not started
		notStarted = nil
		res, err = runBatches(ctx, batches, batchRunner{fence: yes,
			run: func(_ context.Context, b []int, _ time.Duration, _ string) ([]ExternalService, error) {
				if b[0] == 80 {
					return nil, ErrWorkerLost
				}
				return []ExternalService{{Port: b[0]}}, nil
			},
			notStarted: func(_ []int, label, why string) { notStarted = append(notStarted, label+": "+why) },
		})
		if err != nil || !slices.Equal(res.done, []int{22}) || !slices.Equal(res.unfinished, []int{80, 443, 8443}) || len(notStarted) != 2 || notStarted[0] != "batch 3 of 4: "+whyWorkerLost {
			t.Fatalf("worker lost: %+v %v %v", res, err, notStarted)
		}

		// near the inner deadline: the own-IP check runs into it (it takes longer than what is left) or there is too little left to
		// try one; either way batch 1 is kept and the rest are not started, the check not even asked for a batch that cannot fit
		near, cancel4 := context.WithTimeout(t.Context(), batchNeed+40*time.Second)
		defer cancel4()
		fenced := 0
		notStarted = nil
		res, err = runBatches(near, batches, batchRunner{
			fence: func(ctx context.Context) error {
				fenced++
				if fenced == 2 { // the check is slow this time: it hits the inner deadline
					<-ctx.Done()
					return ErrStopped
				}
				return nil
			},
			run: func(_ context.Context, b []int, _ time.Duration, _ string) ([]ExternalService, error) {
				return []ExternalService{{Port: b[0]}}, nil
			},
			notStarted: func(_ []int, label, why string) { notStarted = append(notStarted, label+": "+why) },
		})
		if err != nil || !slices.Equal(res.done, []int{22}) || len(notStarted) != 3 || notStarted[0] != "batch 2 of 4: "+whyNoTime || fenced != 2 {
			t.Fatalf("slow check at the inner deadline: %+v %v %v, %d checks", res, err, notStarted, fenced)
		}
		tight, cancel5 := context.WithTimeout(t.Context(), batchNeed-time.Second)
		defer cancel5()
		fenced, notStarted = 0, nil
		_, err = runBatches(tight, batches, batchRunner{
			fence: func(context.Context) error { fenced++; return nil },
			run: func(context.Context, []int, time.Duration, string) ([]ExternalService, error) {
				t.Fatal("a batch ran with too little time")
				return nil, nil
			},
			notStarted: func(_ []int, label, why string) { notStarted = append(notStarted, label+": "+why) },
		})
		if !errors.Is(err, ErrNoTime) || fenced != 0 || len(notStarted) != 4 {
			t.Fatalf("too little time: err %v, %d checks, not started %v", err, fenced, notStarted)
		}

		// a stop during batch 2 discards everything
		fresh, cancel6 := context.WithTimeout(t.Context(), 8*time.Minute) // the fake clock moved on in the cases above
		defer cancel6()
		stop, cancel3 := context.WithCancel(fresh)
		_, err = runBatches(stop, batches, batchRunner{fence: yes,
			run: func(_ context.Context, b []int, _ time.Duration, _ string) ([]ExternalService, error) {
				if b[0] == 80 {
					cancel3()
					return nil, ErrStopped
				}
				return []ExternalService{{Port: b[0]}}, nil
			},
			notStarted: func([]int, string, string) {},
		})
		if !errors.Is(err, ErrStopped) {
			t.Fatalf("stop: err = %v", err)
		}
	})
}

// A full run says whether the address answered with closed replies (TCP resets): with no open port, that is what tells "nothing
// open" from "nothing reached the address" for exposure. Ports nmap grouped as filtered (no reply) are not an answer.
func TestFullRunSaysTheAddressAnsweredWithClosedPorts(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("198.51.100.7")
	got, err := externalOf([]host{{addr: ip, closed: 65535}}, ip, nmapargv.ExternalFull)
	if err != nil || !got.Refused || len(got.Services) != 0 {
		t.Fatalf("a full run with closed ports only: %+v, %v", got, err)
	}
	got, err = externalOf([]host{{addr: ip, filtered: 65535}}, ip, nmapargv.ExternalFull)
	if err != nil || got.Refused {
		t.Fatalf("a full run with filtered ports only: %+v, %v", got, err)
	}
}
