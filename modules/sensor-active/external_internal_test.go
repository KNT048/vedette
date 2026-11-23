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
	ext, err := versionsOf(all, ownIP, externalPorts)
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
// before any -sV run; a host nmap gave up on is ErrHostTimedOut.
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
	ports, err := nmapargv.ExternalVersionPorts(open)
	if err != nil || !slices.Contains(ports, 666) || !slices.Contains(ports, 22) || len(ports) != len(nmapargv.ExtraPortNumbers)+1 {
		t.Fatalf("-sV ports %v %v", ports, err)
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
	} {
		if _, _, err := readDiscovery([]byte(c.data)); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
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
	ports, err := nmapargv.ExternalVersionPorts(open)
	if err != nil {
		t.Fatal(err)
	}
	after := unionPorts(scanned, ports)
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
// address with 60 of the -sV run's ports open (a router or SYN proxy answering for all of them) is ErrAnswersEverywhere, never 60 services.
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
	if got, err := readExternal([]byte(strings.Replace(base, ports, tarpit.String(), 1))); !errors.Is(err, ErrAnswersEverywhere) {
		t.Fatalf("tarpit: %d services, %v", len(got.Services), err)
	}
	var forty strings.Builder // exactly the limit is still believed
	for _, p := range externalPorts[:40] {
		fmt.Fprintf(&forty, `<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="tcpwrapped" method="probed" conf="8"/></port>`, p)
	}
	if got, err := readExternal([]byte(strings.Replace(base, ports, forty.String(), 1))); err != nil || len(got.Services) != 40 {
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
