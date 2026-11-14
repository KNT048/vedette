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

	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

var ownIP = netip.MustParseAddr("8.8.8.8")

// readExternal is the parse of an external run as ScanExternal does it: the XML limits (INV-7), then externalOf's own bounds over
// every host nmap reported (D-514).
func readExternal(data []byte) (External, error) {
	all, err := parseNmapXML(data)
	if err != nil {
		return External{}, err
	}
	return externalOf(all, ownIP, nmapargv.External)
}

// readFull is readExternal for a full shape (D-526): every TCP port and the script results.
func readFull(data []byte) (External, error) {
	all, err := parseNmapXML(data)
	if err != nil {
		return External{}, err
	}
	return externalOf(all, ownIP, nmapargv.ExternalFull)
}

// D-526: a full run read from a fixture written by hand after nmap's documented XML (nmap.dtd; the vulns library's output of
// smb-vuln-ms17-010 as nsedoc prints it; structured output per https://nmap.org/book/nse-api.html): a high port is a service, the
// script results of open ports and of the host are kept with their CVE ids and whether they say VULNERABLE ("LIKELY VULNERABLE"
// and "NOT VULNERABLE" do not), a script of a closed port is not, text is cleaned and cut, a bad script id is dropped. The same
// XML read as the External shape fails closed on the high port.
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
	ms := byID["smb-vuln-ms17-010"]
	if ms.Port != 0 || !ms.Vulnerable || !slices.Equal(ms.CVEs, []string{"CVE-2017-0143"}) || !strings.Contains(ms.Output, "\n    State: VULNERABLE\n") {
		t.Fatalf("host script: %+v", ms)
	}
	if s := byID["http-vuln-cve2017-5638"]; s.Port != 49152 || !s.Vulnerable || !slices.Equal(s.CVEs, []string{"CVE-2017-5638"}) {
		t.Fatalf("structured state: %+v", s)
	}
	if s := byID["ssl-heartbleed"]; s.Vulnerable || !slices.Equal(s.CVEs, []string{"CVE-2014-0160"}) {
		t.Fatalf("NOT VULNERABLE: %+v", s)
	}
	if s := byID["http-vuln-cve2011-3192"]; s.Vulnerable || s.Port != 443 {
		t.Fatalf("LIKELY VULNERABLE: %+v", s)
	}
	if s := byID["http-title"]; s.Port != 443 || s.Output != "Site title: Box admin page" || s.Vulnerable || len(s.CVEs) != 0 { // a tab and a bidi override in the fixture
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

// INV-7 for scripts (D-526): more script results on one host than maxScriptsPerHost fail the whole run, as too many ports do; a
// port 0 fails a full run; a script output over maxScriptOutput is not read (its port and the run are kept); a long output is cut
// to maxScriptText runes with only printable runes and line breaks left, and names at most maxScriptCVEs CVEs.
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
		len(s.CVEs) != maxScriptCVEs || s.CVEs[0] != "CVE-2021-10000" || s.Port != 10443 {
		t.Fatalf("long output: %d runes, CVEs %v", utf8.RuneCountInString(s.Output), s.CVEs)
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
	if err != nil || len(got.Services) != 4 || len(got.Scripts) != 1 || got.Scripts[0].Output != "" || len(got.Scripts[0].CVEs) != 0 {
		t.Fatalf("an output over the limit: %+v %v", got.Scripts, err)
	}
}

// D-514: what -sV read on each open port of the box's own IP: the application CPE only, the extra info, a service with no
// version (nginx), a tcpwrapped port; Ports is the probed list, not the open ports.
func TestExternalServicesFromTheXML(t *testing.T) {
	t.Parallel()
	got, err := readExternal(fixture(t, "external.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []ExternalService{
		{Port: 22, Name: "ssh", Product: "OpenSSH", Version: "7.4p1 Debian 10+deb9u7", CPE: "cpe:/a:openbsd:openssh:7.4p1", Extra: "protocol 2.0"},
		{Port: 443, Name: "ssl/http", Product: "nginx", CPE: "cpe:/a:igor_sysoev:nginx"}, // tunnel="ssl" (D-522)
		{Port: 8443, Name: "ssl/http", Product: "Apache httpd", Version: "2.4.49", CPE: "cpe:/a:apache:http_server:2.4.49", Extra: "(Unix)"},
		{Port: 10443, Name: "tcpwrapped"},
	}
	if got.Ports != 98 || !slices.Equal(got.Services, want) {
		t.Fatalf("got %d ports %+v", got.Ports, got.Services)
	}
}

// D-522 (N1, N5): an HTTPS page on 4443 (name="http" tunnel="ssl") reaches exposure as "ssl/http", so its templates speak TLS; an
// address with 60 of the 98 ports open (a router or SYN proxy answering for all of them) is ErrAnswersEverywhere, never 60 services.
func TestExternalTLSTunnelAndAnswersEverywhere(t *testing.T) {
	t.Parallel()
	base := string(fixture(t, "external.xml"))
	ports := base[strings.Index(base, "<port ") : strings.LastIndex(base, "</port>")+len("</port>")]
	tls := `<port protocol="tcp" portid="4443"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="http" product="lighttpd" tunnel="ssl" method="probed" conf="10"/></port>`
	got, err := readExternal([]byte(strings.Replace(base, ports, tls, 1)))
	if err != nil || len(got.Services) != 1 || got.Services[0] != (ExternalService{Port: 4443, Name: "ssl/http", Product: "lighttpd"}) {
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

// The output is untrusted (INV-7, D-514): an answer outside what was asked fails the whole run, never a part of it; a DOCTYPE with
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

// #723 review L4: the module turned off (Stop) while a run waited for the nmap slot ends it once it has the slot, before it asks or
// sends anything: an external run and a picked identification alike.
func TestStopDuringTheSlotWaitIsHonoured(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := &Service{log: slog.New(slog.DiscardHandler), clock: time.Now}
		s.runMu.Lock() // another nmap run holds the slot
		ext, ident := make(chan error, 1), make(chan error, 1)
		go func() { _, err := s.ScanExternal(t.Context(), ownIP, nmapargv.External, yesFence{}); ext <- err }()
		go func() { _, err := s.IdentifyDevice(t.Context(), "a-web"); ident <- err }()
		synctest.Wait() // both wait for the slot
		s.Stop()
		s.runMu.Unlock()
		for name, ch := range map[string]chan error{"external": ext, "identify": ident} {
			if err := <-ch; !errors.Is(err, ErrStopped) {
				t.Errorf("%s: err = %v, want ErrStopped", name, err)
			}
		}
	})
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
		// D-526: a full run needs its hour: what was enough for External is not enough for it
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
