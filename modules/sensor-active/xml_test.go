package sensoractive

import (
	"bytes"
	"encoding/xml"
	"maps"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name) //nolint:gosec // fixed fixture names
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseDeviceFixture(t *testing.T) {
	t.Parallel()
	hosts, err := parseNmapXML(fixture(t, "device.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("%d hosts, want 1", len(hosts))
	}
	h := hosts[0]
	if h.addr != netip.MustParseAddr("192.168.10.20") || h.mac != "AA:BB:CC:00:00:20" || h.vendor != "Acme Networks" || h.hostname != "web01.lan" {
		t.Fatalf("host = %+v", h)
	}
	if len(h.ports) != 3 { // the closed telnet port is not kept
		t.Fatalf("%d ports, want 3 open", len(h.ports))
	}
	if h.ports[0].product != "OpenSSH" || len(h.ports[0].cpes) != 2 || h.ports[0].conf != 10 {
		t.Fatalf("port 22 = %+v", h.ports[0])
	}
	if len(h.matches) != 2 || h.matches[0].accuracy != 96 || h.matches[0].classes[0].cpes[0] != "cpe:/o:linux:linux_kernel:5" {
		t.Fatalf("os = %+v", h.matches)
	}
}

func TestParseSweepFixtureKeepsOnlyUpHosts(t *testing.T) {
	t.Parallel()
	hosts, err := parseNmapXML(fixture(t, "sweep.xml"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, h := range hosts {
		got = append(got, h.addr.String())
	}
	if strings.Join(got, ",") != "192.168.10.2,192.168.10.5,203.0.113.9" { // .6 is down
		t.Fatalf("hosts = %v", got)
	}
	// What nmap reports from outside the list of targets is dropped before anything is recorded (INV-1).
	kept := onlyTargets(hosts, addrs(t, "192.168.10.2", "192.168.10.5", "192.168.10.6"))
	if len(kept) != 2 {
		t.Fatalf("onlyTargets kept %d", len(kept))
	}
}

func TestParseRefusesBadOutput(t *testing.T) {
	t.Parallel()
	deep := strings.Repeat("<a>", maxXMLDepth+1) + strings.Repeat("</a>", maxXMLDepth+1)
	manyAttrs := `<nmaprun ` + strings.Repeat(`a="1" `, 1) + func() string {
		var b strings.Builder
		for i := range maxXMLAttrs + 1 {
			b.WriteString(" x" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `="1"`)
		}
		return b.String()
	}() + `></nmaprun>`
	manyHosts := `<nmaprun>` + strings.Repeat(`<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>`, maxXMLHosts+1) + `</nmaprun>`
	manyPorts := `<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports>` + strings.Repeat(`<port protocol="tcp" portid="1"><state state="open"/></port>`, maxPortsPerHost+1) + `</ports></host></nmaprun>`
	bad := map[string]string{
		"empty":               "",
		"not xml":             "hello",
		"wrong root":          `<html></html>`,
		"cut off":             `<nmaprun><host><status state="up"/>`,
		"cut off in a tag":    `<nmaprun><host><status state="up`,
		"mismatched tags":     `<nmaprun><host></nmaprun></host>`,
		"entity definition":   `<!DOCTYPE nmaprun [<!ENTITY a "bbbbbbbbbbbbbbbbbb">]><nmaprun>&a;</nmaprun>`,
		"other doctype":       `<!DOCTYPE foo SYSTEM "http://example.invalid/x.dtd"><nmaprun></nmaprun>`,
		"unknown entity":      `<nmaprun>&xxe;</nmaprun>`,
		"other charset":       `<?xml version="1.0" encoding="ISO-8859-1"?><nmaprun></nmaprun>`,
		"other processing":    `<?php echo 1 ?><nmaprun></nmaprun>`,
		"content after end":   `<nmaprun></nmaprun><nmaprun></nmaprun>`,
		"too deep":            `<nmaprun>` + deep + `</nmaprun>`,
		"too many attributes": manyAttrs,
		"too many hosts":      manyHosts,
		"too many ports":      manyPorts,
		"attribute too long":  `<nmaprun x="` + strings.Repeat("a", 5000) + `"></nmaprun>`,
		// N42-3: only the attributes the parser never reads are exempt; a long one it reads still refuses the run.
		"read attribute too long": `<nmaprun args="nmap"><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="` + strings.Repeat("p", 5000) + `"/></port></ports></host></nmaprun>`,
		"args of another element": `<nmaprun><host args="` + strings.Repeat("a", 5000) + `"></host></nmaprun>`,
		"output over the cap":     `<nmaprun>` + strings.Repeat(" ", maxOutput) + `</nmaprun>`,
		"bad UTF-8 in a value":    "<nmaprun x=\"\xff\xfe\"></nmaprun>",
	}
	for name, doc := range bad {
		if hosts, err := parseNmapXML([]byte(doc)); err == nil {
			t.Errorf("%s: accepted, %d hosts", name, len(hosts))
		}
	}
}

// N42-3 (D-590): nmap echoes its whole argv in <nmaprun args>, and the --script list of the full shapes is longer than the 4 KB cap of
// an attribute; the run of the deep scan must still be read (it was refused as "attribute too long", so nothing was identified).
func TestParseAcceptsTheLongArgvOfTheFullShapes(t *testing.T) {
	t.Parallel()
	boxIP := netip.MustParseAddr("8.8.8.8") // stands for the box's own verified public IP
	ports := make([]string, 1500)
	for i := range ports {
		ports[i] = strconv.Itoa(i + 1)
	}
	for _, kind := range []nmapargv.Kind{nmapargv.ExternalFull, nmapargv.ExternalDisruptive} {
		argv, err := nmapargv.Build(kind, nmapargv.FullRate, []netip.Addr{boxIP})
		if err != nil {
			t.Fatal(err)
		}
		var args bytes.Buffer
		if err := xml.EscapeText(&args, []byte("/usr/bin/nmap "+strings.Join(argv, " "))); err != nil {
			t.Fatal(err)
		}
		if args.Len() <= 4096 {
			t.Fatalf("%s: the argv is %d bytes; the test needs one over the 4 KB cap", kind.Name(), args.Len())
		}
		doc := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" args="` + args.String() + `" start="1" version="7.95" xmloutputversion="1.05">` +
			`<scaninfo type="syn" protocol="tcp" numservices="1500" services="` + strings.Join(ports, ",") + `"/>` +
			`<host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/><ports>` +
			`<port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" version="1.24.0" tunnel="ssl"/></port>` +
			`</ports></host></nmaprun>`
		hosts, err := parseNmapXML([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", kind.Name(), err)
		}
		if len(hosts) != 1 || hosts[0].addr != boxIP || len(hosts[0].ports) != 1 || hosts[0].ports[0].number != 443 || hosts[0].ports[0].product != "nginx" {
			t.Fatalf("%s: %+v", kind.Name(), hosts)
		}
	}
}

func TestParseKeepsOnlyCleanText(t *testing.T) {
	t.Parallel()
	doc := "<nmaprun><host><status state=\"up\"/><address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>" +
		"<address addr=\"not-a-mac\" addrtype=\"mac\" vendor=\"x\"/>" +
		"<hostnames><hostname name=\"bad&#10;name\"/><hostname name=\"good\"/></hostnames>" +
		"<ports><port protocol=\"tcp\" portid=\"99999\"><state state=\"open\"/><service name=\"s\" product=\"" + strings.Repeat("p", 300) + "\"><cpe>not a cpe</cpe><cpe>cpe:/a:v:p:1</cpe></service></port></ports>" +
		"</host></nmaprun>"
	hosts, err := parseNmapXML([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	h := hosts[0]
	if h.mac != "" || h.vendor != "" {
		t.Errorf("a bad MAC was kept: %q %q", h.mac, h.vendor)
	}
	if h.hostname != "good" {
		t.Errorf("hostname = %q, a name with a control character must be dropped", h.hostname)
	}
	p := h.ports[0]
	if p.product != "" || p.number != 65535 || len(p.cpes) != 1 || p.cpes[0] != "cpe:/a:v:p:1" {
		t.Errorf("port = %+v", p)
	}
}

func TestSoftwareAndObservations(t *testing.T) {
	t.Parallel()
	hosts, err := parseNmapXML(fixture(t, "device.xml"))
	if err != nil {
		t.Fatal(err)
	}
	sw := softwareOf(hosts[0])
	byProduct := map[string]string{}
	for _, s := range sw {
		if s.Confidence <= 0 || s.Confidence >= 1 {
			t.Errorf("%s confidence %v is not in (0,1)", s.Product, s.Confidence)
		}
		byProduct[s.Product] = s.Vendor + "|" + s.Version + "|" + s.CPE
	}
	for product, want := range map[string]string{
		"openssh":          "openbsd|8.9p1|cpe:/a:openbsd:openssh:8.9p1",
		"http server":      "apache|2.4.52|cpe:/a:apache:http_server:2.4.52", // underscore -> space: how the CISA list writes it
		"Squid http proxy": "Squid http proxy|5.7|",                          // no CPE: the product name stands for the vendor
		"linux kernel":     "linux||cpe:/o:linux:linux_kernel",               // the fingerprint's OS: a guess, without its generation (D-501)
	} {
		if byProduct[product] != want {
			t.Errorf("software %q = %q, want %q (all: %v)", product, byProduct[product], want, byProduct)
		}
	}
	obs := deviceObservations(hosts[0], nmapargv.Normal)
	got := map[string]float64{}
	for _, o := range obs {
		if o.Source != "nmap" || o.Confidence < 0 || o.Confidence >= 1 {
			t.Errorf("observation %+v", o)
		}
		got[string(o.Field)+"="+o.Value] = o.Confidence
	}
	if _, ok := got["os=Linux 5.4 - 5.15"]; !ok {
		t.Errorf("no os observation of the best match: %v", got)
	}
	if _, ok := got["hostname=web01.lan"]; !ok {
		t.Errorf("no hostname: %v", got)
	}
	if got["os=Linux 5.4 - 5.15"] <= 0.9 {
		t.Errorf("accuracy 96 scaled to %v", got["os=Linux 5.4 - 5.15"])
	}
}

func TestKindOf(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"router": "router", "WAP": "ap", "printer": "printer", "webcam": "camera", "storage-misc": "nas", "general purpose": "", "": "",
		"phone": "smartphone", "VoIP phone": "ip_phone", "VoIP adapter": "voip_adapter", "media device": "media_player", "power-device": "ups", "broadband router": "router", "print server": "printer"} { // D-511: phone types of their own, each acting as iot
		if got := kindOf(in); got != want {
			t.Errorf("kindOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// INV-7: a string is stored only as printable text. C0 and C1 controls, bidi overrides and isolates, zero-width
// characters, the byte order mark, the soft hyphen and the line separators are refused: a device can put them in
// a banner nmap copies into product, version or hostname, where they reorder or hide text in the UI and in a
// CSV export.
func TestTextRefusesInvisibleAndBidiControls(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"evil\u202egnp.exe", "a\u0085b", "zero\u200bwidth", "\u2066isolate", "bom\ufeff", "soft\u00adhyphen", "tag\U000e0041", "line\u2028break", "tab\there", "nul\x00", "del\x7f", "\xff\xfe"} {
		if got := text(s); got != "" {
			t.Errorf("text(%q) = %q, want refused", s, got)
		}
	}
	for _, s := range []string{"Apache httpd", "Cámara IP", "ルーター", "a b", "x"} {
		if got := text(s); got != s {
			t.Errorf("text(%q) = %q, want it kept", s, got)
		}
	}
}

// servicesOf keeps what the inventory accepts (D-350): tcp and udp only, a port 1..65535, at most maxServices; a name or version
// longer than its column is left out rather than refusing the device's whole list.
func TestServicesOfKeepsOnlyWhatTheInventoryAccepts(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 150)
	h := host{ports: []portInfo{
		{number: 22, proto: "tcp", name: "ssh", product: "OpenSSH", version: long, conf: 10},
		{number: 53, proto: "udp", name: long},
		{number: 3868, proto: "sctp", name: "diameter"},
		{number: 0, proto: "tcp", name: "zero"},
	}}
	got := servicesOf(h)
	if len(got) != 2 || got[0].Port != 22 || got[0].Version != "" || got[0].Product != "OpenSSH" || got[1].Port != 53 || got[1].Name != "" || got[1].Proto != "udp" {
		t.Fatalf("services = %+v", got)
	}
	if got[0].Confidence != serviceConf(10) || got[1].Confidence != serviceConf(0) {
		t.Fatalf("confidence = %v, %v", got[0].Confidence, got[1].Confidence)
	}
	many := host{}
	for i := 1; i <= maxServices+5; i++ {
		many.ports = append(many.ports, portInfo{number: i, proto: "tcp"})
	}
	if n := len(servicesOf(many)); n != maxServices {
		t.Fatalf("%d services, want the cap %d", n, maxServices)
	}
}

// D-522 (N1): nmap's XML keeps TLS in tunnel="ssl"; the inventory gets nmap's text form "ssl/http", which the vulnerability scan
// reads as https on any port (4443 here). A name without a tunnel, and a tunnel without a name, keep their meaning.
func TestServiceNameCarriesTheTLSTunnel(t *testing.T) {
	t.Parallel()
	xmlText := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.168.18.20" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="4443"><state state="open"/><service name="http" product="lighttpd" tunnel="ssl" method="probed" conf="10"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="nginx" method="probed" conf="10"/></port>
<port protocol="tcp" portid="9999"><state state="open"/><service tunnel="ssl" method="probed" conf="3"/></port>
</ports></host></nmaprun>`
	hosts, err := parseNmapXML([]byte(xmlText))
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]string{}
	for _, s := range servicesOf(hosts[0]) {
		got[s.Port] = s.Name
	}
	if want := map[int]string{4443: "ssl/http", 8080: "http", 9999: "ssl"}; !maps.Equal(got, want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
}

// D-511 (INV-15): what a port says about the device besides product and version (nmap's extra info and device type, the page
// title, the certificate subject) is kept as the service's detail, never as software; a title with a control character is dropped.
func TestServiceDetail(t *testing.T) {
	t.Parallel()
	xmlText := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.168.18.251" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Fortinet FortiGate firewall http config" extrainfo="FortiOS" devicetype="firewall" tunnel="ssl"/>
<script id="ssl-cert" output="Subject: commonName=FGT60FTK2109ABCD/organizationName=Fortinet/countryName=US&#xa;Issuer: commonName=support"/>
<script id="http-title" output="Login"><elem key="title">FortiGate  Login</elem></script></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/><script id="http-title" output="x"><elem key="title">bad&#x202e;title</elem></script></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports></host></nmaprun>`
	hosts, err := parseNmapXML([]byte(xmlText))
	if err != nil {
		t.Fatal(err)
	}
	svcs := servicesOf(hosts[0])
	want := map[int]string{
		443: "certificate: commonName=FGT60FTK2109ABCD/organizationName=Fortinet/countryName=US; title: FortiGate Login; device type: firewall; FortiOS",
		80:  "", 22: "",
	}
	for _, s := range svcs {
		if s.Detail != want[s.Port] {
			t.Errorf("port %d detail = %q, want %q", s.Port, s.Detail, want[s.Port])
		}
	}
	for _, sw := range softwareOf(hosts[0]) {
		if strings.Contains(sw.Display, "FGT60F") || strings.Contains(sw.Display, "Login") {
			t.Errorf("a detail became software: %+v", sw)
		}
	}
	long := portInfo{title: strings.Repeat("x", 300)}
	if n := len([]rune(detailOf(long))); n != maxSvcDetail {
		t.Errorf("detail of a long title has %d runes, want %d", n, maxSvcDetail)
	}
	// #714 review: a certificate subject or title longer than the inventory keeps is shortened, its commonName first, never dropped.
	longXML := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.168.18.252" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" extrainfo="` + strings.Repeat("e", 150) + `"/>
<script id="ssl-cert" output="Subject: countryName=US/stateOrProvinceName=` + strings.Repeat("California", 20) + `/organizationName=Fortinet/organizationalUnitName=` + strings.Repeat("FortiGate", 20) + `/commonName=FGT60FTK2109WXYZ/emailAddress=support@fortinet.com"/>
<script id="http-title" output="x"><elem key="title">` + strings.Repeat("Juniper Web Device Manager ", 20) + `</elem></script></port>
</ports></host></nmaprun>`
	lh, err := parseNmapXML([]byte(longXML))
	if err != nil {
		t.Fatal(err)
	}
	d := servicesOf(lh[0])[0].Detail
	// A certificate with many names prints more than 4 KB; that does not refuse the run (other attributes stay at 4 KB).
	sans := strings.Repeat("DNS:host.example.com, ", 400)
	bigXML := strings.Replace(longXML, "/emailAddress=support@fortinet.com", "/emailAddress=support@fortinet.com&#xa;Subject Alternative Name: "+sans, 1)
	if bh, err := parseNmapXML([]byte(bigXML)); err != nil || len(bh) != 1 || !strings.HasPrefix(servicesOf(bh[0])[0].Detail, "certificate: commonName=FGT60FTK2109WXYZ") {
		t.Errorf("ssl-cert output of %d bytes: %v", len(sans), err)
	}
	// An output over 64 KB is ignored alone: the port and the rest of the run stay (#714 round 2, L3).
	huge := strings.Replace(longXML, "/emailAddress=support@fortinet.com", "/emailAddress=support@fortinet.com&#xa;"+strings.Repeat("x", 70<<10), 1)
	if hh, err := parseNmapXML([]byte(huge)); err != nil || len(hh) != 1 || len(hh[0].ports) != 1 || strings.HasPrefix(servicesOf(hh[0])[0].Detail, "certificate:") || !strings.Contains(servicesOf(hh[0])[0].Detail, "title: Juniper") {
		t.Errorf("a 70 KB ssl-cert output: err %v, hosts %d", err, len(hh))
	}
	if _, err := parseNmapXML([]byte(strings.Replace(longXML, `extrainfo="`, `extrainfo="`+sans, 1))); err == nil {
		t.Error("a 9 KB extrainfo was accepted: only a script's output may pass 4 KB")
	}
	if !strings.HasPrefix(d, "certificate: commonName=FGT60FTK2109WXYZ/organizationName=Fortinet/") || !strings.Contains(d, "title: Juniper Web Device Manager") || len([]rune(d)) > maxSvcDetail {
		t.Errorf("long subject and title: detail = %q", d)
	}
}
