package sensoractive

import (
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
	"net/netip"
	"os"
	"strings"
	"testing"
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
		"empty":                "",
		"not xml":              "hello",
		"wrong root":           `<html></html>`,
		"cut off":              `<nmaprun><host><status state="up"/>`,
		"cut off in a tag":     `<nmaprun><host><status state="up`,
		"mismatched tags":      `<nmaprun><host></nmaprun></host>`,
		"entity definition":    `<!DOCTYPE nmaprun [<!ENTITY a "bbbbbbbbbbbbbbbbbb">]><nmaprun>&a;</nmaprun>`,
		"other doctype":        `<!DOCTYPE foo SYSTEM "http://example.invalid/x.dtd"><nmaprun></nmaprun>`,
		"unknown entity":       `<nmaprun>&xxe;</nmaprun>`,
		"other charset":        `<?xml version="1.0" encoding="ISO-8859-1"?><nmaprun></nmaprun>`,
		"other processing":     `<?php echo 1 ?><nmaprun></nmaprun>`,
		"content after end":    `<nmaprun></nmaprun><nmaprun></nmaprun>`,
		"too deep":             `<nmaprun>` + deep + `</nmaprun>`,
		"too many attributes":  manyAttrs,
		"too many hosts":       manyHosts,
		"too many ports":       manyPorts,
		"attribute too long":   `<nmaprun x="` + strings.Repeat("a", 5000) + `"></nmaprun>`,
		"output over the cap":  `<nmaprun>` + strings.Repeat(" ", maxOutput) + `</nmaprun>`,
		"bad UTF-8 in a value": "<nmaprun x=\"\xff\xfe\"></nmaprun>",
	}
	for name, doc := range bad {
		if hosts, err := parseNmapXML([]byte(doc)); err == nil {
			t.Errorf("%s: accepted, %d hosts", name, len(hosts))
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
		"phone": "iot", "VoIP phone": "iot", "broadband router": "router", "print server": "printer"} { // D-501: no phone kind yet, phones are iot as in the catalog
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
