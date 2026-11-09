package sensorpassive

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

// l3 strips the Ethernet header of a generated frame.
func l3(frame []byte) []byte { return frame[14:] }

// l4udp returns the UDP payload of a generated UDPFrame.
func l4udp(t *testing.T, frame []byte) []byte {
	t.Helper()
	f, err := parseEthernet(frame)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := parseIPv4(f.payload)
	if err != nil {
		t.Fatal(err)
	}
	u, err := parseUDP(ip.payload)
	if err != nil {
		t.Fatal(err)
	}
	return u.payload
}

func TestParseEthernet(t *testing.T) {
	t.Parallel()
	pay := []byte{0x45, 0, 0, 20}
	tests := []struct {
		name    string
		in      []byte
		wantErr error
		want    uint16
	}{
		{"plain", pktgen.Eth(pktgen.Bcast, pktgen.PC, 0x0800, pay), nil, 0x0800},
		{"vlan", pktgen.EthVLAN(pktgen.Bcast, pktgen.PC, 7, 0x0806, pay), nil, 0x0806},
		{"short", []byte{1, 2, 3}, errMalformed, 0},
		{"cut vlan tag", append(pktgen.Eth(pktgen.Bcast, pktgen.PC, 0x8100, nil), 0), errMalformed, 0},
		{"802.3 length frame", pktgen.Eth(pktgen.Bcast, pktgen.PC, 100, pay), errIgnore, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, err := parseEthernet(tc.in)
			if !errors.Is(err, tc.wantErr) || (err == nil && f.ethType != tc.want) {
				t.Fatalf("got ethType %#x err %v, want %#x err %v", f.ethType, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestParseARP(t *testing.T) {
	t.Parallel()
	req := l3(pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP))
	a, err := parseARP(req)
	if err != nil || a.op != 1 || a.senderMAC != mac(pktgen.PC) || a.senderIP != pktgen.PCIP || a.targetIP != pktgen.RouterIP {
		t.Fatalf("request: %+v %v", a, err)
	}
	probe := l3(pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, netip.MustParseAddr("0.0.0.0"), pktgen.MAC{}, pktgen.RouterIP))
	if a, err := parseARP(probe); err != nil || a.senderIP.IsValid() {
		t.Fatalf("probe must have no sender IP: %+v %v", a, err)
	}
	for name, in := range map[string][]byte{
		"short":      req[:27],
		"op 9":       append(append([]byte{}, req[:6]...), append([]byte{0, 9}, req[8:]...)...),
		"not ipv4":   append([]byte{0, 1, 0x86, 0xdd}, req[4:]...),
		"hardware 7": append([]byte{0, 1, 8, 0, 7, 4}, req[6:]...),
	} {
		if _, err := parseARP(in); !errors.Is(err, errMalformed) {
			t.Errorf("%s: want malformed, got %v", name, err)
		}
	}
}

func TestParseDHCP(t *testing.T) {
	t.Parallel()
	msg := pktgen.DHCP(1, pktgen.PC, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{
		Type: 3, Hostname: "PC-ACCOUNTING-01", VendorClass: "MSFT 5.0", ClientID: []byte{1, 1, 2, 3, 4, 5, 6}, Requested: pktgen.PCIP})
	m, err := parseDHCP(msg)
	if err != nil {
		t.Fatal(err)
	}
	if m.op != 1 || m.msgType != 3 || m.clientMAC != mac(pktgen.PC) || m.hostname != "PC-ACCOUNTING-01" || m.vendorClass != "MSFT 5.0" ||
		len(m.clientID) != 7 || m.requestedIP != pktgen.PCIP {
		t.Fatalf("parsed %+v", m)
	}
	ack, _ := parseDHCP(pktgen.DHCP(2, pktgen.PC, netip.Addr{}, pktgen.PCIP, pktgen.DHCPOpts{Type: 5}))
	if ack.yourIP != pktgen.PCIP || ack.msgType != 5 {
		t.Fatalf("ack %+v", ack)
	}
	if m, err := parseDHCP(pktgen.DHCP(1, pktgen.PC, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Hostname: "bad name!"})); err != nil || m.hostname != "" {
		t.Fatalf("a hostname with odd characters is dropped, not fatal: %+v %v", m, err)
	}
	if m, _ := parseDHCP(pktgen.DHCP(1, pktgen.PC, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Hostname: "n\x00ul"})); m.hostname != "" {
		t.Fatalf("embedded NUL accepted: %q", m.hostname)
	}
	bad := map[string][]byte{
		"short":             msg[:100],
		"bad op":            append([]byte{9}, msg[1:]...),
		"not ethernet":      append([]byte{1, 6, 6}, msg[3:]...),
		"no cookie":         append(append([]byte{}, msg[:236]...), 0, 0, 0, 0, 255),
		"option too long":   append(msg[:len(msg)-1:len(msg)-1], 12, 200, 'x'),
		"option header cut": append(msg[:len(msg)-1:len(msg)-1], 12),
		"too big":           make([]byte, maxDHCP+1),
	}
	for name, in := range bad {
		if _, err := parseDHCP(in); !errors.Is(err, errMalformed) {
			t.Errorf("%s: want malformed, got %v", name, err)
		}
	}
}

func TestParseDNS(t *testing.T) {
	t.Parallel()
	q := pktgen.DNSMessage(1, false, [][2]any{{"Example.ORG", uint16(1)}}, nil)
	m, err := parseDNS(q)
	if err != nil || m.response || len(m.questions) != 1 || m.questions[0].name != "Example.ORG" || m.questions[0].qtype != 1 {
		t.Fatalf("query: %+v %v", m, err)
	}
	resp := pktgen.DNSMessage(2, true, nil, []pktgen.DNSRecord{
		pktgen.RR("host.local", dnsTypeA, pktgen.A(pktgen.PrinterIP)),
		pktgen.RR("_ipp._tcp.local", dnsTypePTR, pktgen.NameRData("Inst._ipp._tcp.local")),
		pktgen.RR("Inst._ipp._tcp.local", dnsTypeTXT, pktgen.TXT("md=Model X", "junk")),
	})
	m, err = parseDNS(resp)
	if err != nil || !m.response || len(m.records) != 3 {
		t.Fatalf("response: %+v %v", m, err)
	}
	if n, ok := m.rdataName(m.records[1]); !ok || n != "Inst._ipp._tcp.local" {
		t.Fatalf("PTR target %q %v", n, ok)
	}
	if v := txtPairs(m.records[2].data)["md"]; v != "Model X" {
		t.Fatalf("TXT md = %q", v)
	}
	// a compression pointer back to an earlier name works
	ptr := append(append([]byte{}, q[:12]...), 0, 0, 0, 0) // placeholder replaced below
	_ = ptr
	comp := append([]byte{0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0}, pktgen.NameRData("a.example")...)
	comp = append(comp, 0xc0, 12) // the name pointer would be in a record; build a record by hand
	comp = append(comp[:12+len(pktgen.NameRData("a.example"))], 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0)
	if m, err := parseDNS(comp); err != nil || len(m.records) != 1 || m.records[0].name != "a.example" {
		t.Fatalf("compressed: %+v %v", m, err)
	}
	loop := []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0}
	toomany := []byte{0, 0, 0x84, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}
	longName := append([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, strings.Repeat("\x3fabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij", 5)...)
	for name, in := range map[string][]byte{
		"short": {1, 2, 3}, "pointer loop": loop, "too many records": toomany, "name too long": append(longName, 0, 0, 1, 0, 1),
		"label cut": {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 9, 'a'}, "reserved label type": {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x80, 0},
		"rdata cut": append(append([]byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0}, 0, 1, 0, 1, 0, 0, 0, 1), 0, 9, 1),
	} {
		if _, err := parseDNS(in); !errors.Is(err, errMalformed) {
			t.Errorf("%s: want malformed, got %v", name, err)
		}
	}
}

func TestParseSSDP(t *testing.T) {
	t.Parallel()
	m, err := parseSSDP(pktgen.SSDPNotify("Linux/5.4 UPnP/1.0 MiniUPnPd/2.2", "urn:x:InternetGatewayDevice:1", "uuid:1", "http://192.168.10.1:5000/d.xml"))
	if err != nil || m.server != "Linux/5.4 UPnP/1.0 MiniUPnPd/2.2" || m.usn != "uuid:1" || m.location != "http://192.168.10.1:5000/d.xml" || !strings.Contains(m.nt, "InternetGatewayDevice") {
		t.Fatalf("notify: %+v %v", m, err)
	}
	if m, err := parseSSDP([]byte("HTTP/1.1 200 OK\r\nsErVeR: Foo/1\r\nST: upnp:rootdevice\r\n\r\n")); err != nil || m.server != "Foo/1" {
		t.Fatalf("response: %+v %v", m, err)
	}
	if _, err := parseSSDP([]byte("M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n")); !errors.Is(err, errIgnore) {
		t.Fatalf("a search request is ignored, got %v", err)
	}
	for name, in := range map[string][]byte{
		"not ssdp": []byte("GET / HTTP/1.1\r\n\r\n"), "header without colon": []byte("NOTIFY * HTTP/1.1\r\nnonsense\r\n\r\n"),
		"too long":       append([]byte("NOTIFY * HTTP/1.1\r\n"), make([]byte, maxSSDP)...),
		"too many lines": []byte("NOTIFY * HTTP/1.1\r\n" + strings.Repeat("A: b\r\n", 50) + "\r\n"),
	} {
		if _, err := parseSSDP(in); !errors.Is(err, errMalformed) {
			t.Errorf("%s: want malformed, got %v", name, err)
		}
	}
}

func TestParseLLDP(t *testing.T) {
	t.Parallel()
	f, err := parseLLDP(l3(pktgen.LLDP(pktgen.Switch, pktgen.LLDPInfo{Chassis: pktgen.Switch, Port: "Gi1", SysName: "SW1", SysDesc: "Example OS", Caps: lldpCapBridge | lldpCapRouter})))
	if err != nil || !f.hasMAC || f.chassisMAC != mac(pktgen.Switch) || f.sysName != "SW1" || f.sysDesc != "Example OS" || f.caps != lldpCapBridge|lldpCapRouter {
		t.Fatalf("parsed %+v %v", f, err)
	}
	good := l3(pktgen.LLDP(pktgen.Switch, pktgen.LLDPInfo{Chassis: pktgen.Switch, Port: "Gi1", SysName: "SW1"}))
	for name, in := range map[string][]byte{
		"empty":          {},
		"cut in a TLV":   {0x02, 0x07, 4, 0xaa},
		"no end TLV":     good[:len(good)-2],
		"wrong order":    {0x04, 0x01, 'x', 0, 0},
		"ends too early": {0x02, 0x07, 4, 1, 2, 3, 4, 5, 6, 0, 0},
	} {
		if _, err := parseLLDP(in); !errors.Is(err, errMalformed) {
			t.Errorf("%s: want malformed, got %v", name, err)
		}
	}
	var many []byte
	many = append(many, good[:len(good)-2]...)
	for range 70 {
		many = append(many, 0x0c, 0x00)
	}
	if _, err := parseLLDP(append(many, 0, 0)); !errors.Is(err, errMalformed) {
		t.Errorf("too many TLVs: %v", err)
	}
}

func TestParseClientHelloSNI(t *testing.T) {
	t.Parallel()
	if n, err := parseClientHelloSNI(pktgen.ClientHello("Portal.Example.ORG")); err != nil || n != "portal.example.org" {
		t.Fatalf("got %q %v", n, err)
	}
	for name, in := range map[string][]byte{
		"no SNI extension": pktgen.ClientHello(""), "application data": {0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5},
		"plain text": []byte("GET / HTTP/1.1"), "server hello": {0x16, 3, 3, 0, 4, 2, 0, 0, 0}, "empty": nil,
	} {
		if n, err := parseClientHelloSNI(in); !errors.Is(err, errIgnore) {
			t.Errorf("%s: want ignore, got %q %v", name, n, err)
		}
	}
	hello := pktgen.ClientHello("portal.example.org")
	for name, in := range map[string][]byte{
		"handshake longer than record": {0x16, 3, 1, 0, 3, 1, 0xff, 0xff, 0xff},
		"record length zero":           {0x16, 3, 1, 0, 0, 1, 0, 0, 0},
		"SNI is not a host name":       pktgen.ClientHello("bad name!"),
		"SNI too long":                 pktgen.ClientHello(strings.Repeat("a", 64) + ".org"),
	} {
		if _, err := parseClientHelloSNI(in); !errors.Is(err, errMalformed) {
			t.Errorf("%s: want malformed, got %v", name, err)
		}
	}
	// a hello cut anywhere never panics and never yields a name that was not there
	for i := range len(hello) {
		if n, err := parseClientHelloSNI(hello[:i]); err == nil && n != "" && i < len(hello)-8 {
			t.Errorf("cut at %d: found %q in a truncated hello", i, n)
		}
	}
}

func TestParseHTTPHost(t *testing.T) {
	t.Parallel()
	req := func(h string) []byte { return pktgen.HTTPRequest("GET", "/", h, []string{"Cookie: a=b"}, "") }
	for in, want := range map[string]string{"Example.ORG": "example.org", "legacy.example.org:8080": "legacy.example.org", "192.168.1.9:80": "192.168.1.9", "example.org.": "example.org"} {
		if got, err := parseHTTPHost(req(in)); err != nil || got != want {
			t.Errorf("Host %q: got %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := parseHTTPHost([]byte("GET / HTTP/1.1\r\nCookie: x=y\r\n\r\n")); !errors.Is(err, errIgnore) {
		t.Errorf("no Host: %v", err)
	}
	if _, err := parseHTTPHost([]byte("GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n")); !errors.Is(err, errIgnore) {
		t.Errorf("IPv6 literal: %v", err)
	}
	for name, in := range map[string][]byte{"not a request": []byte("HTTP/1.1 200 OK\r\n"), "body continuation": []byte("password=x&y=z"), "request line cut": []byte("GET /abc")} {
		if _, err := parseHTTPHost(in); !errors.Is(err, errIgnore) {
			t.Errorf("%s: want ignore, got %v", name, err)
		}
	}
	for name, in := range map[string][]byte{
		"no version": []byte("GET /\x00\x01 garbage\r\nHost: a\r\n\r\n"), "odd host": req("bad host!"),
	} {
		if _, err := parseHTTPHost(in); !errors.Is(err, errMalformed) {
			t.Errorf("%s: want malformed, got %v", name, err)
		}
	}
}

func TestParseIPv4AndTransports(t *testing.T) {
	t.Parallel()
	frame := pktgen.UDPFrame(pktgen.Bcast, pktgen.PC, pktgen.PCIP, pktgen.DNSIP, 1234, 53, []byte("hi"))
	if got := l4udp(t, frame); string(got) != "hi" {
		t.Fatalf("payload %q", got)
	}
	tcpFrame := pktgen.TCPFrame(pktgen.Bcast, pktgen.PC, pktgen.PCIP, pktgen.WebIP, 5, 80, []byte("data"))
	ip, err := parseIPv4(l3(tcpFrame))
	if err != nil {
		t.Fatal(err)
	}
	seg, err := parseTCP(ip.payload)
	if err != nil || seg.dport != 80 || string(seg.payload) != "data" {
		t.Fatalf("tcp %+v %v", seg, err)
	}
	for name, f := range map[string]func() error{
		"ipv4 short":      func() error { _, e := parseIPv4([]byte{0x45}); return e },
		"ipv4 version":    func() error { _, e := parseIPv4(append([]byte{0x65}, make([]byte, 30)...)); return e },
		"ipv4 ihl":        func() error { _, e := parseIPv4(append([]byte{0x41}, make([]byte, 30)...)); return e },
		"udp short":       func() error { _, e := parseUDP([]byte{1, 2}); return e },
		"udp length":      func() error { _, e := parseUDP([]byte{0, 1, 0, 2, 0, 3, 0, 0}); return e },
		"tcp short":       func() error { _, e := parseTCP([]byte{1}); return e },
		"tcp data offset": func() error { b := make([]byte, 20); b[12] = 0xf0; _, e := parseTCP(b); return e },
	} {
		if err := f(); !errors.Is(err, errMalformed) {
			t.Errorf("%s: want malformed, got %v", name, err)
		}
	}
	// a non-first fragment has no transport header
	b := append([]byte{}, l3(frame)...)
	b[6], b[7] = 0x00, 0x08
	if ip, err := parseIPv4(b); err != nil || ip.firstFrg {
		t.Fatalf("fragment: %+v %v", ip, err)
	}
}

func TestCleanTextAndHostname(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"a", "a-b_c.d", "PC-01", strings.Repeat("a", 63)} {
		if !hostnameOK(s) {
			t.Errorf("%q should be a host name", s)
		}
	}
	for _, s := range []string{"", ".", "a..b", ".a", "a.", "a b", "a/b", "é", strings.Repeat("a", 64), strings.Repeat("a.", 130)} {
		if hostnameOK(s) {
			t.Errorf("%q should not be a host name", s)
		}
	}
	if v, ok := cleanText("  héllo  ", 200); !ok || v != "héllo" {
		t.Errorf("cleanText: %q %v", v, ok)
	}
	if _, ok := cleanText("a\x00b", 200); ok {
		t.Error("control characters accepted")
	}
	if v, _ := cleanText("hé", 2); v != "h" {
		t.Errorf("cut inside a rune: %q", v)
	}
	if got := truncate("héllo", 2); got != "h" {
		t.Errorf("truncate inside a rune: %q", got)
	}
}
