package sensorpassive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

// One fuzz target per parser (INV-4). Each checks the two promises of a parser: it never panics, and what it
// returns respects its bounds. Run each for at least 30 s: `go test -run '^$' -fuzz FuzzParseARP -fuzztime 30s .`
// (CI runs them longer, see CONTRACT INV-4).

func seeds(f *testing.F, extra ...[]byte) {
	for _, s := range extra {
		f.Add(s)
	}
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Add(bytes.Repeat([]byte{0}, 300))
}

func FuzzParseARP(f *testing.F) {
	seeds(f, l3(pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := parseARP(b)
		if err == nil && a.op != 1 && a.op != 2 {
			t.Fatalf("operation %d accepted", a.op)
		}
	})
}

func FuzzParseDHCP(f *testing.F) {
	seeds(f,
		pktgen.DHCP(1, pktgen.PC, netip.Addr{}, netip.Addr{}, pktgen.DHCPOpts{Type: 3, Hostname: "PC-01", VendorClass: "MSFT 5.0", ClientID: []byte{1, 2, 3, 4, 5, 6, 7}, Requested: pktgen.PCIP}),
		pktgen.DHCP(2, pktgen.PC, netip.Addr{}, pktgen.PCIP, pktgen.DHCPOpts{Type: 5}))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parseDHCP(b)
		if err != nil {
			return
		}
		if m.hostname != "" && !hostnameOK(m.hostname) {
			t.Fatalf("hostname %q is not a host name", m.hostname)
		}
		if len(m.vendorClass) > 200 || !printable(m.vendorClass) || len(m.clientID) > 64 {
			t.Fatalf("out of bounds: %+v", m)
		}
	})
}

func FuzzParseDNS(f *testing.F) {
	seeds(f,
		pktgen.DNSMessage(1, false, [][2]any{{"example.org", uint16(1)}}, nil),
		pktgen.DNSMessage(2, true, nil, []pktgen.DNSRecord{
			pktgen.RR("h.local", 1, pktgen.A(pktgen.PrinterIP)), pktgen.RR("_ipp._tcp.local", 12, pktgen.NameRData("I._ipp._tcp.local")), pktgen.RR("I._ipp._tcp.local", 16, pktgen.TXT("md=X"))}),
		[]byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := parseDNS(b)
		if err != nil {
			return
		}
		if len(m.questions) > 16 || len(m.records) > maxDNSRecords {
			t.Fatalf("too many entries: %d %d", len(m.questions), len(m.records))
		}
		for _, q := range m.questions {
			if len(q.name) > 253 {
				t.Fatalf("name of %d bytes", len(q.name))
			}
		}
		for _, r := range m.records {
			if len(r.name) > 253 || r.off+len(r.data) > len(b) {
				t.Fatalf("record out of bounds: %+v", r)
			}
			if r.rtype == dnsTypePTR {
				_, _ = m.rdataName(r)
			}
			if r.rtype == dnsTypeTXT {
				_ = txtPairs(r.data)
			}
		}
	})
}

func FuzzParseSSDP(f *testing.F) {
	seeds(f, pktgen.SSDPNotify("Linux/5.4 UPnP/1.0 X/1", "urn:x:InternetGatewayDevice:1", "uuid:1", "http://192.168.10.1/d.xml"),
		[]byte("HTTP/1.1 200 OK\r\nSERVER: a\r\n\r\n"), []byte("M-SEARCH * HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := parseSSDP(b); err == nil && len(b) > maxSSDP {
			t.Fatal("oversize message accepted")
		}
	})
}

func FuzzParseLLDP(f *testing.F) {
	seeds(f, l3(pktgen.LLDP(pktgen.Switch, pktgen.LLDPInfo{Chassis: pktgen.Switch, Port: "Gi1", SysName: "SW1", SysDesc: "OS", Caps: 20})))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := parseLLDP(b)
		if err == nil && (len(l.sysName) > 255 || len(l.sysDesc) > 255 || !printable(l.sysName) || !printable(l.sysDesc)) {
			t.Fatalf("out of bounds: %+v", l)
		}
	})
}

func FuzzParseClientHelloSNI(f *testing.F) {
	h := pktgen.ClientHello("portal.example.org")
	seeds(f, h, h[:len(h)/2], pktgen.ClientHello(""), []byte{0x16, 3, 1, 0, 3, 1, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if n, err := parseClientHelloSNI(b); err == nil && !hostnameOK(n) {
			t.Fatalf("SNI %q is not a host name", n)
		}
	})
}

func FuzzParseHTTPHost(f *testing.F) {
	seeds(f, pktgen.HTTPRequest("GET", "/", "example.org:8080", []string{"Cookie: a=b"}, ""), []byte("GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n"), []byte("POST /x HTTP/1.0\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := parseHTTPHost(b)
		if err != nil {
			return
		}
		if ip, e := netip.ParseAddr(h); e != nil || !ip.Is4() {
			if !hostnameOK(h) {
				t.Fatalf("Host %q is neither an IPv4 address nor a host name", h)
			}
		}
	})
}

// FuzzFileSource reads a recording of any shape: it must fail or end, never panic or allocate wildly.
func FuzzFileSource(f *testing.F) {
	seeds(f, pktgen.WritePCAP(pktgen.LANDiscovery()), pktgen.WritePCAPNG(pktgen.SpanMetadata()), pktgen.WritePCAP(pktgen.Malformed()))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := NewFileSource(bytes.NewReader(b))
		if err != nil {
			return
		}
		for range 10000 {
			p, err := s.Next(context.Background())
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil && !errors.Is(err, ErrDropped) {
				return
			}
			if len(p.Data) > maxRecord {
				t.Fatalf("a packet of %d bytes", len(p.Data))
			}
		}
	})
}

// FuzzEngineHandle pushes arbitrary frames through the whole pipeline with SPAN and every extraction on.
// Everything it keeps must be inside the allowed fields (INV-3): host names, valid MACs, bounded text.
func FuzzEngineHandle(f *testing.F) {
	for _, fr := range [][]pktgen.Frame{pktgen.LANDiscovery(), pktgen.SpanMetadata(), pktgen.Malformed()} {
		for _, p := range fr {
			f.Add(p.Data)
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		cfg := spanCfg(Filter{"port", "9"})
		cfg.Clock = func() time.Time { return pktgen.T0 }
		e, err := newEngine(cfg)
		if err != nil {
			t.Fatal(err)
		}
		e.Handle(Packet{At: pktgen.T0, Data: b})
		obs, meta := e.Drain(pktgen.T0, true)
		for _, o := range obs {
			if _, ok := parseMAC(o.AssetHint.MAC); !ok || len(o.Value) > 253 || !printable(o.Value) || o.Confidence <= 0 || o.Confidence > 1 {
				t.Fatalf("bad observation %+v", o)
			}
		}
		for _, m := range meta {
			if m.Name != "" && !hostnameOK(m.Name) {
				if ip, err := netip.ParseAddr(m.Name); err != nil || !ip.Is4() {
					t.Fatalf("bad metadata name %+v", m)
				}
			}
		}
	})
}
