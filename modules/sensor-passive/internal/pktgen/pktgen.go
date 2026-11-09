// Package pktgen builds small hand-made packets and recordings for the tests of sensor-passive. Nothing here
// captures from a network or sends to one: it only produces bytes (agent-safety: fixtures replace the real
// network). The recordings under ../../testdata are generated from Fixtures and compared byte for byte by
// TestFixturesAreCurrent; regenerate them with `go test ./modules/sensor-passive/internal/pktgen -run TestWriteFixtures -update`.
package pktgen

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"time"
)

// MAC is a hardware address.
type MAC [6]byte

// The cast of the fixtures. Box is the Vedette box itself; the others are devices on the LAN.
var (
	Box     = MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	PC      = MAC{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x11}
	Printer = MAC{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x12}
	Router  = MAC{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x13}
	Switch  = MAC{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x14}
	Phone   = MAC{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x15}
	Laptop  = MAC{0x3c, 0x07, 0x54, 0x00, 0x00, 0x31} // a registered OUI (Apple, Inc.): the others are locally administered
	Bcast   = MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	Mcast4  = MAC{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb} // mDNS
	LLDPDst = MAC{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
)

// Addresses of the fixtures.
var (
	BoxIP     = netip.MustParseAddr("192.168.10.2")
	PCIP      = netip.MustParseAddr("192.168.10.21")
	PrinterIP = netip.MustParseAddr("192.168.10.22")
	RouterIP  = netip.MustParseAddr("192.168.10.1")
	PhoneIP   = netip.MustParseAddr("192.168.10.23")
	LaptopIP  = netip.MustParseAddr("192.168.10.24")
	DNSIP     = netip.MustParseAddr("192.168.10.53")
	WebIP     = netip.MustParseAddr("203.0.113.7")
)

func (m MAC) String() string {
	const h = "0123456789abcdef"
	b := make([]byte, 0, 17)
	for i, x := range m {
		if i > 0 {
			b = append(b, ':')
		}
		b = append(b, h[x>>4], h[x&15])
	}
	return string(b)
}

// Eth wraps payload in an Ethernet II header.
func Eth(dst, src MAC, etherType uint16, payload []byte) []byte {
	b := append(append([]byte{}, dst[:]...), src[:]...)
	b = binary.BigEndian.AppendUint16(b, etherType)
	return append(b, payload...)
}

// EthVLAN wraps payload in an Ethernet header with one 802.1Q tag.
func EthVLAN(dst, src MAC, vlan uint16, etherType uint16, payload []byte) []byte {
	b := append(append([]byte{}, dst[:]...), src[:]...)
	b = binary.BigEndian.AppendUint16(b, 0x8100)
	b = binary.BigEndian.AppendUint16(b, vlan)
	b = binary.BigEndian.AppendUint16(b, etherType)
	return append(b, payload...)
}

// IPv4 wraps payload in an IPv4 header (no options, no fragmentation, correct checksum).
func IPv4(src, dst netip.Addr, proto uint8, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], u16(20+len(payload)))
	h[8], h[9] = 64, proto
	s, d := src.As4(), dst.As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(h[10:], ^uint16(sum))
	return append(h, payload...)
}

// UDP builds a UDP datagram (checksum 0: "not computed", legal over IPv4).
func UDP(sport, dport uint16, payload []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, sport)
	b = binary.BigEndian.AppendUint16(b, dport)
	b = binary.BigEndian.AppendUint16(b, u16(8+len(payload)))
	b = append(b, 0, 0)
	return append(b, payload...)
}

// TCP builds a TCP segment with PSH|ACK and no options.
func TCP(sport, dport uint16, payload []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, sport)
	b = binary.BigEndian.AppendUint16(b, dport)
	b = binary.BigEndian.AppendUint32(b, 1000)
	b = binary.BigEndian.AppendUint32(b, 2000)
	b = append(b, 5<<4, 0x18)
	b = binary.BigEndian.AppendUint16(b, 65535)
	b = append(b, 0, 0, 0, 0)
	return append(b, payload...)
}

// UDPFrame is Eth(IPv4(UDP)) in one call.
func UDPFrame(dst, src MAC, sip, dip netip.Addr, sport, dport uint16, payload []byte) []byte {
	return Eth(dst, src, 0x0800, IPv4(sip, dip, 17, UDP(sport, dport, payload)))
}

// TCPFrame is Eth(IPv4(TCP)) in one call.
func TCPFrame(dst, src MAC, sip, dip netip.Addr, sport, dport uint16, payload []byte) []byte {
	return Eth(dst, src, 0x0800, IPv4(sip, dip, 6, TCP(sport, dport, payload)))
}

// ARP builds an ARP packet (op 1 request, 2 reply) inside an Ethernet frame to dst.
func ARP(dst MAC, op uint16, smac MAC, sip netip.Addr, tmac MAC, tip netip.Addr) []byte {
	b := []byte{0, 1, 8, 0, 6, 4}
	b = binary.BigEndian.AppendUint16(b, op)
	s, t := sip.As4(), tip.As4()
	b = append(b, smac[:]...)
	b = append(b, s[:]...)
	b = append(b, tmac[:]...)
	b = append(b, t[:]...)
	return Eth(dst, smac, 0x0806, b)
}

// DHCPOpts are the options a DHCP message carries.
type DHCPOpts struct {
	Type        byte
	Hostname    string
	VendorClass string
	ClientID    []byte
	Requested   netip.Addr
}

// DHCP builds a BOOTP/DHCP message (op 1 or 2) for an Ethernet client.
func DHCP(op byte, chaddr MAC, ciaddr, yiaddr netip.Addr, o DHCPOpts) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = op, 1, 6
	binary.BigEndian.PutUint32(b[4:], 0x3903f326) // xid
	if ciaddr.IsValid() {
		a := ciaddr.As4()
		copy(b[12:], a[:])
	}
	if yiaddr.IsValid() {
		a := yiaddr.As4()
		copy(b[16:], a[:])
	}
	copy(b[28:], chaddr[:])
	binary.BigEndian.PutUint32(b[236:], 0x63825363)
	opt := func(code byte, v []byte) { b = append(append(b, code, u8(len(v))), v...) }
	if o.Type != 0 {
		opt(53, []byte{o.Type})
	}
	if o.Hostname != "" {
		opt(12, []byte(o.Hostname))
	}
	if o.VendorClass != "" {
		opt(60, []byte(o.VendorClass))
	}
	if o.ClientID != nil {
		opt(61, o.ClientID)
	}
	if o.Requested.IsValid() {
		a := o.Requested.As4()
		opt(50, a[:])
	}
	return append(b, 255)
}

// DNSRecord is one resource record for DNSMessage.
type DNSRecord struct {
	Name  string
	Type  uint16
	RData []byte
}

// RR builds a DNSRecord.
func RR(name string, typ uint16, rdata []byte) DNSRecord { return DNSRecord{name, typ, rdata} }

// A returns the rdata of an A record.
func A(ip netip.Addr) []byte { a := ip.As4(); return a[:] }

// NameRData encodes a domain name for PTR rdata.
func NameRData(name string) []byte { return encodeName(name) }

// TXT encodes key=value strings as TXT rdata.
func TXT(kv ...string) []byte {
	var b []byte
	for _, s := range kv {
		b = append(append(b, u8(len(s))), s...)
	}
	return b
}

func encodeName(name string) []byte {
	var b []byte
	if name != "" {
		for _, l := range strings.Split(name, ".") {
			b = append(append(b, u8(len(l))), l...)
		}
	}
	return append(b, 0)
}

// DNSMessage builds a DNS message; response sets the QR bit.
func DNSMessage(id uint16, response bool, questions [][2]any, records []DNSRecord) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	flags := uint16(0)
	if response {
		flags = 0x8400
	}
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, u16(len(questions)))
	b = binary.BigEndian.AppendUint16(b, u16(len(records)))
	b = append(b, 0, 0, 0, 0)
	for _, q := range questions {
		b = append(b, encodeName(q[0].(string))...)
		b = binary.BigEndian.AppendUint16(b, q[1].(uint16))
		b = binary.BigEndian.AppendUint16(b, 1)
	}
	for _, r := range records {
		b = append(b, encodeName(r.Name)...)
		b = binary.BigEndian.AppendUint16(b, r.Type)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, 120)
		b = binary.BigEndian.AppendUint16(b, u16(len(r.RData)))
		b = append(b, r.RData...)
	}
	return b
}

// SSDPNotify builds an SSDP NOTIFY (ssdp:alive) message.
func SSDPNotify(server, nt, usn, location string) []byte {
	var sb strings.Builder
	sb.WriteString("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\n")
	sb.WriteString("LOCATION: " + location + "\r\nNT: " + nt + "\r\nNTS: ssdp:alive\r\nSERVER: " + server + "\r\nUSN: " + usn + "\r\n\r\n")
	return []byte(sb.String())
}

// LLDPInfo is what an LLDP frame carries.
type LLDPInfo struct {
	Chassis MAC
	Port    string
	SysName string
	SysDesc string
	Caps    uint16 // enabled capabilities (also advertised)
}

// LLDP builds an LLDP frame from src.
func LLDP(src MAC, i LLDPInfo) []byte {
	var b []byte
	tlv := func(t int, v []byte) {
		b = binary.BigEndian.AppendUint16(b, u16(t<<9|len(v)))
		b = append(b, v...)
	}
	tlv(1, append([]byte{4}, i.Chassis[:]...))
	tlv(2, append([]byte{5}, i.Port...))
	tlv(3, []byte{0, 120})
	if i.SysName != "" {
		tlv(5, []byte(i.SysName))
	}
	if i.SysDesc != "" {
		tlv(6, []byte(i.SysDesc))
	}
	if i.Caps != 0 {
		tlv(7, binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, i.Caps), i.Caps))
	}
	tlv(0, nil)
	return Eth(LLDPDst, src, 0x88cc, b)
}

// ClientHello builds a TLS 1.2 ClientHello record with a server_name extension (sni may be empty: no extension).
func ClientHello(sni string) []byte {
	var ext []byte
	if sni != "" {
		name := append([]byte{0}, binary.BigEndian.AppendUint16(nil, u16(len(sni)))...)
		name = append(name, sni...)
		list := binary.BigEndian.AppendUint16(nil, u16(len(name)))
		list = append(list, name...)
		ext = binary.BigEndian.AppendUint16(ext, 0)
		ext = binary.BigEndian.AppendUint16(ext, u16(len(list)))
		ext = append(ext, list...)
	}
	ext = append(ext, 0, 0x0b, 0, 2, 1, 0) // ec_point_formats, so the SNI is not the only extension
	var hello []byte
	hello = append(hello, 3, 3)
	hello = append(hello, bytes.Repeat([]byte{0x42}, 32)...)
	hello = append(hello, 0)                            // session id
	hello = append(hello, 0, 4, 0xc0, 0x2f, 0x00, 0x2f) // cipher suites
	hello = append(hello, 1, 0)                         // compression
	hello = binary.BigEndian.AppendUint16(hello, u16(len(ext)))
	hello = append(hello, ext...)
	hs := append([]byte{1, u8(len(hello) >> 16), u8(len(hello) >> 8), u8(len(hello))}, hello...)
	rec := append([]byte{0x16, 3, 1}, binary.BigEndian.AppendUint16(nil, u16(len(hs)))...)
	return append(rec, hs...)
}

// HTTPRequest builds an HTTP/1.1 request with the given header lines and body. Tests put secrets in the
// Cookie header and the body to prove they are never kept.
func HTTPRequest(method, path, host string, extra []string, body string) []byte {
	var sb strings.Builder
	sb.WriteString(method + " " + path + " HTTP/1.1\r\n")
	if host != "" {
		sb.WriteString("Host: " + host + "\r\n")
	}
	for _, h := range extra {
		sb.WriteString(h + "\r\n")
	}
	sb.WriteString("\r\n" + body)
	return []byte(sb.String())
}

// Frame is one recorded frame.
type Frame struct {
	At   time.Time
	Data []byte
}

// The fixtures are small by construction; these conversions would only matter for a frame over 64 KiB.
func u16(n int) uint16 { return uint16(n) } //nolint:gosec // test data is far below 64 KiB
func u8(n int) byte    { return byte(n) }   //nolint:gosec // callers pass lengths below 256 or masked shifts
