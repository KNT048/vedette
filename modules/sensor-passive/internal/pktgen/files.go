package pktgen

import (
	"bytes"
	"encoding/binary"
	"time"
)

// WritePCAP writes frames as a classic little-endian microsecond pcap with link type Ethernet.
func WritePCAP(frames []Frame) []byte {
	var b bytes.Buffer
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], 1)
	b.Write(h)
	for _, f := range frames {
		r := make([]byte, 16)
		binary.LittleEndian.PutUint32(r[0:], u32(f.At.Unix()))
		binary.LittleEndian.PutUint32(r[4:], u32(int64(f.At.Nanosecond()/1000)))
		binary.LittleEndian.PutUint32(r[8:], u32(int64(len(f.Data))))
		binary.LittleEndian.PutUint32(r[12:], u32(int64(len(f.Data))))
		b.Write(r)
		b.Write(f.Data)
	}
	return b.Bytes()
}

// WritePCAPNG writes frames as a little-endian pcapng file: one section, one Ethernet interface with
// nanosecond timestamps, enhanced packet blocks.
func WritePCAPNG(frames []Frame) []byte {
	var b bytes.Buffer
	block := func(typ uint32, body []byte) {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		total := u32(int64(12 + len(body)))
		_ = binary.Write(&b, binary.LittleEndian, typ)
		_ = binary.Write(&b, binary.LittleEndian, total)
		b.Write(body)
		_ = binary.Write(&b, binary.LittleEndian, total)
	}
	shb := binary.LittleEndian.AppendUint32(nil, 0x1a2b3c4d)
	shb = binary.LittleEndian.AppendUint16(shb, 1)
	shb = binary.LittleEndian.AppendUint16(shb, 0)
	shb = binary.LittleEndian.AppendUint64(shb, ^uint64(0)) // section length unknown
	block(0x0a0d0d0a, shb)
	idb := binary.LittleEndian.AppendUint16(nil, 1) // Ethernet
	idb = binary.LittleEndian.AppendUint16(idb, 0)
	idb = binary.LittleEndian.AppendUint32(idb, 65535)
	idb = append(idb, 9, 0, 1, 0, 9, 0, 0, 0) // if_tsresol = 9 (nanoseconds), padded
	idb = append(idb, 0, 0, 0, 0)             // end of options
	block(1, idb)
	for _, f := range frames {
		ns := uint64(f.At.UnixNano())
		epb := binary.LittleEndian.AppendUint32(nil, 0)
		epb = binary.LittleEndian.AppendUint32(epb, u32(int64(ns>>32)))
		epb = binary.LittleEndian.AppendUint32(epb, u32(int64(ns&0xffffffff)))
		epb = binary.LittleEndian.AppendUint32(epb, u32(int64(len(f.Data))))
		epb = binary.LittleEndian.AppendUint32(epb, u32(int64(len(f.Data))))
		block(6, append(epb, f.Data...))
	}
	return b.Bytes()
}

// T0 is the fixed start time of every fixture.
var T0 = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

func at(sec int) time.Time { return T0.Add(time.Duration(sec) * time.Second) }

// Fixtures returns the recordings of testdata, by file name. They are deterministic.
func Fixtures() map[string][]byte {
	return map[string][]byte{
		"lan-discovery.pcap":   WritePCAP(LANDiscovery()),
		"span-metadata.pcapng": WritePCAPNG(SpanMetadata()),
		"span-own-only.pcap":   WritePCAP(SpanOwnOnly()),
		"malformed.pcap":       WritePCAP(Malformed()),
	}
}

// Secrets that must never appear in anything the module keeps (INV-3, FORBID-2).
const (
	SecretCookie   = "session=SECRET-COOKIE-7f3a91"
	SecretPassword = "password=hunter2-SECRET"
	SecretAuth     = "Authorization: Bearer SECRET-TOKEN-55aa"
)

// LANDiscovery is a few minutes on a quiet LAN: ARP, DHCP, mDNS, SSDP and LLDP, plus the box's own chatter.
func LANDiscovery() []Frame {
	var f []Frame
	add := func(sec int, d []byte) { f = append(f, Frame{at(sec), d}) }
	// the PC joins: DHCP discover, offer, request (with its name), ack, then ARP
	add(0, UDPFrame(Bcast, PC, netipZero, netipBcast, 68, 67, DHCP(1, PC, netipInvalid, netipInvalid, DHCPOpts{Type: 1, Hostname: "PC-ACCOUNTING-01", VendorClass: "MSFT 5.0", ClientID: append([]byte{1}, PC[:]...)})))
	add(1, UDPFrame(Bcast, Router, RouterIP, netipBcast, 67, 68, DHCP(2, PC, netipInvalid, PCIP, DHCPOpts{Type: 2})))
	add(2, UDPFrame(Bcast, PC, netipZero, netipBcast, 68, 67, DHCP(1, PC, netipInvalid, netipInvalid, DHCPOpts{Type: 3, Hostname: "PC-ACCOUNTING-01", Requested: PCIP})))
	add(3, UDPFrame(PC, Router, RouterIP, netipBcast, 67, 68, DHCP(2, PC, netipInvalid, PCIP, DHCPOpts{Type: 5})))
	add(4, ARP(Bcast, 1, PC, PCIP, MAC{}, RouterIP))
	add(4, ARP(PC, 2, Router, RouterIP, PC, PCIP))
	add(5, ARP(Bcast, 1, PC, PCIP, MAC{}, RouterIP)) // the same ARP again: sent once
	// the box asks too: nothing about it may become a device
	add(6, ARP(Bcast, 1, Box, BoxIP, MAC{}, RouterIP))
	// a printer announces itself on mDNS (hostname, kind, model) and SSDP
	add(10, UDPFrame(Mcast4, Printer, PrinterIP, netipMDNS, 5353, 5353, DNSMessage(0, true, nil, []DNSRecord{
		{"hp-laser-3f.local", 1, A(PrinterIP)},
		{"_ipp._tcp.local", 12, NameRData("HP Laser 3F._ipp._tcp.local")},
		{"HP Laser 3F._ipp._tcp.local", 16, TXT("ty=HP LaserJet Pro M404", "md=HP LaserJet Pro M404")},
		{"liar.local", 1, A(PCIP)}, // a name that points at somebody else: not evidence about the sender
	})))
	add(11, UDPFrame(netipMcastMAC, Router, RouterIP, netipSSDP, 1900, 1900, SSDPNotify("Linux/5.4 UPnP/1.0 MiniUPnPd/2.2", "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "uuid:abc::urn:schemas-upnp-org:device:InternetGatewayDevice:1", "http://192.168.10.1:5000/rootDesc.xml")))
	add(12, UDPFrame(netipMcastMAC, Router, RouterIP, netipSSDP, 1900, 1900, []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")))
	// the switch speaks LLDP
	add(20, LLDP(Switch, LLDPInfo{Chassis: Switch, Port: "Gi1/0/7", SysName: "SW-CORE-01", SysDesc: "Juniper Networks, Inc. ex2300-24t Ethernet Switch, kernel JUNOS 18.2R3.4, Build date: 2019-08-30 12:00:00 UTC Copyright (c) 1996-2019 Juniper Networks, Inc.", Caps: 1<<2 | 1<<4}))
	// a laptop with a registered vendor prefix says hello
	add(25, ARP(Bcast, 1, Laptop, LaptopIP, MAC{}, RouterIP))
	// a phone only asks for DHCP, no name
	add(30, UDPFrame(Bcast, Phone, netipZero, netipBcast, 68, 67, DHCP(1, Phone, netipInvalid, netipInvalid, DHCPOpts{Type: 1})))
	// ordinary IP traffic carries no discovery in a non-SPAN recording
	add(31, UDPFrame(Router, PC, PCIP, DNSIP, 40000, 53, DNSMessage(7, false, [][2]any{{"example.org", uint16(1)}}, nil)))
	return f
}

// SpanMetadata is what a SPAN port delivers: DNS queries, TLS hellos, HTTP requests and flows of several
// devices, including an excluded host, a request full of secrets, and the box's own traffic.
func SpanMetadata() []Frame {
	var f []Frame
	add := func(sec int, d []byte) { f = append(f, Frame{at(sec), d}) }
	add(0, UDPFrame(Router, PC, PCIP, DNSIP, 40001, 53, DNSMessage(1, false, [][2]any{{"Updates.Example.ORG", uint16(1)}}, nil)))
	add(0, UDPFrame(PC, Router, DNSIP, PCIP, 53, 40001, DNSMessage(1, true, [][2]any{{"updates.example.org", uint16(1)}}, []DNSRecord{{"updates.example.org", 1, A(WebIP)}})))
	add(1, UDPFrame(Router, Phone, PhoneIP, DNSIP, 40002, 53, DNSMessage(2, false, [][2]any{{"tracker.badsite.test", uint16(28)}}, nil)))
	add(2, TCPFrame(Router, PC, PCIP, WebIP, 50001, 443, ClientHello("portal.example.org")))
	add(2, TCPFrame(Router, PC, PCIP, WebIP, 50001, 443, []byte{0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5})) // application data: nothing to read
	add(3, TCPFrame(Router, PC, PCIP, WebIP, 50002, 80, HTTPRequest("POST", "/login", "legacy.example.org:80", []string{"Cookie: " + SecretCookie, SecretAuth, "Content-Type: application/x-www-form-urlencoded"}, SecretPassword)))
	add(4, TCPFrame(Router, PC, PCIP, WebIP, 50002, 80, []byte("...rest of the body, "+SecretPassword)))
	// the excluded host (see the filters in the tests: 192.168.10.23) talks too
	add(5, UDPFrame(Router, Phone, PhoneIP, DNSIP, 40003, 53, DNSMessage(3, false, [][2]any{{"private.example.net", uint16(1)}}, nil)))
	add(5, TCPFrame(Router, Phone, PhoneIP, WebIP, 50003, 443, ClientHello("private.example.net")))
	// the box itself
	add(6, UDPFrame(Router, Box, BoxIP, DNSIP, 40004, 53, DNSMessage(4, false, [][2]any{{"box-update.example.org", uint16(1)}}, nil)))
	add(7, ARP(Bcast, 1, Box, BoxIP, MAC{}, RouterIP))
	// a second and third packet of the same flow
	add(8, TCPFrame(Router, PC, PCIP, WebIP, 50001, 443, []byte{0x17, 3, 3, 0, 5, 9, 9, 9, 9, 9}))
	add(9, TCPFrame(PC, Router, WebIP, PCIP, 443, 50001, []byte{0x17, 3, 3, 0, 5, 7, 7, 7, 7, 7}))
	// discovery over the mirror works too
	add(10, ARP(Bcast, 1, Printer, PrinterIP, MAC{}, RouterIP))
	return f
}

// SpanOwnOnly is a "mirror" that carries only the box's own frames (INV-9).
func SpanOwnOnly() []Frame {
	var f []Frame
	for i := range 5 {
		f = append(f, Frame{at(i), UDPFrame(Router, Box, BoxIP, DNSIP, 40010, 53, DNSMessage(uint16(i), false, [][2]any{{"ntp.example.org", uint16(1)}}, nil))})
	}
	return f
}

// Malformed is a set of broken frames, one or more for every parser, and a valid ARP at the end to prove the
// reader carries on after bad input.
func Malformed() []Frame {
	var f []Frame
	add := func(d []byte) { f = append(f, Frame{at(len(f)), d}) }
	add([]byte{1, 2, 3})                                                        // shorter than an Ethernet header
	add(Eth(Bcast, PC, 0x0806, []byte{0, 1, 8, 0, 6, 4, 0, 9}))                 // ARP, bad operation and short
	add(Eth(Router, PC, 0x0800, []byte{0x45, 0, 0}))                            // IPv4 header cut
	add(Eth(Router, PC, 0x0800, append([]byte{0x65}, make([]byte, 30)...)))     // IP version 6 in an IPv4 frame
	add(UDPFrame(Bcast, PC, netipZero, netipBcast, 68, 67, []byte{1, 1, 6, 0})) // DHCP cut
	d := DHCP(1, PC, netipInvalid, netipInvalid, DHCPOpts{Type: 1})
	add(UDPFrame(Bcast, PC, netipZero, netipBcast, 68, 67, append(d[:len(d)-1], 12, 200, 'x')))                                                             // option longer than the message
	add(UDPFrame(Mcast4, Printer, PrinterIP, netipMDNS, 5353, 5353, []byte{0, 0, 0x84, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}))                                   // 65535 answers
	add(UDPFrame(Mcast4, Printer, PrinterIP, netipMDNS, 5353, 5353, []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0})) // a pointer to itself
	add(UDPFrame(Router, PC, PCIP, DNSIP, 40000, 53, []byte{1, 2, 3}))                                                                                      // DNS cut
	add(UDPFrame(netipMcastMAC, Router, RouterIP, netipSSDP, 1900, 1900, []byte("GET / HTTP/1.1\r\n\r\n")))                                                 // not an SSDP start line
	add(Eth(LLDPDst, Switch, 0x88cc, []byte{0x02, 0x07, 4, 0xaa}))                                                                                          // LLDP cut inside a TLV
	add(TCPFrame(Router, PC, PCIP, WebIP, 50001, 443, []byte{0x16, 3, 1, 0, 3, 1, 0xff, 0xff, 0xff}))                                                       // ClientHello longer than its record
	add(TCPFrame(Router, PC, PCIP, WebIP, 50001, 80, []byte("GET /\x00\x01 garbage\r\nHost: a\r\n\r\n")))                                                   // request line without a version
	add(Eth(Router, PC, 0x0800, IPv4(PCIP, WebIP, 6, []byte{1, 2, 3})))                                                                                     // TCP header cut
	add(ARP(Bcast, 1, PC, PCIP, MAC{}, RouterIP))
	return f
}

func u32(n int64) uint32 { return uint32(n) } //nolint:gosec // timestamps and sizes of the fixtures fit in 32 bits
