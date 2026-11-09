package ops

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// ARP frames (D-101, INV-18). The host sends and reads exactly one kind of frame: Ethernet II
// carrying an IPv4-over-Ethernet ARP packet, 14 + 28 = 42 bytes. Everything here is pure, takes
// bytes and returns bytes, and is fuzzed: the code that reads what hostile hosts put on the wire
// runs as root, so it is small and has no other input.

const (
	arpFrameLen = 42
	// arpWireMax is the longest frame the reader accepts: Ethernet pads a short frame to 60 bytes
	// and many cards deliver the padding. Only the first 42 bytes are looked at; the padding is
	// never interpreted (it can carry leaked memory of the sender).
	arpWireMax = 60

	arpOpRequest = 1
	arpOpReply   = 2
)

var etherBroadcast = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// arpPacket is what parseARP returns.
type arpPacket struct {
	Op        uint16
	SenderMAC [6]byte
	SenderIP  netip.Addr
	TargetMAC [6]byte
	TargetIP  netip.Addr
}

// encodeARP builds one frame. All fields are caller-chosen; the Ethernet source is the sender MAC.
func encodeARP(dst [6]byte, p arpPacket) []byte {
	b := make([]byte, arpFrameLen)
	copy(b[0:6], dst[:])
	copy(b[6:12], p.SenderMAC[:])
	binary.BigEndian.PutUint16(b[12:14], 0x0806)
	binary.BigEndian.PutUint16(b[14:16], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(b[16:18], 0x0800) // protocol type: IPv4
	b[18], b[19] = 6, 4
	binary.BigEndian.PutUint16(b[20:22], p.Op)
	copy(b[22:28], p.SenderMAC[:])
	s := p.SenderIP.As4()
	copy(b[28:32], s[:])
	copy(b[32:38], p.TargetMAC[:])
	t := p.TargetIP.As4()
	copy(b[38:42], t[:])
	return b
}

// probeFrame is the RFC 5227 probe: a broadcast request for target whose sender IP is 0.0.0.0, so
// no cache on the LAN learns the address that is being tested.
func probeFrame(mac [6]byte, target netip.Addr) []byte {
	return encodeARP(etherBroadcast, arpPacket{Op: arpOpRequest, SenderMAC: mac, SenderIP: netip.IPv4Unspecified(), TargetIP: target})
}

// requestFrame is a broadcast "who has target, tell src": the gateway check.
func requestFrame(mac [6]byte, src, target netip.Addr) []byte {
	return encodeARP(etherBroadcast, arpPacket{Op: arpOpRequest, SenderMAC: mac, SenderIP: src, TargetIP: target})
}

var errNotARP = errors.New("arp: not an Ethernet/IPv4 ARP frame of 42 bytes")

// parseARP reads one frame. It refuses any length but 42 and any field value but Ethernet,
// IPv4, hardware length 6, protocol length 4 and the request or reply opcode.
func parseARP(b []byte) (arpPacket, error) {
	if len(b) != arpFrameLen ||
		binary.BigEndian.Uint16(b[12:14]) != 0x0806 ||
		binary.BigEndian.Uint16(b[14:16]) != 1 ||
		binary.BigEndian.Uint16(b[16:18]) != 0x0800 ||
		b[18] != 6 || b[19] != 4 {
		return arpPacket{}, errNotARP
	}
	op := binary.BigEndian.Uint16(b[20:22])
	if op != arpOpRequest && op != arpOpReply {
		return arpPacket{}, errNotARP
	}
	p := arpPacket{Op: op, SenderIP: netip.AddrFrom4([4]byte(b[28:32])), TargetIP: netip.AddrFrom4([4]byte(b[38:42]))}
	copy(p.SenderMAC[:], b[22:28])
	copy(p.TargetMAC[:], b[32:38])
	return p, nil
}

// arpFrameOf cuts what the socket delivered down to the 42 bytes parseARP reads: a frame shorter
// than 42 or longer than the 60-byte Ethernet minimum is not ours to read.
func arpFrameOf(raw []byte) ([]byte, bool) {
	if len(raw) < arpFrameLen || len(raw) > arpWireMax {
		return nil, false
	}
	return raw[:arpFrameLen], true
}
