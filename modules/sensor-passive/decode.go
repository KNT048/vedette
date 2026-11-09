package sensorpassive

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// errMalformed is wrapped by every parser: the bytes cannot be what they claim to be. The caller drops
// the packet and counts it (INV-4); nothing in this package panics on bad input.
var errMalformed = errors.New("malformed packet")

// errIgnore says the packet is fine but carries nothing this module reads (not counted as malformed).
var errIgnore = errors.New("nothing to read")

func malformed(what string) error { return errors.Join(errMalformed, errors.New(what)) }

const (
	etherARP  = 0x0806
	etherIPv4 = 0x0800
	etherVLAN = 0x8100
	etherQinQ = 0x88a8
	etherLLDP = 0x88cc

	protoTCP = 6
	protoUDP = 17
)

type mac [6]byte

func (m mac) String() string {
	const hexd = "0123456789abcdef"
	b := make([]byte, 0, 17)
	for i, x := range m {
		if i > 0 {
			b = append(b, ':')
		}
		b = append(b, hexd[x>>4], hexd[x&15])
	}
	return string(b)
}

// usable reports whether m can identify a device: not all-zero, not broadcast, not a group address.
func (m mac) usable() bool {
	return m != mac{} && m[0]&1 == 0
}

type frame struct {
	src, dst mac
	ethType  uint16
	payload  []byte
}

// parseEthernet reads the Ethernet II header and up to two VLAN tags.
func parseEthernet(b []byte) (frame, error) {
	if len(b) < 14 {
		return frame{}, malformed("ethernet: short frame")
	}
	var f frame
	copy(f.dst[:], b[0:6])
	copy(f.src[:], b[6:12])
	et := binary.BigEndian.Uint16(b[12:14])
	off := 14
	for range 2 {
		if et != etherVLAN && et != etherQinQ {
			break
		}
		if len(b) < off+4 {
			return frame{}, malformed("ethernet: short VLAN tag")
		}
		et = binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
	}
	if et <= 1500 { // 802.3 length field: LLC frames carry nothing we read
		return frame{}, errIgnore
	}
	f.ethType, f.payload = et, b[off:]
	return f, nil
}

type ipv4 struct {
	src, dst netip.Addr
	proto    uint8
	totalLen int
	payload  []byte
	firstFrg bool // false for a fragment that is not the first: it has no L4 header
}

func parseIPv4(b []byte) (ipv4, error) {
	if len(b) < 20 {
		return ipv4{}, malformed("ipv4: short header")
	}
	if b[0]>>4 != 4 {
		return ipv4{}, malformed("ipv4: version")
	}
	ihl := int(b[0]&15) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || total < ihl || len(b) < ihl {
		return ipv4{}, malformed("ipv4: header length")
	}
	if total > len(b) { // a snapped or truncated capture: read what is there
		total = len(b)
	}
	frag := binary.BigEndian.Uint16(b[6:8])
	p := ipv4{
		src:      netip.AddrFrom4([4]byte(b[12:16])),
		dst:      netip.AddrFrom4([4]byte(b[16:20])),
		proto:    b[9],
		totalLen: total,
		payload:  b[ihl:total],
		firstFrg: frag&0x1fff == 0,
	}
	return p, nil
}

type udpDatagram struct {
	sport, dport uint16
	payload      []byte
}

func parseUDP(b []byte) (udpDatagram, error) {
	if len(b) < 8 {
		return udpDatagram{}, malformed("udp: short header")
	}
	n := int(binary.BigEndian.Uint16(b[4:6]))
	if n < 8 {
		return udpDatagram{}, malformed("udp: length")
	}
	if n > len(b) {
		n = len(b)
	}
	return udpDatagram{binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4]), b[8:n]}, nil
}

type tcpSegment struct {
	sport, dport uint16
	payload      []byte
}

func parseTCP(b []byte) (tcpSegment, error) {
	if len(b) < 20 {
		return tcpSegment{}, malformed("tcp: short header")
	}
	off := int(b[12]>>4) * 4
	if off < 20 || off > len(b) {
		return tcpSegment{}, malformed("tcp: data offset")
	}
	return tcpSegment{binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4]), b[off:]}, nil
}

// hostnameOK accepts the characters of a host name: letters, digits, '-', '_' and dots between labels.
// It is the gate for every name that becomes a stored value or a metadata field.
func hostnameOK(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labelLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if labelLen == 0 {
				return false
			}
			labelLen = 0
			continue
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
		labelLen++
		if labelLen > 63 {
			return false
		}
	}
	return labelLen > 0 // no trailing dot: callers trim it first
}

// printable reports whether s is text a person can read: valid UTF-8, no control characters.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// cleanText trims s and cuts it to max bytes on a rune boundary; ok is false when nothing printable is left.
func cleanText(s string, limit int) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > limit {
		s = s[:limit]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	if s == "" || !printable(s) {
		return "", false
	}
	return s, true
}
