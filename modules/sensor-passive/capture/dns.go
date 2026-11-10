package capture

import (
	"encoding/binary"
	"strings"
)

const (
	dnsTypeA   = 1
	dnsTypePTR = 12
	dnsTypeTXT = 16

	maxDNSMessage = 9000 // an mDNS message is at most 9000 bytes (RFC 6762 §17)
	maxDNSRecords = 64   // records read from one message; more is malformed
	maxNameJumps  = 8
)

type dnsQuestion struct {
	name  string
	qtype uint16
}

type dnsRecord struct {
	name  string
	rtype uint16
	data  []byte // raw rdata, bounds-checked
	off   int    // offset of data in the message, to read a name inside it
}

type dnsMessage struct {
	raw       []byte
	response  bool
	opcode    int
	questions []dnsQuestion
	records   []dnsRecord // answers, authority and additional together
}

// parseDNS reads a DNS or mDNS message. Names are decoded with a bounded number of compression jumps;
// the result is text and may hold any byte but NUL-free printable runs (names are checked by the users).
func parseDNS(b []byte) (dnsMessage, error) {
	if len(b) < 12 || len(b) > maxDNSMessage {
		return dnsMessage{}, malformed("dns: size")
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	ns := int(binary.BigEndian.Uint16(b[8:10]))
	ar := int(binary.BigEndian.Uint16(b[10:12]))
	if qd > 16 || an+ns+ar > maxDNSRecords {
		return dnsMessage{}, malformed("dns: too many entries")
	}
	m := dnsMessage{raw: b, response: flags&0x8000 != 0, opcode: int(flags>>11) & 15}
	off := 12
	for range qd {
		name, next, err := readName(b, off)
		if err != nil {
			return dnsMessage{}, err
		}
		if next+4 > len(b) {
			return dnsMessage{}, malformed("dns: short question")
		}
		m.questions = append(m.questions, dnsQuestion{name, binary.BigEndian.Uint16(b[next : next+2])})
		off = next + 4
	}
	for range an + ns + ar {
		name, next, err := readName(b, off)
		if err != nil {
			return dnsMessage{}, err
		}
		if next+10 > len(b) {
			return dnsMessage{}, malformed("dns: short record")
		}
		rdlen := int(binary.BigEndian.Uint16(b[next+8 : next+10]))
		if next+10+rdlen > len(b) {
			return dnsMessage{}, malformed("dns: rdata overruns the message")
		}
		m.records = append(m.records, dnsRecord{name, binary.BigEndian.Uint16(b[next : next+2]), b[next+10 : next+10+rdlen], next + 10})
		off = next + 10 + rdlen
	}
	return m, nil
}

// readName decodes the name at off and returns it (dot-separated, no trailing dot) and the offset after it
// in the original position (compression pointers do not move that offset past their two bytes).
func readName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	next, jumped, jumps := 0, false, 0
	for {
		if off >= len(b) {
			return "", 0, malformed("dns: name overruns the message")
		}
		c := int(b[off])
		switch {
		case c == 0:
			if !jumped {
				next = off + 1
			}
			return sb.String(), next, nil
		case c&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return "", 0, malformed("dns: short pointer")
			}
			if !jumped {
				next = off + 2
			}
			jumped = true
			if jumps++; jumps > maxNameJumps {
				return "", 0, malformed("dns: too many compression jumps")
			}
			off = (c&0x3f)<<8 | int(b[off+1])
		case c&0xc0 != 0:
			return "", 0, malformed("dns: label type")
		default:
			if off+1+c > len(b) {
				return "", 0, malformed("dns: label overruns the message")
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(b[off+1 : off+1+c])
			if sb.Len() > 253 {
				return "", 0, malformed("dns: name too long")
			}
			off += 1 + c
		}
	}
}

// rdataName decodes the name a PTR record points to.
func (m dnsMessage) rdataName(r dnsRecord) (string, bool) {
	n, _, err := readName(m.raw, r.off)
	return n, err == nil
}

// txtPairs reads the key=value strings of a TXT rdata (DNS-SD), at most 32 strings.
func txtPairs(rdata []byte) map[string]string {
	out := map[string]string{}
	for i, n := 0, 0; i < len(rdata) && n < 32; n++ {
		l := int(rdata[i])
		if i+1+l > len(rdata) {
			break
		}
		if k, v, ok := strings.Cut(string(rdata[i+1:i+1+l]), "="); ok && len(k) <= 32 {
			out[strings.ToLower(k)] = v
		}
		i += 1 + l
	}
	return out
}
