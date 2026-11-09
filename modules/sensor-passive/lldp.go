package sensorpassive

import "encoding/binary"

const maxLLDPTLVs = 64

// LLDP capability bits (IEEE 802.1AB, system capabilities TLV).
const (
	lldpCapBridge = 1 << 2
	lldpCapAP     = 1 << 3
	lldpCapRouter = 1 << 4
)

type lldpFrame struct {
	chassisMAC mac // set when the chassis ID is a MAC address (subtype 4)
	hasMAC     bool
	sysName    string
	sysDesc    string
	caps       uint16 // enabled capabilities
}

// parseLLDP reads the TLVs of an LLDPDU. The first three must be chassis ID, port ID and TTL, as the
// standard demands; the frame ends at the End TLV.
func parseLLDP(b []byte) (lldpFrame, error) {
	var f lldpFrame
	for n, i := 0, 0; ; n++ {
		if n >= maxLLDPTLVs {
			return lldpFrame{}, malformed("lldp: too many TLVs")
		}
		if i+2 > len(b) {
			return lldpFrame{}, malformed("lldp: missing End TLV")
		}
		h := binary.BigEndian.Uint16(b[i : i+2])
		typ, l := int(h>>9), int(h&0x1ff)
		if i+2+l > len(b) {
			return lldpFrame{}, malformed("lldp: TLV overruns the frame")
		}
		v := b[i+2 : i+2+l]
		i += 2 + l
		if n < 3 && typ != n+1 {
			return lldpFrame{}, malformed("lldp: mandatory TLV order")
		}
		switch typ {
		case 0:
			if n < 3 {
				return lldpFrame{}, malformed("lldp: ends before the mandatory TLVs")
			}
			return f, nil
		case 1:
			if l == 7 && v[0] == 4 {
				copy(f.chassisMAC[:], v[1:7])
				f.hasMAC = true
			}
		case 5:
			if s, ok := cleanText(string(v), 255); ok {
				f.sysName = s
			}
		case 6:
			if s, ok := cleanText(string(v), 255); ok {
				f.sysDesc = s
			}
		case 7:
			if l == 4 {
				f.caps = binary.BigEndian.Uint16(v[2:4])
			}
		}
	}
}
