package capture

import (
	"encoding/binary"
	"net/netip"
)

type arpPacket struct {
	op        uint16 // 1 request, 2 reply
	senderMAC mac
	senderIP  netip.Addr // zero for a probe (0.0.0.0)
	targetIP  netip.Addr
}

// parseARP reads an Ethernet/IPv4 ARP packet. Anything else (other hardware or protocol types) is malformed
// here because the caller only passes ethertype 0x0806 frames.
func parseARP(b []byte) (arpPacket, error) {
	if len(b) < 28 {
		return arpPacket{}, malformed("arp: short packet")
	}
	if binary.BigEndian.Uint16(b[0:2]) != 1 || binary.BigEndian.Uint16(b[2:4]) != etherIPv4 || b[4] != 6 || b[5] != 4 {
		return arpPacket{}, malformed("arp: not Ethernet/IPv4")
	}
	op := binary.BigEndian.Uint16(b[6:8])
	if op != 1 && op != 2 {
		return arpPacket{}, malformed("arp: operation")
	}
	a := arpPacket{op: op}
	copy(a.senderMAC[:], b[8:14])
	if ip := netip.AddrFrom4([4]byte(b[14:18])); !ip.IsUnspecified() {
		a.senderIP = ip
	}
	a.targetIP = netip.AddrFrom4([4]byte(b[24:28]))
	return a, nil
}
