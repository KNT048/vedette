package pktgen

import "net/netip"

var (
	netipInvalid  netip.Addr // unset: "no address"
	netipZero     = netip.MustParseAddr("0.0.0.0")
	netipBcast    = netip.MustParseAddr("255.255.255.255")
	netipMDNS     = netip.MustParseAddr("224.0.0.251")
	netipSSDP     = netip.MustParseAddr("239.255.255.250")
	netipMcastMAC = MAC{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}
)
