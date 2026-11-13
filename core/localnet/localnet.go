// Package localnet says which IPv4 addresses can belong to a customer's own network, the networks Vedette may watch and scan
// (setup, Devices -> Scope, nmap and nuclei targets, the LAN device of a logged connection): the private ranges of RFC 1918
// (10/8, 172.16/12, 192.168/16) and the shared address space of RFC 6598 (100.64.0.0/10: carrier-grade NAT inside an ISP or
// a company network, Tailscale), D-461. Only 100.64/10: the rest of 100/8 is public.
//
// It is not a public-address test: the guards that ask "is this on the Internet" (feeds, webhooks, SIEM, exposure, the block
// list) keep refusing 100.64/10 by their own rules. Standard library only: the sensor binary links it through nmapargv and
// nucleiargv.
package localnet

import (
	"net/netip"
	"slices"
)

// Names names the local networks in the words of the error messages that refuse a range outside them (setup, Devices -> Scope;
// the mocks in web/src say the same).
const Names = "10.x, 172.16-31.x, 192.168.x, 100.64-127.x"

// Shared is the RFC 6598 shared address space, 100.64.0.0 to 100.127.255.255.
var Shared = netip.MustParsePrefix("100.64.0.0/10")

// blocks are the networks a local address lies in.
var blocks = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), Shared}

// Addr reports whether a is a plain IPv4 address (not IPv4-mapped IPv6) inside one of the local networks.
func Addr(a netip.Addr) bool {
	return a.Is4() && slices.ContainsFunc(blocks, func(b netip.Prefix) bool { return b.Contains(a) })
}

// Prefix reports whether p is an IPv4 range inside one of the local networks and not wider than it: 100.64.0.0/16 is local,
// 100.0.0.0/8 and 10.0.0.0/7 are not.
func Prefix(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is4() && slices.ContainsFunc(blocks, func(b netip.Prefix) bool { return b.Bits() <= p.Bits() && b.Contains(p.Addr()) })
}
