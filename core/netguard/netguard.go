// Package netguard holds the address facts every outbound guard of Vedette shares (a webhook, a feed, a SIEM forward, an AI provider):
// the cloud instance-metadata endpoints that are not link-local, the metadata service's names, and the IPv4 address an IPv6 transition
// form carries (NAT64, 6to4, IPv4-compatible), so that a guard judges both. Each guard keeps its own rules (box addresses, private ranges,
// ports); this package says only what those addresses are (D-411).
//
// ponytail: response uses it; notify, feeds, logs and ai still keep their own copy of the same code (moving them is a follow-up after
// PR #625, which changes those guards, lands: .ai/deferred/fix-v1-intake-sensor-response.md).
package netguard

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// metadataAddrs are cloud instance-metadata endpoints that are not link-local (169.254.169.254 is): AWS and Google Cloud over IPv6
// (inside the unique-local range), Alibaba, Oracle.
var metadataAddrs = []netip.Addr{netip.MustParseAddr("fd00:ec2::254"), netip.MustParseAddr("fd20:ce::254"), netip.MustParseAddr("100.100.100.200"), netip.MustParseAddr("192.0.0.192")}

// Metadata reports whether a is a cloud metadata endpoint that is not link-local. A guard refuses link-local addresses (which hold
// 169.254.169.254) on its own; it calls Metadata for each of Forms(a).
func Metadata(a netip.Addr) bool { return slices.Contains(metadataAddrs, a.Unmap().WithZone("")) }

// MetadataName reports a name of the cloud metadata service (Google Cloud), refused at save before any lookup; host is lower case,
// without a trailing dot. Other names that resolve to a metadata address are refused when connecting.
func MetadataName(host string) bool {
	return host == "metadata" || host == "metadata.google.internal" || host == "metadata.goog"
}

// Always reports what no guard ever allows, whatever the box's own addresses are: loopback, link-local, multicast, unspecified, the
// limited broadcast and the cloud metadata endpoints. a is one address, not its forms.
func Always(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() ||
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || slices.Contains(metadataAddrs, a)
}

// Forms is a (unmapped, without zone) plus the IPv4 address that a transition form carries (NAT64 64:ff9b::/96 and the local-use
// 64:ff9b:1::/48 in every RFC 6052 layout, 6to4, IPv4-compatible): a connection to one of them reaches that IPv4 address through a
// translator, so a guard judges every form.
func Forms(a netip.Addr) []netip.Addr {
	a = a.Unmap().WithZone("")
	out := []netip.Addr{a}
	if !a.Is6() {
		return out
	}
	b := a.As16()
	var v4 [4]byte
	zeros := func(from, to int) bool {
		for _, x := range b[from:to] {
			if x != 0 {
				return false
			}
		}
		return true
	}
	switch {
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && zeros(4, 12):
		copy(v4[:], b[12:16])
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4] == 0 && b[5] == 1:
		for _, x := range nat64Local(b) {
			out = append(out, netip.AddrFrom4(x))
		}
		return out
	case b[0] == 0x20 && b[1] == 0x02:
		copy(v4[:], b[2:6])
	case zeros(0, 12) && !a.IsUnspecified() && a != netip.IPv6Loopback():
		copy(v4[:], b[12:16])
	default:
		return out
	}
	return append(out, netip.AddrFrom4(v4))
}

// nat64Layouts are the RFC 6052 layouts a 64:ff9b:1::/48 sub-prefix can have (never /32 or /40): the prefix length and the byte
// offsets of the four IPv4 octets (byte 8 is the reserved u octet).
var nat64Layouts = []struct {
	bits int
	at   [4]int
}{{48, [4]int{6, 7, 9, 10}}, {56, [4]int{7, 9, 10, 11}}, {64, [4]int{9, 10, 11, 12}}, {96, [4]int{12, 13, 14, 15}}}

func nat64Embed(b [16]byte, at [4]int) [4]byte {
	return [4]byte{b[at[0]], b[at[1]], b[at[2]], b[at[3]]}
}

// nat64Local lists the IPv4 addresses a 64:ff9b:1::/48 (RFC 8215) address can carry. The operator's prefix is a sub-prefix of that /48
// and its length is not in the address. The address is read in each layout and every reading is judged, so a forbidden IPv4 address
// is never missed. When the network's own NAT64 prefix was learned (nat64Prefixes, RFC 7050) and covers the address, the learned
// layouts (all that cover it) are read for the checks that depend on the network (private ranges, the box's own addresses), and the
// other layouts only for Always: DNS can narrow the first group, never switch off the second (D-442 (2)). A learned reading inside
// 0.0.0.0/8 falls back to every layout. Otherwise a reading inside 0.0.0.0/8 is dropped: a translator never forwards to "this network",
// and it is what the zero suffix of a shorter prefix looks like in a longer layout. An operator prefix whose own bytes read as an
// always-refused address in a shorter layout has every NAT64 destination refused (a known false positive: it fails closed).
func nat64Local(b [16]byte) [][4]byte {
	addr := netip.AddrFrom16(b)
	var out [][4]byte
	add := func(v4 [4]byte) {
		if v4[0] != 0 && !slices.Contains(out, v4) {
			out = append(out, v4)
		}
	}
	var bits []int
	for _, p := range nat64Prefixes() {
		if p.Contains(addr) {
			bits = append(bits, p.Bits())
		}
	}
	if len(bits) > 0 {
		learned := true
		for _, l := range nat64Layouts {
			if slices.Contains(bits, l.bits) {
				if v4 := nat64Embed(b, l.at); v4[0] == 0 {
					learned = false
				} else {
					add(v4)
				}
			}
		}
		if learned {
			for _, l := range nat64Layouts {
				if v4 := nat64Embed(b, l.at); Always(netip.AddrFrom4(v4)) {
					add(v4)
				}
			}
			return out
		}
		out = nil
	}
	for _, l := range nat64Layouts {
		add(nat64Embed(b, l.at))
	}
	return out
}

// learnNAT64 reads the AAAA answers for ipv4only.arpa (RFC 7050, what Android, iOS and systemd-resolved do): an answer inside
// 64:ff9b:1::/48 that carries 192.0.0.170 or 192.0.0.171 in exactly one layout, with a zero u octet, gives the prefix and its length.
func learnNAT64(answers []netip.Addr) []netip.Prefix {
	local := netip.MustParsePrefix("64:ff9b:1::/48")
	var out []netip.Prefix
	for _, a := range answers {
		a = a.Unmap()
		if !a.Is6() || !local.Contains(a) {
			continue
		}
		b := a.As16()
		if b[8] != 0 {
			continue
		}
		bits := 0
		for _, l := range nat64Layouts {
			if v4 := nat64Embed(b, l.at); v4 == [4]byte{192, 0, 0, 170} || v4 == [4]byte{192, 0, 0, 171} {
				if bits != 0 {
					bits = -1
					break
				}
				bits = l.bits
			}
		}
		if bits > 0 {
			if p := netip.PrefixFrom(a, bits).Masked(); !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// nat64Cache asks the system resolver for ipv4only.arpa only when a 64:ff9b:1::/48 address is judged, for at most 2 s, and keeps the
// answer 6 hours (10 minutes when nothing was learned or the lookup failed). One lookup runs at a time and nobody else waits for it: a
// caller that finds it running gets what is known, which is nothing at first, and nothing means every layout. The query carries no
// customer data (D-442).
type nat64Cache struct {
	mu       sync.Mutex
	lookup   func(ctx context.Context) ([]netip.Addr, error)
	now      func() time.Time
	prefixes []netip.Prefix
	until    time.Time
	busy     bool
}

func (c *nat64Cache) get() []netip.Prefix {
	c.mu.Lock()
	if c.busy || c.now().Before(c.until) {
		defer c.mu.Unlock()
		return c.prefixes
	}
	c.busy = true
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	answers, err := c.lookup(ctx)
	prefixes := learnNAT64(answers)
	ttl := 6 * time.Hour
	if err != nil || len(prefixes) == 0 {
		ttl = 10 * time.Minute
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.busy, c.prefixes, c.until = false, prefixes, c.now().Add(ttl)
	return prefixes
}

// nat64Prefixes is the learned NAT64 prefixes of this network. The package tests replace it.
var nat64Prefixes = (&nat64Cache{
	lookup: func(ctx context.Context) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip6", "ipv4only.arpa")
	},
	now: time.Now,
}).get
