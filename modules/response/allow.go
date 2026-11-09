// Package response is the response module (WP-13a, part 1): the execution switch, the action catalog, rules and the engine, requests and
// approvals in the app, the box actions (block list, message, webhook) and the hash-chained log. See CONTRACT.md.
package response

import (
	"net/netip"
	"strconv"
	"strings"
)

// The never-touch list (INV-10): gateway, DNS servers, domain controllers, this box, management addresses and the
// services the customer declared, as IP addresses, CIDR ranges or domains. A target that matches is refused at
// planning and again right before running. The box's own interface addresses always count, whether or not they are
// listed.

// AllowEntry is one line of the never-touch list.
type AllowEntry struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// parseEntry reads a never-touch entry: an address (loopback and link-local allowed: the box itself), a prefix, or a domain.
func parseEntry(v string) (netip.Addr, netip.Prefix, string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" {
		return a.Unmap(), netip.Prefix{}, "", true
	}
	if p, err := netip.ParsePrefix(v); err == nil && p.Addr().Zone() == "" {
		return netip.Addr{}, netip.PrefixFrom(p.Addr().Unmap(), unmapBits(p)).Masked(), "", true
	}
	if len(v) <= 253 && domainRE.MatchString(v) {
		return netip.Addr{}, netip.Prefix{}, v, true
	}
	return netip.Addr{}, netip.Prefix{}, "", false
}

// ValidAllowValue reports whether v can be an entry of the list; it returns the canonical (lower case) text.
func ValidAllowValue(v string) (string, bool) {
	a, p, d, ok := parseEntry(v)
	switch {
	case !ok:
		return "", false
	case a.IsValid():
		return a.String(), true
	case p.IsValid():
		return p.String(), true
	}
	return d, true
}

// touches reports whether a target value (a checked ip, cidr or domain) is touched by a never-touch entry: it
// equals the entry, lies inside it, contains it (a range that holds a listed address) or overlaps it.
func touches(entry, value string) bool {
	ea, ep, ed, ok := parseEntry(entry)
	if !ok {
		return false
	}
	va, vp, vd, ok := parseEntry(value)
	if !ok {
		return false
	}
	switch {
	case ea.IsValid() && va.IsValid():
		return ea == va
	case ea.IsValid() && vp.IsValid():
		return vp.Contains(ea)
	case ep.IsValid() && va.IsValid():
		return ep.Contains(va)
	case ep.IsValid() && vp.IsValid():
		return ep.Contains(vp.Addr()) || vp.Contains(ep.Addr())
	case ed != "" && vd != "":
		return vd == ed || strings.HasSuffix(vd, "."+ed)
	}
	return false
}

// boxEntries turns the box's own addresses into never-touch entries.
func boxEntries(addrs []netip.Addr) []AllowEntry {
	out := make([]AllowEntry, 0, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsValid() {
			out = append(out, AllowEntry{Value: a.String(), Label: "This Vedette box"})
		}
	}
	return out
}

// prefixSize is how many addresses a cidr value names, capped so a huge IPv6 range stays a number.
func prefixSize(c string) int {
	p, err := netip.ParsePrefix(c)
	if err != nil {
		return 1
	}
	host := p.Addr().BitLen() - p.Bits()
	if host > 30 {
		return 1 << 30
	}
	return 1 << host
}

func itoa(n int) string { return strconv.Itoa(n) }
