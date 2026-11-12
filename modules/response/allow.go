// Package response is the response module (WP-13a, part 1): the execution switch, the action catalog, rules and the engine, requests and
// approvals in the app, the box actions (block list, message, webhook) and the hash-chained log. See CONTRACT.md.
package response

import (
	"net/netip"
	"regexp"
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

// entry is a parsed never-touch value. Exactly one of addr, prefix, mac, domain or iface is set.
type entry struct {
	addr   netip.Addr
	prefix netip.Prefix
	mac    string
	domain string
	iface  string
}

// ifaceEntryRE is what may be listed as a port: a name that starts with a letter (Gi1/0/48, ether1, ae0.100) or a stack
// position of numbers (1/1/48). A number with dots (a mistyped address) is not a port.
var ifaceEntryRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9/.:-]{0,31}|[0-9]+(/[0-9]+)+)$`)

// parseEntry reads a never-touch entry: an address (loopback and link-local allowed: the box itself), a prefix, a MAC
// address, a domain, or a port name. A port name protects that name on every device (the safe side; scoping it to one
// switch needs the identity of the switch, part 13b).
func parseEntry(v string) (entry, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if a, err := netip.ParseAddr(v); err == nil && a.Zone() == "" {
		return entry{addr: a.Unmap()}, true
	}
	if p, err := netip.ParsePrefix(v); err == nil && p.Addr().Zone() == "" {
		return entry{prefix: netip.PrefixFrom(p.Addr().Unmap(), unmapBits(p)).Masked()}, true
	}
	if mac, ok := canonEntryMAC(v); ok {
		return entry{mac: mac}, true
	}
	if len(v) <= 253 && domainRE.MatchString(v) {
		return entry{domain: v}, true
	}
	if interfaceRE.MatchString(v) && ifaceEntryRE.MatchString(v) && cleanSegments(v) {
		return entry{iface: v}, true
	}
	return entry{}, false
}

var (
	ciscoMACRE = regexp.MustCompile(`^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$`)
	bareMACRE  = regexp.MustCompile(`^[0-9a-f]{12}$`)
)

// canonEntryMAC reads a MAC in any form an admin pastes from a device or a label: aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, the Cisco
// dotted form aabb.ccdd.eeff or twelve bare hex digits. It returns the canonical lower-case colon form, the one events and
// parameters use, so an entry in one form still matches a target in another. v is lower case.
func canonEntryMAC(v string) (string, bool) {
	switch {
	case macRE.MatchString(v):
		return strings.ReplaceAll(v, "-", ":"), true
	case ciscoMACRE.MatchString(v):
		v = strings.ReplaceAll(v, ".", "")
	case !bareMACRE.MatchString(v):
		return "", false
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(v[i : i+2])
	}
	return b.String(), true
}

// ValidAllowValue reports whether v can be an entry of the list; it returns the canonical (lower case) text.
func ValidAllowValue(v string) (string, bool) {
	e, ok := parseEntry(v)
	switch {
	case !ok:
		return "", false
	case e.addr.IsValid():
		return e.addr.String(), true
	case e.prefix.IsValid():
		return e.prefix.String(), true
	case e.mac != "":
		return e.mac, true
	case e.domain != "":
		return e.domain, true
	}
	return e.iface, true
}

// touches reports whether a target value (a checked ip, cidr, domain, mac or interface) is touched by a never-touch
// entry: it equals the entry, lies inside it, contains it (a range that holds a listed address, a parent domain of a
// listed domain) or overlaps it.
func touches(entryValue, value string) bool {
	e, ok := parseEntry(entryValue)
	if !ok {
		return false
	}
	v, ok := parseEntry(value)
	if !ok {
		return false
	}
	return touchesParsed(e, v)
}

// touchesParsed is touches on entries parseEntry already read, for a caller that tests many values against one list.
func touchesParsed(e, v entry) bool {
	switch {
	case e.addr.IsValid() && v.addr.IsValid():
		return e.addr == v.addr
	case e.addr.IsValid() && v.prefix.IsValid():
		return v.prefix.Contains(e.addr)
	case e.prefix.IsValid() && v.addr.IsValid():
		return e.prefix.Contains(v.addr)
	case e.prefix.IsValid() && v.prefix.IsValid():
		return e.prefix.Contains(v.prefix.Addr()) || v.prefix.Contains(e.prefix.Addr())
	case e.domain != "" && v.domain != "":
		// the listed domain, its subdomains, and its parents (blocking corp.example.com blocks login.corp.example.com on a DNS filter)
		return v.domain == e.domain || strings.HasSuffix(v.domain, "."+e.domain) || strings.HasSuffix(e.domain, "."+v.domain)
	case e.mac != "" && v.mac != "":
		return e.mac == v.mac
	case e.iface != "" && v.iface != "":
		return e.iface == v.iface
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
