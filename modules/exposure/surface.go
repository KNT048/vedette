package exposure

import (
	"fmt"
	"net/netip"
	"slices"
)

// The surface of a verified domain (INV-27, D-567): every name with where it was found, its CNAME and each address with its kind.
// What serves a name (a CDN or the customer's own server) does not matter (kien 2026-11-14): the customer verified the domain. Until
// the deep scan of each name comes (after the fence, plan 2026-11-14 §5), a name on another public address gets the D-229 check by
// name only, as before.

// Kinds of a name's address (contract.ts HostIp.class).
const (
	ClassBox     = "box"
	ClassPublic  = "public"
	ClassPrivate = "private"
)

var (
	hostSources = []string{"ct", "dns", "mx", "ns", "wordlist"}
	hostClasses = []string{ClassBox, ClassPublic, ClassPrivate}
)

// maxHostIPs bounds a host row (INV-10): the scan keeps at most 16 addresses a name.
const maxHostIPs = 32

// The "Not checked" lines of a domain's surface (INV-27).
const (
	// NotWordlistWildcard is the line of a scan that did not try the common names: the domain answers any name.
	NotWordlistWildcard = "Common names (a list of about 150, such as vpn, mail and remote): not tried, because this domain answers any name (wildcard DNS), so every one would look real."
	notIPv6             = "IPv6 addresses (%d listed): IPv6 is not scanned yet."
	notByNameOnly       = "Names on public addresses that are not this box's (%s): checked by name on ports 80 and 443 only; the deep scan of each name comes with the next update."
)

// sanitizeHost limits one host row (INV-10): text bounded, a source and kinds from their lists, addresses that parse (the family is
// read from the address, not trusted), a CNAME that is a host name. Anything else is dropped.
func sanitizeHost(h HostRow, txt func(string) string) HostRow {
	out := HostRow{Name: txt(h.Name), IP: txt(h.IP)}
	if slices.Contains(hostSources, h.Source) {
		out.Source = h.Source
	}
	if c := txt(h.CNAME); len(c) <= 253 && domainRE.MatchString(c) {
		out.CNAME = c
	}
	for _, a := range h.IPs {
		ip, err := netip.ParseAddr(a.IP)
		if err != nil || !slices.Contains(hostClasses, a.Class) || len(out.IPs) >= maxHostIPs {
			continue
		}
		ip = ip.Unmap()
		fam := "ipv4"
		if ip.Is6() {
			fam = "ipv6"
		}
		out.IPs = append(out.IPs, HostIP{IP: ip.String(), Family: fam, Class: a.Class})
	}
	return out
}

// surfaceNotChecked is what a domain's surface did not scan: names on public IPv4 addresses that are not the box's (by name only),
// and IPv6 addresses. It reads the rows before they are limited (identify runs first), so the family comes from the address.
func surfaceNotChecked(hosts []HostRow) []NotCheckedRow {
	v6, byName := 0, 0
	for _, h := range hosts {
		public := false
		for _, a := range h.IPs {
			ip, err := netip.ParseAddr(a.IP)
			switch {
			case err != nil:
			case ip.Unmap().Is6():
				v6++
			case a.Class == ClassPublic:
				public = true
			}
		}
		if public {
			byName++
		}
	}
	var out []NotCheckedRow
	if byName > 0 {
		out = append(out, NotCheckedRow{Kind: "by_name", Text: fmt.Sprintf(notByNameOnly, plural(byName, "name"))})
	}
	if v6 > 0 {
		out = append(out, NotCheckedRow{Kind: "address_family", Text: fmt.Sprintf(notIPv6, v6)})
	}
	return out
}
