package exposure

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The surface of a verified domain (INV-27): every name with where it was found, its CNAME and each address with its kind.
// What serves a name (a CDN or the customer's own server) does not matter: the customer verified the domain. Until
// the deep scan of each name comes (after the fence), a name on another public address gets the check by
// name only, as before. With the domain's testing terms accepted, each public IPv4 address of its names gets
// the deep scan at the terms depth (deep.go), whatever serves it.

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
	// NotWordlistNoAnswer: the wildcard check got no clear answer, so the common names were not tried (a missed wildcard would list
	// every one of them).
	NotWordlistNoAnswer = "Common names (a list of about 150, such as vpn, mail and remote): not tried, because the wildcard check got no answer from the DNS resolver."
	// NotWordlistCut: some common names got no answer in the time the scan gives DNS lookups.
	NotWordlistCut = "Common names (a list of about 150, such as vpn, mail and remote): not all tried, because some lookups got no answer from the DNS resolver in time."
	// NotWordlistChosen: the scope is the names chosen, so the common names are not tried for the others.
	NotWordlistChosen = "Common names (a list of about 150, such as vpn, mail and remote): not tried, because this target scans only the names you chose; a name only that list finds is not listed. Scan it once with the scope \"every name found\" to list them."
	notIPv6           = "IPv6 addresses (%d listed): IPv6 is not scanned yet."
	notResolved       = "Names whose address lookup got no answer this time (%s): shown as the last scan found them."
	notByNameOnly     = "Names on public addresses that are not this box's (%s): checked by name on ports 80 and 443 only; accept this domain's testing terms (Ownership tab) for the deep scan of each address."
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
		row := HostIP{IP: ip.String(), Family: fam, Class: a.Class, Contacted: a.Contacted && ip.Is4() && a.Class != ClassPrivate}
		if slices.Contains(deepStates, a.Deep) && ip.Is4() { // What the deep scan did with the address this run
			row.Deep = a.Deep
			if a.Deep == DeepWaiting && a.NextInLine > 0 && a.NextInLine <= maxContentRows {
				row.NextInLine = a.NextInLine
			}
		}
		if at, err := time.Parse(time.RFC3339, a.LastDeep); err == nil && ip.Is4() {
			row.LastDeep = store.FormatTS(at)
		}
		if at, err := time.Parse(time.RFC3339, a.LastTried); err == nil && ip.Is4() {
			row.LastTried = store.FormatTS(at)
		}
		out.IPs = append(out.IPs, row)
	}
	return out
}

// unresolvedLine says, in "Not checked", how many names got no clear answer to their address lookup this time (INV-27): their rows
// keep what the scans before saw, and their addresses are not taken as checked.
func unresolvedLine(c Content) Content {
	if len(c.Unresolved) > 0 {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "lookup", Text: fmt.Sprintf(notResolved, plural(len(c.Unresolved), "name"))})
	}
	return c
}

// surfaceNotChecked is what a domain's surface did not scan: names on public IPv4 addresses that are not the box's (by name only, when
// the testing terms are not accepted: with them, deepDomain says what each address got), and IPv6 addresses. It reads the rows before
// they are limited (identify runs first), so the family comes from the address.
func surfaceNotChecked(hosts []HostRow, deep bool) []NotCheckedRow {
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
	if byName > 0 && !deep {
		out = append(out, NotCheckedRow{Kind: "by_name", Text: fmt.Sprintf(notByNameOnly, plural(byName, "name"))})
	}
	if v6 > 0 {
		out = append(out, NotCheckedRow{Kind: "address_family", Text: fmt.Sprintf(notIPv6, v6)})
	}
	return out
}
