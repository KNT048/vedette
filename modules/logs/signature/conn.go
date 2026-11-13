package signature

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/localnet"
)

// The connection a line is about (L4, D-213): the LAN device that made it and what it connected to (a public address, and for a DNS
// or web-filter line the name it asked for), read only from the fields a device's format names (local_field, dest_ip_field,
// dest_host_fields of a key=value profile, conn_pattern of a template profile). The same anti-framing rule as the remote address
// (D-210) and stricter: a field counts only when it is written exactly ONCE as a key=value site outside quoted text, whatever the
// values; two sites (the same value or not), a double quote that is not a value's own, or more pairs than the scan looks at make the
// whole line a line without a connection. There is no free-text reader: a line of a device without a profile, and a line the profile
// does not settle, has none. Missing data beats a false hit, because a hit tells a person that a device on their network talked to a
// criminal, and opens an incident and may drive a response. Addresses are read with net/netip only, on the text as it is (no
// trimming of quotes or brackets), and names are lower-cased ASCII under a strict pattern.

// Destination kinds.
const (
	KindIP     = "ip"
	KindDomain = "domain"
)

// MaxDests is how many destinations one line yields (an address and a name).
const MaxDests = 2

// Dest is one destination of a line: an address (canonical text) or a domain name (lower case, no trailing dot).
type Dest struct{ Kind, Value string }

// Conn is a connection a line is about: a LAN device (private IPv4) and where it went. The zero Conn (Local not valid) is no connection.
// Blocked says that the device that logged it stopped it (the profile's conn_blocked, D-227): the line records an attempt. False when the
// format does not say so, which is read as a connection that went through.
type Conn struct {
	Local   netip.Addr
	Dests   []Dest
	Blocked bool
}

// LocalOK says whether an address can be the LAN device of a connection: an IPv4 address of a local network (RFC 1918, or the RFC 6598
// shared space 100.64/10 that a network watched by Vedette may use, localnet.Addr, D-461). The destination rule (PublicDest) is not
// changed: a 100.64/10 destination is never looked up.
func LocalOK(a netip.Addr) bool { return a.IsValid() && localnet.Addr(a) }

var specialNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "100::/64", "2001:db8::/32", "2001::/23", "2002::/16", // NAT64, discard, documentation, IETF protocol assignments, 6to4
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// PublicDest says whether an address is one a feed can list: not private, loopback, link-local, multicast, unspecified, broadcast,
// carrier-grade NAT, documentation, benchmarking, reserved or an IPv4-in-IPv6 form.
func PublicDest(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsPrivate() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range specialNets {
		if p.Contains(a) {
			return false
		}
	}
	return a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// CleanDomain returns the lower-case form of a domain name that a device wrote, or false: at most 253 bytes, at least two labels of 1 to 63
// characters from a-z, 0-9 and "-" (not at the start or end; a name with a non-ASCII letter is refused, an IDN is written in its xn-- form by
// the resolvers and the firewalls), one trailing dot allowed, and a last label that is not all digits (so an address is never a name).
func CleanDomain(s string) (string, bool) {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	s = strings.ToLower(s) // ASCII only after the checks below; ToLower of a non-ASCII letter is refused there
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	last := labels[len(labels)-1]
	if allDigits(last) {
		return "", false
	}
	return s, true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

// strictFields reads the key=value pairs of a line and returns the value of each wanted key that is written exactly once. ok is false (and
// no value is to be trusted) when a wanted key is written twice, when a double quote is anywhere but around a value ("key=\"value\"",
// the closing quote followed by a space or the end), when a quote is not closed, or when the line has more pairs than the scan reads.
func strictFields(s string, want map[string]bool) (vals map[string]string, ok bool) {
	vals = map[string]string{}
	pairs := 0
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' {
			i++
			continue
		}
		j := i
		for j < len(s) && isKeyByte(s[j]) {
			j++
		}
		if j == i || j >= len(s) || s[j] != '=' { // not a pair: a word, which may not hold a quote
			for j < len(s) && s[j] != ' ' && s[j] != '\t' {
				if s[j] == '"' {
					return nil, false
				}
				j++
			}
			if j == i {
				j++
			}
			i = j
			continue
		}
		if pairs++; pairs > maxPairs {
			return nil, false
		}
		key := s[i:j]
		j++
		var val string
		if j < len(s) && s[j] == '"' {
			k := j + 1
			for k < len(s) && s[k] != '"' {
				if s[k] == '\\' {
					k++
				}
				k++
			}
			if k >= len(s) || k+1 < len(s) && s[k+1] != ' ' && s[k+1] != '\t' { // not closed, or text glued to the closing quote
				return nil, false
			}
			val, j = s[j+1:k], k+1
		} else {
			k := j
			for k < len(s) && s[k] != ' ' && s[k] != '\t' {
				if s[k] == '"' {
					return nil, false
				}
				k++
			}
			val, j = s[j:k], k
		}
		if want[key] {
			if _, seen := vals[key]; seen {
				return nil, false
			}
			vals[key] = val
		}
		i = j
	}
	return vals, true
}

// connByFields reads the connection of a key=value line: the local device, then the destination address and the names. A line with no
// local device, or with none of the destination fields, has no connection; a field that is present and not what it should be (a private
// destination, a name that is not a name) gives no destination of that field and does not stop the others.
func (p *profile) connByFields(msg string) Conn {
	vals, ok := strictFields(msg, p.connWanted)
	if !ok {
		return Conn{}
	}
	for k, allowed := range p.Rule.ConnWhen {
		if v, has := vals[k]; !has || !slices.Contains(allowed, v) {
			return Conn{}
		}
	}
	local, err := netip.ParseAddr(vals[p.Rule.LocalField])
	if err != nil || !LocalOK(local) {
		return Conn{}
	}
	c := Conn{Local: local}
	if v, has := vals[p.Rule.DestIPField]; has && p.Rule.DestIPField != "" {
		if a, err := netip.ParseAddr(v); err == nil && PublicDest(a) {
			c.Dests = append(c.Dests, Dest{KindIP, a.String()})
		}
	}
	for _, k := range p.Rule.DestHostFields {
		if v, has := vals[k]; has {
			if d, ok := CleanDomain(v); ok && len(c.Dests) < MaxDests {
				c.Dests = append(c.Dests, Dest{KindDomain, d})
			}
		}
	}
	if len(c.Dests) == 0 {
		return Conn{}
	}
	c.Blocked = len(p.Rule.ConnBlocked) > 0
	for k, blocked := range p.Rule.ConnBlocked {
		if v, has := vals[k]; !has || !slices.Contains(blocked, v) {
			c.Blocked = false
		}
	}
	return c
}

// connByPattern reads the connection of a template line. The anchored conn_patterns come first (the first that matches, exactly once, is the
// connection and says whether it was blocked); then the conn_pattern ("local" and "dest" are addresses): exactly one match, exactly one "->"
// in the line and no odd quote, or no connection.
func (p *profile) connByPattern(msg string) Conn {
	if p.connRefuse != nil && p.connRefuse.MatchString(msg) {
		return Conn{}
	}
	for _, cp := range p.connPats {
		m := cp.re.FindAllStringSubmatch(msg, 2)
		if len(m) == 0 {
			continue
		}
		if len(m) != 1 {
			return Conn{}
		}
		return connFrom(cp.re, m[0], cp.blocked)
	}
	if p.conn == nil || strings.Count(msg, "->") != 1 || unbalancedQuotes(msg) {
		return Conn{}
	}
	m := p.conn.FindAllStringSubmatch(msg, 2)
	if len(m) != 1 {
		return Conn{}
	}
	return connFrom(p.conn, m[0], false)
}

func connFrom(re *regexp.Regexp, m []string, blocked bool) Conn {
	local, err1 := netip.ParseAddr(m[re.SubexpIndex("local")])
	dest, err2 := netip.ParseAddr(m[re.SubexpIndex("dest")])
	if err1 != nil || err2 != nil || !LocalOK(local) || !PublicDest(dest) {
		return Conn{}
	}
	return Conn{Local: local, Dests: []Dest{{KindIP, dest.String()}}, Blocked: blocked}
}
