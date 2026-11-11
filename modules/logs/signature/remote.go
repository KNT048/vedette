package signature

import (
	"net/netip"
	"strings"
)

// The remote address of a line (D-210): the peer that the line is about (the client of a failed login, the source of a blocked
// connection), never the device that sent the log. A profile names where it is (remote_fields, remote_patterns); every line that
// the profile does not settle, and every line of a device without a profile, goes through genericRemote. An address is read with
// net/netip only: what does not parse is no address, and the line still counts everywhere else. The result is unmapped (no IPv4-in-IPv6),
// has no zone, and is Countable.

// maxAddrText is the longest text ParseAddr looks at (the longest IPv6 text with a zone and a port is under 64 bytes).
const maxAddrText = 96

// maxRemoteWords is how many words genericRemote looks at in one line.
const maxRemoteWords = 400

// Countable says whether an address can be the remote peer of a line that a counter keeps: not the unspecified address, not loopback,
// not multicast, not link-local, not the IPv4 broadcast. A private LAN address is countable (an internal brute-forcer is real).
func Countable(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast() &&
		!a.IsLinkLocalMulticast() && !a.IsInterfaceLocalMulticast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// ParseAddr reads an address out of the text a device wrote for it: a plain address, "addr:port" (IPv4), "[addr]:port", "name[addr]"
// (postfix), "https(addr)" (FortiGate), "[AF_INET]addr:port" (OpenVPN), with quotes, angle brackets, a trailing comma or colon, an
// IPv6 zone, or an IPv4-mapped IPv6 form. It returns the address unmapped and without a zone. Anything else is not an address (false).
func ParseAddr(s string) (netip.Addr, bool) {
	if s == "" || len(s) > maxAddrText {
		return netip.Addr{}, false
	}
	s = strings.Trim(s, "\"'<>,; \t")
	if i := strings.IndexByte(s, '['); i >= 0 {
		j := strings.IndexByte(s[i:], ']')
		if j < 0 {
			return netip.Addr{}, false
		}
		if a, ok := parseBare(s[i+1 : i+j]); ok {
			return a, true
		}
		return parseBare(s[i+j+1:]) // "[AF_INET]1.2.3.4:5555"
	}
	if i := strings.IndexByte(s, '('); i >= 0 && strings.HasSuffix(s, ")") { // "https(1.2.3.4)"
		s = s[i+1 : len(s)-1]
	}
	return parseBare(s)
}

// parseBare reads "addr", "addr%zone" or "addr:port" (IPv4 only: an IPv6 text with a colon is read as an address). A trailing
// separator ("1.2.3.4:", "1.2.3.4,") is dropped only when the text as it is does not parse ("2001:db8::" is an address).
func parseBare(s string) (netip.Addr, bool) {
	if a, ok := parseOne(s); ok {
		return a, true
	}
	return parseOne(strings.TrimRight(s, ":.,;)"))
}

func parseOne(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		if strings.IndexByte(s, '.') < 0 || strings.Count(s, ":") != 1 {
			return netip.Addr{}, false
		}
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return netip.Addr{}, false
		}
		a = ap.Addr()
	}
	return a.Unmap().WithZone(""), true
}

// remoteKeys are the keys (compared in lower case) whose value is the address of the peer: PAM rhost, dovecot rip, postfix client,
// iptables SRC, FortiGate remip and srcip, and the usual spellings of remote and client address.
var remoteKeys = set("rhost", "rip", "remip", "remote", "remote_ip", "remote_addr", "remoteaddr", "remote_address", "client", "client_ip", "clientip",
	"client_addr", "src", "srcip", "src_ip", "source_ip", "sourceip", "source_address", "saddr", "peer", "peer_ip", "ipaddress", "ip_address", "ip")

// genericRemote finds the peer address of a line that no profile settled (D-210, round 3). It is a POSITIONAL ALLOWLIST: an address is
// read only from a position where a daemon puts its peer, and any other address-shaped word makes the line ambiguous, so it has none:
//
//	(a) the first word of the message (after a "tag:" word) when the line is an access-log line (ADDR ident user [date] ...): nginx, apache;
//	(b) sshd "from ADDR port N", "by ADDR port N" and "user NAME ADDR port N": the address is directly followed by " port <digits>";
//	(c) apache error "[client ADDR]" and "[client ADDR:port]";
//	(d) key=value with a key of remoteKeys (rhost, rip, client, src ...): the value is a site even when it is empty or "-".
//
// A line yields an address only when it has such sites, every site is the same countable address, and no other word of the line is an
// address (quoted or not, in JSON, after "user", in a URI). Words inside a double-quoted span, or that open a quoted span with " or ', are
// text the client controls and are never a site; an odd number of unescaped double quotes gives none. Missing data beats a framed address:
// TopAddresses feeds automatic bans (fail2ban CVE-2007-4321, DenyHosts CVE-2007-4323). It does not use regular expressions.
func genericRemote(msg string) netip.Addr {
	if unbalancedQuotes(msg) {
		return netip.Addr{}
	}
	words := splitWords(msg)
	first := 0
	if len(words) > 0 && strings.HasSuffix(words[0], ":") {
		first = 1
	}
	var sites []string
	stray := false
	inQuote := false
	prev, prev2 := "", ""
	for n, w := range words {
		if w == "" {
			prev, prev2 = "", ""
			continue
		}
		quoted := inQuote || w[0] == '"' || w[0] == '\''
		for k := 0; k < len(w); k++ {
			if w[k] == '"' && (k == 0 || w[k-1] != '\\') {
				inQuote = !inQuote
			}
		}
		site := false
		if !quoted {
			eq := strings.IndexByte(w, '=')
			switch {
			case eq > 0 && eq < 24:
				if remoteKeys[lowerKey(w[:eq])] {
					sites, site = append(sites, w[eq+1:]), true
				}
			case n == first && accessLog(words[n:]):
				sites, site = append(sites, w), true
			case (prev == "from" || prev == "by") && portFollows(words, n+1), prev2 == "user" && portFollows(words, n+1):
				sites, site = append(sites, w), true
			case prev == "[client":
				sites, site = append(sites, strings.TrimSuffix(w, "]")), true
			}
		}
		if !site {
			if a, ok := ParseAddr(w); ok && Countable(a) {
				stray = true
			}
		}
		prev2, prev = prev, lowerKey(strings.TrimRight(w, ":"))
	}
	if stray || len(sites) == 0 {
		return netip.Addr{}
	}
	var found netip.Addr
	for _, v := range sites {
		a, ok := ParseAddr(v)
		if !ok || !Countable(a) || found.IsValid() && found != a {
			return netip.Addr{}
		}
		found = a
	}
	return found
}

// splitWords cuts the line at spaces and tabs into at most maxRemoteWords words; a word that is too long to be an address is "" (it keeps
// its position).
func splitWords(msg string) []string {
	var out []string
	for i := 0; i < len(msg) && len(out) < maxRemoteWords; {
		if msg[i] == ' ' || msg[i] == '\t' {
			i++
			continue
		}
		j := i
		for j < len(msg) && msg[j] != ' ' && msg[j] != '\t' {
			j++
		}
		if j-i > maxAddrText+24 {
			out = append(out, "")
		} else {
			out = append(out, msg[i:j])
		}
		i = j
	}
	return out
}

// portFollows says whether the words from i are "port <digits>".
func portFollows(words []string, i int) bool {
	if i+1 >= len(words) || words[i] != "port" || words[i+1] == "" {
		return false
	}
	for _, c := range words[i+1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// accessLog says whether the words are the start of a common or combined access-log line: ADDR ident user [date.
func accessLog(w []string) bool { return len(w) >= 4 && strings.HasPrefix(w[3], "[") }

// unbalancedQuotes says whether the line has an odd number of unescaped double quotes: then no quoted span can be told from text.
func unbalancedQuotes(msg string) bool {
	odd := false
	for k := 0; k < len(msg); k++ {
		if msg[k] == '"' && (k == 0 || msg[k-1] != '\\') {
			odd = !odd
		}
	}
	return odd
}

// lowerKey lower-cases a short ASCII word without allocating when it is already lower case.
func lowerKey(w string) string {
	if len(w) > 32 {
		return ""
	}
	for i := 0; i < len(w); i++ {
		if c := w[i]; c >= 'A' && c <= 'Z' {
			var b [32]byte
			n := copy(b[:], w)
			for k := 0; k < n; k++ {
				if b[k] >= 'A' && b[k] <= 'Z' {
					b[k] += 'a' - 'A'
				}
			}
			return string(b[:n])
		}
	}
	return w
}
