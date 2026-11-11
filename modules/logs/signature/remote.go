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

// remoteWords are the words after which a peer address comes: sshd "from 1.2.3.4", "closed by 1.2.3.4".
var remoteWords = set("from", "by")

// genericRemote finds the peer address of a line that no profile settled, by the layouts that daemons share: key=value with a key of
// remoteKeys, the word after "from" or "by", host[addr] (postfix) and name/addr:port (OpenVPN). The first countable address, left to
// right, wins. It does not use regular expressions (it runs on every line of a device without a profile).
func genericRemote(msg string) netip.Addr {
	prev := ""
	words := 0
	for i := 0; i < len(msg) && words < maxRemoteWords; {
		if msg[i] == ' ' || msg[i] == '\t' {
			i++
			continue
		}
		j := i
		for j < len(msg) && msg[j] != ' ' && msg[j] != '\t' {
			j++
		}
		w := msg[i:j]
		i = j
		words++
		if len(w) > maxAddrText+24 {
			prev = ""
			continue
		}
		var cand string
		switch eq := strings.IndexByte(w, '='); {
		case eq > 0 && eq < 24:
			if remoteKeys[lowerKey(w[:eq])] {
				cand = w[eq+1:]
			}
		case remoteWords[prev]:
			cand = w
		case strings.IndexByte(w, '[') > 0 && strings.IndexByte(w, ']') > 0: // unknown[1.2.3.4]:
			cand = w
		case strings.IndexByte(w, '/') > 0: // bob/1.2.3.4:5555
			cand = w[strings.LastIndexByte(w, '/')+1:]
		}
		if cand != "" {
			if a, ok := ParseAddr(cand); ok && Countable(a) {
				return a
			}
		}
		prev = lowerKey(strings.TrimRight(w, ":"))
	}
	return netip.Addr{}
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
