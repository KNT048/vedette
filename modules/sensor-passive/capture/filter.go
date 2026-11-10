package capture

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// matcher is the compiled form of the exclusion filters (D-56, INV-7).
type matcher struct {
	prefixes []netip.Prefix
	ports    [][2]uint16
}

// compileFilters turns the settings into a matcher. A filter that cannot be read is an error: capture does not
// start, because ignoring a rule would read traffic the admin asked not to read (fail closed).
func compileFilters(fs []Filter) (*matcher, error) {
	m := &matcher{}
	for _, f := range fs {
		switch f.Type {
		case "cidr":
			p, err := netip.ParsePrefix(f.Value)
			if err != nil || !p.Addr().Is4() {
				return nil, fmt.Errorf("capture: filter cidr %q: not an IPv4 range", f.Value)
			}
			m.prefixes = append(m.prefixes, p.Masked())
		case "host":
			a, err := netip.ParseAddr(f.Value)
			if err != nil || !a.Is4() {
				return nil, fmt.Errorf("capture: filter host %q: not an IPv4 address", f.Value)
			}
			m.prefixes = append(m.prefixes, netip.PrefixFrom(a, 32))
		case "port":
			lo, hi, ok := strings.Cut(f.Value, "-")
			if !ok {
				hi = lo
			}
			a, err1 := strconv.ParseUint(lo, 10, 16)
			b, err2 := strconv.ParseUint(hi, 10, 16)
			if err1 != nil || err2 != nil || a == 0 || b < a {
				return nil, fmt.Errorf("capture: filter port %q: want 1-65535 or a-b", f.Value)
			}
			m.ports = append(m.ports, [2]uint16{uint16(a), uint16(b)})
		default:
			return nil, fmt.Errorf("capture: filter type %q is unknown", f.Type)
		}
	}
	return m, nil
}

// hasPorts reports whether any port rule exists.
func (m *matcher) hasPorts() bool { return len(m.ports) > 0 }

// excludes reports whether traffic between src and dst (zero addresses and port 0 mean "not present") is
// excluded: either end in a listed range or host, or either port in a listed port.
func (m *matcher) excludes(src, dst netip.Addr, sport, dport uint16) bool {
	for _, p := range m.prefixes {
		if (src.IsValid() && p.Contains(src)) || (dst.IsValid() && p.Contains(dst)) {
			return true
		}
	}
	for _, r := range m.ports {
		if (sport != 0 && sport >= r[0] && sport <= r[1]) || (dport != 0 && dport >= r[0] && dport <= r[1]) {
			return true
		}
	}
	return false
}
