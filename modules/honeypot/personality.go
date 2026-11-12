package honeypot

import (
	"encoding/binary"
	"net/netip"
	"regexp"
	"strings"
)

// personalities follows web/src/features/honeypot/personalities.ts: what the fake machine shows a scanner, and the
// device kinds of the inventory it blends in with (INV-11).
var personalities = []struct {
	id       Personality
	services []DecoyService
	kinds    []string
}{
	{WindowsFS, []DecoyService{{"SMB", 445}, {"RDP", 3389}}, []string{"server", "pc"}},
	{NAS, []DecoyService{{"HTTP login page", 80}, {"SMB", 445}}, []string{"nas"}},
	{Printer, []DecoyService{{"HTTP", 80}, {"Raw print", 9100}}, []string{"printer"}},
	{Camera, []DecoyService{{"HTTP", 80}, {"RTSP", 554}}, []string{"camera", "nvr"}},
	{Linux, []DecoyService{{"SSH", 22}}, []string{"server"}},
}

func personalityServices(p Personality) []DecoyService {
	for _, d := range personalities {
		if d.id == p {
			return append([]DecoyService{}, d.services...)
		}
	}
	return []DecoyService{}
}

func validPersonality(p Personality) bool {
	for _, d := range personalities {
		if d.id == p {
			return true
		}
	}
	return false
}

var (
	windowsRE = regexp.MustCompile(`(?i)windows`)
	linuxRE   = regexp.MustCompile(`(?i)linux|ubuntu|debian`)
)

func contains(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

func hasKind(kinds []string, k string) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}

// suggestions are the device types that really exist in the inventory, so a decoy of that type blends in (INV-11).
func suggestions(devices []Device) []DecoySuggestion {
	out := []DecoySuggestion{}
	for _, p := range personalities {
		var m []Device
		for _, d := range devices {
			var hit bool
			switch p.id {
			case WindowsFS:
				hit = d.Kind == "server" && (windowsRE.MatchString(d.OS) || contains(d.Ports, 445))
			case Linux:
				hit = d.Kind == "server" && linuxRE.MatchString(d.OS)
			default:
				hit = hasKind(p.kinds, d.Kind)
			}
			if hit {
				m = append(m, d)
			}
		}
		if len(m) == 0 {
			continue
		}
		s := DecoySuggestion{Personality: p.id, Count: len(m), Examples: []string{}}
		for _, d := range m[:min(3, len(m))] {
			s.Examples = append(s.Examples, d.Name)
		}
		out = append(out, s)
	}
	return out
}

// spareIPs are unused addresses near the top of the /24 of the box. ponytail: assumes a /24, a wider range still gets
// .230-.249 of its first block; the upgrade is to walk down from the broadcast address.
func spareIPs(w *world) []string {
	out := []string{}
	if !w.lan.IsValid() {
		return out
	}
	b := w.lan.Masked().Addr().As4()
	used := w.usedIPs()
	for i := 230; i < 250 && len(out) < 5; i++ {
		ip := netip.AddrFrom4([4]byte{b[0], b[1], b[2], byte(i)})
		if !used[ip] && usable(w.lan, ip) {
			out = append(out, ip.String())
		}
	}
	return out
}

// discovered says whether the inventory has a device (not the box) in the box's network: before that "unused" is a claim
// nobody checked.
func (w *world) discovered() bool {
	for _, d := range w.devices {
		if !d.IsBox && d.IP.IsValid() && w.lan.Contains(d.IP) {
			return true
		}
	}
	return false
}

// usable is true for an address inside the prefix that is neither its network nor its broadcast address.
func usable(p netip.Prefix, ip netip.Addr) bool {
	if !p.Contains(ip) || p.Bits() >= 31 {
		return false
	}
	return ip != p.Masked().Addr() && ip != lastAddr(p)
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	n := binary.BigEndian.Uint32(b[:]) | (uint32(1)<<(32-p.Bits()) - 1)
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

var (
	netbiosRE   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,13}[A-Za-z0-9])?$`)
	allDigitsRE = regexp.MustCompile(`^\d+$`)
	tokenNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$`)
)

func validHostname(s string) bool { return netbiosRE.MatchString(s) && !allDigitsRE.MatchString(s) }

func slug(name string) string {
	var b strings.Builder
	dash := true
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
