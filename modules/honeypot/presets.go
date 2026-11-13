package honeypot

import (
	"encoding/binary"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// presets follows web/src/features/honeypot/presets.ts (D-466): what a Trap IP of each kind answers on, the vendor whose MAC
// prefix it gets, the device kinds of the inventory it blends in with (INV-11) and the example name the messages give. Data, so
// a service B3 adds is a row here, not a new screen.
type presetDef struct {
	id       Preset
	services []ServiceName
	vendor   string
	kinds    []string
	example  string
}

var presets = []presetDef{
	{FileServer, []ServiceName{SMB, RDP}, "dell", []string{"server", "pc"}, "FILESRV-OLD"},
	{NAS, []ServiceName{HTTP, SMB}, "synology", []string{"nas"}, "NAS-ARCHIVE"},
	{Printer, []ServiceName{HTTP}, "hp", []string{"printer"}, "PRN-FLOOR2"},
	{Camera, []ServiceName{HTTP}, "hikvision", []string{"camera", "nvr"}, "CAM-STORE-04"},
	{Linux, []ServiceName{SSH}, "vmware", []string{"server"}, "BUILD-SRV-02"},
	{Database, []ServiceName{MSSQL}, "dell", []string{"server"}, "SQL-OLD-01"},
	{Custom, nil, "", nil, "TRAP-01"},
}

// vendors are the MAC prefixes a Trap IP may carry (IEEE OUIs, six hex digits; TestVendorOUIsBelongToTheVendor checks each
// against the D-83 table). The host makes the MAC from the prefix and three bytes of its own key (host-api 6.6).
var vendors = []struct{ id, oui, name string }{
	{"dell", "f8bc12", "Dell"}, {"hp", "3cd92b", "Hewlett Packard"}, {"vmware", "005056", "VMware"}, {"hyperv", "00155d", "Microsoft"},
	{"supermicro", "0cc47a", "Super Micro"}, {"synology", "001132", "Synology"}, {"qnap", "245ebe", "QNAP"}, {"brother", "30055c", "Brother"},
	{"canon", "001e8f", "CANON"}, {"hikvision", "4419b6", "Hikvision"}, {"dahua", "3cef8c", "Dahua"}, {"axis", "accc8e", "Axis"},
}

func validPreset(p Preset) bool {
	return slices.ContainsFunc(presets, func(x presetDef) bool { return x.id == p })
}

// presetExample is the example name of a preset, for the messages.
func presetExample(p Preset) string {
	for _, x := range presets {
		if x.id == p {
			return x.example
		}
	}
	return "FILESRV-OLD"
}

// vendorOUI is the six hex digits of a vendor's MAC prefix; ok is false for an unknown vendor.
func vendorOUI(id string) (string, bool) {
	for _, v := range vendors {
		if v.id == id {
			return v.oui, true
		}
	}
	return "", false
}

// ports are what the host lets the address answer on: the fixed TCP port of each service (INV-2).
func ports(services []ServiceName) []Port {
	out := make([]Port, 0, len(services))
	for _, s := range services {
		out = append(out, Port{Proto: "tcp", Port: s.Port()})
	}
	return out
}

// inOrder returns the services in the order of Services, each once, unknown names dropped.
func inOrder(l []ServiceName) []ServiceName {
	out := []ServiceName{}
	for _, s := range Services {
		if slices.Contains(l, s) {
			out = append(out, s)
		}
	}
	return out
}

var (
	windowsRE = regexp.MustCompile(`(?i)windows`)
	linuxRE   = regexp.MustCompile(`(?i)linux|ubuntu|debian`)
)

// suggestions are the device types that really exist in the inventory, so a Trap IP of that type blends in (INV-11).
func suggestions(devices []Device) []TrapSuggestion {
	out := []TrapSuggestion{}
	for _, p := range presets {
		if p.id == Custom {
			continue
		}
		var m []Device
		for _, d := range devices {
			var hit bool
			switch p.id {
			case FileServer:
				hit = d.Kind == "server" && (windowsRE.MatchString(d.OS) || slices.Contains(d.Ports, 445))
			case Linux:
				hit = d.Kind == "server" && linuxRE.MatchString(d.OS)
			case Database:
				hit = d.Kind == "server" && slices.Contains(d.Ports, 1433)
			default:
				hit = slices.Contains(p.kinds, d.Kind)
			}
			if hit {
				m = append(m, d)
			}
		}
		if len(m) == 0 {
			continue
		}
		s := TrapSuggestion{Preset: p.id, Count: len(m), Examples: []string{}}
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
