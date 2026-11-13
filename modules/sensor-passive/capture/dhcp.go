package capture

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

const maxDHCP = 2048 // bytes read from one DHCP message

type dhcpMessage struct {
	op          byte // 1 client to server, 2 server to client
	msgType     byte // option 53; 0 when absent
	clientMAC   mac  // chaddr
	clientIP    netip.Addr
	yourIP      netip.Addr // yiaddr: the address a server hands out
	requestedIP netip.Addr // option 50
	hostname    string     // option 12, only when it is a valid host name
	vendorClass string     // option 60, printable text
	clientID    []byte     // option 61
}

// parseDHCP reads a BOOTP/DHCP message for Ethernet clients. Options that do not fit are an error; an option
// value that is not usable (a hostname with odd characters) is left empty.
func parseDHCP(b []byte) (dhcpMessage, error) {
	if len(b) < 240 || len(b) > maxDHCP {
		return dhcpMessage{}, malformed("dhcp: size")
	}
	if b[0] != 1 && b[0] != 2 {
		return dhcpMessage{}, malformed("dhcp: op")
	}
	if b[1] != 1 || b[2] != 6 {
		return dhcpMessage{}, malformed("dhcp: not an Ethernet client")
	}
	if binary.BigEndian.Uint32(b[236:240]) != 0x63825363 {
		return dhcpMessage{}, malformed("dhcp: magic cookie")
	}
	m := dhcpMessage{op: b[0]}
	copy(m.clientMAC[:], b[28:34])
	if ip := netip.AddrFrom4([4]byte(b[12:16])); !ip.IsUnspecified() {
		m.clientIP = ip
	}
	if ip := netip.AddrFrom4([4]byte(b[16:20])); !ip.IsUnspecified() {
		m.yourIP = ip
	}
	opts := b[240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			return dhcpMessage{}, malformed("dhcp: option length missing")
		}
		n := int(opts[i+1])
		if i+2+n > len(opts) {
			return dhcpMessage{}, malformed("dhcp: option overruns the message")
		}
		v := opts[i+2 : i+2+n]
		switch code {
		case 12:
			if s := trimNUL(string(v)); hostnameOK(s) {
				m.hostname = s
			}
		case 50:
			if n == 4 {
				m.requestedIP = netip.AddrFrom4([4]byte(v))
			}
		case 53:
			if n == 1 {
				m.msgType = v[0]
			}
		case 60:
			if s, ok := cleanText(string(v), 200); ok {
				m.vendorClass = s
			}
		case 61:
			if n >= 2 && n <= 64 {
				m.clientID = append([]byte(nil), v...)
			}
		}
		i += 2 + n
	}
	return m, nil
}

// dhcpOS reads the OS family from the vendor class (option 60) of a DHCP client whose format is known (D-501): Windows ("MSFT 5.0"),
// Android ("android-dhcp-13"), dhcpcd ("dhcpcd-9.4.1:Linux-6.1.21:aarch64:..."), BusyBox udhcpc ("udhcp 1.36.1"). Option 60 names
// the DHCP client, so it says the operating system, not who made the device or which version runs: a hint, never a version to
// match. Anything else gives "".
func dhcpOS(vc string) string {
	switch {
	case strings.HasPrefix(vc, "MSFT "):
		return "Microsoft Windows"
	case strings.HasPrefix(vc, "android-dhcp-"):
		if n := strings.TrimPrefix(vc, "android-dhcp-"); n != "" && len(n) <= 3 && strings.Trim(n, "0123456789") == "" {
			return "Android " + n
		}
		return "Android"
	case strings.HasPrefix(vc, "dhcpcd-"):
		_, rest, _ := strings.Cut(vc, ":")
		switch name, _, _ := strings.Cut(rest, "-"); name {
		case "Linux", "NetBSD", "FreeBSD", "OpenBSD", "DragonFly":
			return name
		}
	case strings.HasPrefix(vc, "udhcp "):
		return "Linux (BusyBox)"
	}
	return ""
}

// trimNUL drops the trailing NULs some clients add to option 12.
func trimNUL(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}
