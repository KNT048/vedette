package netguard

import (
	"net/netip"
	"slices"
)

// D-446: Vedette never connects to itself, and may connect to another program on the machine it runs on. Loopback, the addresses of
// core's own container and the honeypot's decoys are Vedette itself on every port; the machine's addresses only on Vedette's own ports.

// vedettePorts are the ports Vedette itself answers on at the machine's addresses: the interface 8443, the sensor link 8444, MCP 8765,
// syslog 514 and syslog over TLS 6514 (install.sh preflight, the core unit's PublishPort lines, the container-only compose).
var vedettePorts = []uint16{514, 6514, 8443, 8444, 8765}

// VedettePort reports whether port is one of Vedette's own ports.
func VedettePort(port uint16) bool { return slices.Contains(vedettePorts, port) }

// OwnText is the sentence for Vedette itself (D-446), the same in every module that refuses it.
const OwnText = "That address is Vedette itself: loopback, Vedette's own container, or one of its ports (8443, 8444, 8765, 514, 6514) on the machine that runs it. For another program on that machine, enter the machine's LAN address and that program's port."

// Own is what Vedette itself is, as a guard reads it at a check.
type Own struct {
	Machine []netip.Addr // the machine's addresses (vedette-host, the container's gateway, ...): refused on Vedette's own ports
	Known   bool         // false: the machine's addresses are not known yet, so Vedette's own ports are refused on every address
	Self    []netip.Addr // core's own container addresses and the honeypot's decoys: refused on every port
}

// Refuses reports whether a at port is Vedette itself, in any of its Forms: loopback (unless allowLoopback, a test seam), one of
// o.Self on every port, or one of o.Machine on one of Vedette's own ports (every address while o.Known is false).
func (o Own) Refuses(a netip.Addr, port uint16, allowLoopback bool) bool {
	vport := VedettePort(port)
	if vport && !o.Known {
		return true
	}
	in := func(l []netip.Addr, f netip.Addr) bool {
		return slices.ContainsFunc(l, func(x netip.Addr) bool { return x.Unmap().WithZone("") == f })
	}
	for _, f := range Forms(a) {
		switch {
		case f.IsLoopback():
			if !allowLoopback {
				return true
			}
		case in(o.Self, f), vport && in(o.Machine, f):
			return true
		}
	}
	return false
}
