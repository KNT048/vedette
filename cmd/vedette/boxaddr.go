package main

import (
	"net/netip"

	"github.com/knt048/vedette/host/api"
)

// boxCardIPv4 is the IPv4 address of the card named by core's management-card rule (core NetworkHandlers.ManagementCard), taken
// from the host state. "" when the card has no usable address (S-INV-1: the box's own device row shows this address, never a
// container's).
func boxCardIPv4(st api.NetState, card string) string {
	for _, i := range st.Interfaces {
		if i.Name != card {
			continue
		}
		for _, s := range i.Addresses {
			if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() && !p.Addr().IsLinkLocalUnicast() && !p.Addr().IsLoopback() {
				return p.Addr().String()
			}
		}
	}
	return ""
}
