package main

import (
	"net/netip"

	"github.com/knt048/vedette/host/api"
)

// boxManagementIPv4 is the IPv4 address of the box's management card, picked as Box network picks that card (modules/core
// mgmtIface): the configured card, else the host's management role, else the card of the default route. "" when none has a usable
// address (S-INV-1: the box's own device row shows this address, never a container's).
func boxManagementIPv4(st api.NetState) string {
	name := ""
	switch {
	case st.Config.Mgmt != nil && st.Config.Mgmt.Iface != "":
		name = st.Config.Mgmt.Iface
	default:
		for _, i := range st.Interfaces {
			if i.Role == api.NetRoleManagement {
				name = i.Name
				break
			}
		}
		if name == "" && st.DefaultRoute != nil {
			name = st.DefaultRoute.Iface
		}
	}
	for _, i := range st.Interfaces {
		if i.Name != name {
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
