package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/inventory"
)

// The mitigation-config answer writes a firewall rule per firewall it is given. A rule on a firewall that traffic to the device never
// crosses protects nothing and reads as if it did, so the AI is given the firewalls on the device's path, as far as the box knows it:
// the subnets of the box's own cards and its default gateways (vedette-host state/net). A device on a subnet of the box reaches other
// networks through the gateway of that subnet; a device on no subnet of the box is reached through the box's default gateway.

// aiNet is the box's own network as vedette-host reports it. known is false when there is no host or it did not answer.
type aiNet struct {
	known    bool
	subnets  []netip.Prefix // masked; no single-address, link-local or loopback prefixes
	gateways []netip.Addr   // the default gateways (IPv4 and IPv6 next hops), no zone
}

// aiNetOf reads the subnets and default gateways out of a state/net answer.
func aiNetOf(st api.NetState) aiNet {
	n := aiNet{known: true}
	for _, i := range st.Interfaces {
		for _, s := range i.Addresses {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil || p.IsSingleIP() || p.Addr().Is4In6() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsLoopback() {
				continue
			}
			n.subnets = append(n.subnets, netip.PrefixFrom(p.Addr().WithZone(""), p.Bits()).Masked())
		}
	}
	add := func(s string) {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && !a.IsUnspecified() && !a.IsLinkLocalUnicast() {
			n.gateways = append(n.gateways, a.Unmap().WithZone(""))
		}
	}
	if st.DefaultRoute != nil {
		add(st.DefaultRoute.Gateway)
	}
	for _, r := range st.DefaultRoutes6 {
		add(r.Gateway)
	}
	return n
}

// aiPath is what the box knows of a firewall's place on the way to a device.
type aiPath int

const (
	pathUnknown      aiPath = iota // no known path: not a gateway of the device's network, not on its subnet
	pathSameSubnet                 // on the device's own subnet but not the box's gateway: it may be the device's gateway
	pathGatewayOther               // the box's default gateway, and the device is on no subnet of the box: traffic to it passes there
	pathGateway                    // the default gateway of the device's own subnet
)

// onPath: the firewall is on a path the box knows.
func (p aiPath) onPath() bool { return p == pathGateway || p == pathGatewayOther }

// label is the path as the AI reads it.
func (p aiPath) label() string {
	switch p {
	case pathGateway:
		return "path: the default gateway of this device's network"
	case pathGatewayOther:
		return "path: the box's default gateway; this device is on another network, so traffic from the box's network to it passes here"
	case pathSameSubnet:
		return "path: on this device's own network, not its known gateway; it may be the device's gateway"
	}
	return "path to this device: not known"
}

// subnetOf is the box's subnet that holds a, if any (the longest one).
func (n aiNet) subnetOf(a netip.Addr) (netip.Prefix, bool) {
	var best netip.Prefix
	for _, p := range n.subnets {
		if p.Contains(a) && (!best.IsValid() || p.Bits() > best.Bits()) {
			best = p
		}
	}
	return best, best.IsValid()
}

// deviceGateway is the gateway the device's traffic to other networks passes: the box's default gateway on the device's subnet, or
// for a device on no subnet of the box the box's default gateway of the same address family. Invalid when the box knows none.
func (n aiNet) deviceGateway(dev netip.Addr) netip.Addr {
	sub, onBox := n.subnetOf(dev)
	for _, g := range n.gateways {
		if onBox && sub.Contains(g) || !onBox && g.Is4() == dev.Is4() {
			return g
		}
	}
	return netip.Addr{}
}

// path is where a firewall at fw stands on the way to a device at dev.
func (n aiNet) path(dev, fw netip.Addr) aiPath {
	if !n.known || !dev.IsValid() || !fw.IsValid() {
		return pathUnknown
	}
	if g := n.deviceGateway(dev); g.IsValid() && g == fw {
		if _, onBox := n.subnetOf(dev); onBox {
			return pathGateway
		}
		return pathGatewayOther
	}
	if sub, ok := n.subnetOf(dev); ok && sub.Contains(fw) {
		return pathSameSubnet
	}
	return pathUnknown
}

// aiFirewalls is what the config skill is told about the firewalls and routers of the inventory for one device. Walls (with the path
// of each in Paths) are the ones a rule may be written for. OnPath: they are on the device's path; else a rule for one of them is an
// assumption, and Why says why the path is not known. Others counts the firewalls and routers left out because they are not on the
// device's path. Gateway is the device's gateway when the box knows its address but it is not a firewall or router of the inventory.
type aiFirewalls struct {
	Walls   []inventory.Device
	Paths   []aiPath
	OnPath  bool
	Why     string
	Others  int
	Gateway netip.Addr
}

// aiPickWalls chooses, from the firewalls and routers of the inventory, the ones the AI may write a rule for (their ids, at most
// aiMaxFirewalls, in the inventory's order), for the device devID at devIP. The device itself is left out: its own block covers it.
// The firewalls on its path, when the box knows any; else the ones on its own subnet, as an assumption; else none, with the gateway
// the box knows. When the box does not know its own network, every firewall, as an assumption.
func aiPickWalls(n aiNet, devID, devIP string, all []inventory.KindDevice) (ids []string, sel aiFirewalls) {
	dev, _ := netip.ParseAddr(devIP)
	dev = dev.Unmap().WithZone("")
	var cands []inventory.KindDevice
	for _, k := range all {
		if k.ID != devID {
			cands = append(cands, k)
		}
	}
	paths := make([]aiPath, len(cands))
	best := pathUnknown
	for i, k := range cands {
		fw, _ := netip.ParseAddr(k.IP)
		paths[i] = n.path(dev, fw.Unmap().WithZone(""))
		best = max(best, paths[i])
	}
	take := func(keep func(aiPath) bool) {
		for i, k := range cands {
			if !keep(paths[i]) {
				sel.Others++
				continue
			}
			if len(ids) < aiMaxFirewalls {
				ids = append(ids, k.ID)
				sel.Paths = append(sel.Paths, paths[i])
			}
		}
	}
	switch {
	case !n.known:
		sel.Why = "Vedette cannot read the box's own network here, so it does not know which firewall traffic to this device passes"
		take(func(aiPath) bool { return true })
	case !dev.IsValid():
		sel.Why = "Vedette knows no IP address of this device"
		take(func(aiPath) bool { return true })
	case best.onPath():
		sel.OnPath = true
		take(aiPath.onPath)
	case best == pathSameSubnet:
		sel.Why = "none of them is the box's gateway for this device's network; these are on the device's own subnet and may be its gateway"
		take(func(p aiPath) bool { return p == pathSameSubnet })
	default:
		if g := n.deviceGateway(dev); g != dev { // a gateway's own finding: it is the device, not a firewall in front of it
			sel.Gateway = g
		}
		take(func(aiPath) bool { return false })
	}
	return ids, sel
}

// aiNetReader reads the box's network for the config skill: nil without a host.
func aiNetReader(r netStateReader) func(context.Context) aiNet {
	if r == nil {
		return nil
	}
	return func(ctx context.Context) aiNet {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		st, err := r.StateNet(ctx)
		if err != nil {
			return aiNet{}
		}
		return aiNetOf(st)
	}
}

// aiNetworkBlock is the text of the network block: the firewalls a rule may be written for, each with its place on the path, and
// what was left out.
func aiNetworkBlock(f aiFirewalls) string {
	var b strings.Builder
	list := func() {
		for i, w := range f.Walls {
			fmt.Fprintf(&b, "- %s, IP %s, kind %s; %s; %s\n", aiName(w), aiIP(w.IP), aiVal(w.Kind, 30), aiWallFacts(w), f.Paths[i].label())
		}
	}
	switch {
	case len(f.Walls) > 0 && f.OnPath:
		b.WriteString("Firewalls and routers on this device's path (write a firewall rule only for these):\n")
		list()
	case len(f.Walls) > 0:
		fmt.Fprintf(&b, "Vedette does not know which firewall is on this device's path: %s. Firewalls and routers in the inventory (a rule for one of them is an assumption):\n", f.Why)
		list()
	case f.Others == 0:
		b.WriteString("No firewall or router is in the inventory.\n")
	default:
		b.WriteString("No firewall or router in the inventory is on a path Vedette knows to this device.\n")
	}
	if f.Gateway.IsValid() {
		fmt.Fprintf(&b, "The gateway of this device's network is %s, which is not in the inventory as a firewall or router; its vendor is not known.\n", f.Gateway)
	}
	switch {
	case f.Others == 1:
		b.WriteString("1 other firewall or router in the inventory is not on a path Vedette knows to this device: write no rule for it.\n")
	case f.Others > 1:
		fmt.Fprintf(&b, "%d other firewalls or routers in the inventory are not on a path Vedette knows to this device: write no rule for them.\n", f.Others)
	}
	return b.String()
}

// aiWallFacts is the device facts of a firewall, or that its vendor is not known.
func aiWallFacts(w inventory.Device) string {
	if v := aiDeviceFacts(w); v != "" {
		return v
	}
	return "vendor not known"
}
