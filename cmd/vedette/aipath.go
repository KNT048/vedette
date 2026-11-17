package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// The mitigation-config answer writes a firewall rule per firewall it is given. A rule on a firewall that traffic to the device never
// crosses protects nothing and reads as if it did, so the AI is given the firewalls on the device's path, as far as the box knows it:
// the subnets of the box's own cards and its default gateways (vedette-host state/net). A device on a subnet of the box reaches other
// networks through the gateway of that subnet; for a device on another network the box knows only its own way there, so what it offers
// then is an assumption, and the network block says so.

// aiSubnet is one subnet of a box card.
type aiSubnet struct {
	prefix netip.Prefix // masked
	iface  string
}

// aiGateway is one default route's next hop, with the card it leaves by and the next hop's MAC when the neighbour table has it.
type aiGateway struct {
	ip    netip.Addr // no zone
	iface string
	mac   string // lower case, "" when not known
}

// aiNet is the box's own network as vedette-host reports it. known is false when there is no host or it did not answer.
type aiNet struct {
	known    bool
	subnets  []aiSubnet
	gateways []aiGateway // the IPv4 default route first
}

// aiVirtualIface names the cards that are not the customer's network: container bridges, virtual links and tunnels. An address range
// of theirs can overlap a real network of the customer (172.17.0.0/16), and a device there is not on the box's subnet.
func aiVirtualIface(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "podman", "cni", "virbr", "lxc", "lxd", "flannel", "cali", "vxlan", "wg", "tun", "tap", "tailscale", "zt"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// aiNetOf reads the subnets and default gateways out of a state/net answer.
func aiNetOf(st api.NetState) aiNet {
	n := aiNet{known: true}
	for _, i := range st.Interfaces {
		if i.Role != "management" && aiVirtualIface(i.Name) {
			continue
		}
		for _, s := range i.Addresses {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil || p.IsSingleIP() || p.Addr().Is4In6() || p.Addr().IsLinkLocalUnicast() || p.Addr().IsLoopback() {
				continue
			}
			n.subnets = append(n.subnets, aiSubnet{prefix: netip.PrefixFrom(p.Addr().WithZone(""), p.Bits()).Masked(), iface: i.Name})
		}
	}
	add := func(r api.NetRoute) {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Gateway)); err == nil && !a.IsUnspecified() {
			n.gateways = append(n.gateways, aiGateway{ip: a.Unmap().WithZone(""), iface: r.Iface, mac: strings.ToLower(strings.TrimSpace(r.MAC))})
		}
	}
	if st.DefaultRoute != nil {
		add(*st.DefaultRoute)
	}
	for _, r := range st.DefaultRoutes6 {
		add(r)
	}
	return n
}

// subnetOf is the box's subnet that holds a, if any (the longest one).
func (n aiNet) subnetOf(a netip.Addr) (aiSubnet, bool) {
	var best aiSubnet
	for _, s := range n.subnets {
		if s.prefix.Contains(a) && (!best.prefix.IsValid() || s.prefix.Bits() > best.prefix.Bits()) {
			best = s
		}
	}
	return best, best.prefix.IsValid()
}

// deviceGateway is the gateway of a device on a subnet of the box: the default route of the device's address family that leaves by
// the card of that subnet (an IPv6 next hop is usually a link-local address of that card), or whose address is in that subnet. ok is
// false when the device is on no subnet of the box or the box knows no gateway there.
func (n aiNet) deviceGateway(dev netip.Addr) (aiGateway, bool) {
	sub, onBox := n.subnetOf(dev)
	if !onBox {
		return aiGateway{}, false
	}
	for _, g := range n.gateways {
		if g.ip.Is4() == dev.Is4() && (g.iface != "" && g.iface == sub.iface || sub.prefix.Contains(g.ip)) {
			return g, true
		}
	}
	return aiGateway{}, false
}

// boxGateway is the box's own default gateway of the device's address family: its way to a network it is not on.
func (n aiNet) boxGateway(dev netip.Addr) (aiGateway, bool) {
	for _, g := range n.gateways {
		if g.ip.Is4() == dev.Is4() {
			return g, true
		}
	}
	return aiGateway{}, false
}

// is reports whether a device at ip with mac is this gateway: the same address, or the MAC the box's neighbour table gives for it (a
// router listed under another of its addresses, or reached over an IPv6 link-local next hop).
func (g aiGateway) is(ip netip.Addr, mac string) bool {
	return ip.IsValid() && ip == g.ip || g.mac != "" && strings.EqualFold(mac, g.mac)
}

// aiPath is what the box knows of a firewall's place on the way to a device.
type aiPath int

const (
	pathUnknown    aiPath = iota // no known place on the path
	pathBoxGateway               // the box's gateway, the device on another network: a rule there covers traffic from the box's network only
	pathSameSubnet               // on the device's own subnet, which has no gateway the box knows: it may be the device's gateway
	pathNearby                   // the device is on another network and this firewall on the same /24 (/64): likely its own gateway
	pathGateway                  // the gateway of the device's own subnet: on the path
)

// label is the path as the AI reads it.
func (p aiPath) label() string {
	switch p {
	case pathGateway:
		return "path: the default gateway of this device's network"
	case pathNearby:
		return "path: on the same network as this device (the same /24, or /64 for IPv6), so likely its own gateway; an assumption"
	case pathBoxGateway:
		return "path: the box's default gateway; a rule here covers only traffic from the box's network to this device, not from the device's own network or the Internet"
	case pathSameSubnet:
		return "path: on this device's own subnet, which has no gateway the box knows; it may be the device's gateway, an assumption"
	}
	return "path to this device: not known"
}

// aiSameNet: a and b are on the same /24 (IPv4) or /64 (IPv6), the usual size of one network.
func aiSameNet(a, b netip.Addr) bool {
	bits := 24
	if a.Is6() {
		bits = 64
	}
	if a.Is4() != b.Is4() {
		return false
	}
	p, err := a.Prefix(bits)
	return err == nil && p.Contains(b)
}

// aiFirewalls is what the config skill is told about the firewalls and routers of the inventory for one device. Walls (with the path
// of each in Paths) are the ones a rule may be written for. OnPath: they are on the device's path; else a rule for one of them is an
// assumption, and Why says why the path is not known. Edge: the device is itself the gateway of its network, so no firewall of the
// inventory is in front of it. Others counts the firewalls and routers left out because they are not on the device's path; More the
// ones that qualify but are over aiMaxFirewalls. Gateway is the device's gateway when it is not a firewall or router of the inventory.
type aiFirewalls struct {
	Walls   []inventory.Device
	Paths   []aiPath
	OnPath  bool
	Edge    bool
	Why     string
	Others  int
	More    int
	Gateway netip.Addr
}

// assumed: the firewalls offered are not known to be on the device's path.
func (f aiFirewalls) assumed() bool { return !f.OnPath && !f.Edge }

// aiTarget is the finding's device as the firewall choice needs it.
type aiTarget struct{ ID, IP, MAC string }

// aiPickWalls chooses, from the firewalls and routers of the inventory, the ones the AI may write a rule for (their ids, at most
// aiMaxFirewalls, in the inventory's order). The device itself is never one: its own block covers it.
//   - The device is the gateway of its network (the edge): none.
//   - The device is on a subnet of the box with a known gateway: that gateway if it is in the inventory, else none and the gateway's
//     address is named. A firewall elsewhere on the subnet is not on the device's way out.
//   - On a subnet of the box with no known gateway: the firewalls on that subnet, as an assumption.
//   - On another network: the firewalls on the same /24 (/64) as the device, then the box's gateway, as an assumption.
//   - The box's network or the device's address is not known: every firewall, as an assumption.
func aiPickWalls(n aiNet, dev aiTarget, all []inventory.KindDevice) (ids []string, sel aiFirewalls) {
	ip, _ := netip.ParseAddr(dev.IP)
	ip = ip.Unmap().WithZone("")
	var cands []inventory.KindDevice
	for _, k := range all {
		if k.ID != dev.ID {
			cands = append(cands, k)
		}
	}
	paths := make([]aiPath, len(cands))
	_, onBox := n.subnetOf(ip)
	gw, hasGW := n.deviceGateway(ip)
	box, hasBox := n.boxGateway(ip)
	for i, k := range cands {
		fw, _ := netip.ParseAddr(k.IP)
		fw = fw.Unmap().WithZone("")
		mac := ""
		if k.MAC != nil {
			mac = *k.MAC
		}
		switch {
		case !n.known || !ip.IsValid():
		case hasGW:
			if gw.is(fw, mac) {
				paths[i] = pathGateway
			}
		case onBox:
			if sub, ok := n.subnetOf(fw); ok && sub.prefix.Contains(ip) {
				paths[i] = pathSameSubnet
			}
		case fw.IsValid() && aiSameNet(ip, fw):
			paths[i] = pathNearby
		case hasBox && box.is(fw, mac):
			paths[i] = pathBoxGateway
		}
	}
	take := func(keep func(aiPath) bool) {
		for _, want := range []aiPath{pathGateway, pathNearby, pathSameSubnet, pathBoxGateway, pathUnknown} { // the likeliest first
			for i, k := range cands {
				switch {
				case paths[i] != want:
				case !keep(paths[i]):
					sel.Others++
				case len(ids) == aiMaxFirewalls:
					sel.More++
				default:
					ids = append(ids, k.ID)
					sel.Paths = append(sel.Paths, paths[i])
				}
			}
		}
	}
	all1 := func(aiPath) bool { return true }
	devMAC := ""
	if onBox { // a MAC says the same machine only on the box's own link; across a router every device shows the router's MAC
		devMAC = dev.MAC
	}
	switch {
	case !n.known:
		sel.Why = "Vedette cannot read the box's own network here, so it does not know which firewall traffic to this device passes"
		take(all1)
	case !ip.IsValid():
		sel.Why = "Vedette knows no IP address of this device"
		take(all1)
	case hasGW && gw.is(ip, devMAC):
		sel.Edge = true
		take(func(aiPath) bool { return false })
	case hasGW:
		sel.OnPath = true
		take(func(p aiPath) bool { return p == pathGateway })
		if len(ids) == 0 && sel.More == 0 {
			sel.OnPath, sel.Gateway = false, gw.ip
		}
	case onBox:
		sel.Why = "the box knows no gateway for this device's subnet; the firewalls below are on that subnet and may be its gateway"
		take(func(p aiPath) bool { return p == pathSameSubnet })
	default:
		sel.Why = "this device is on another network than the box, and Vedette does not know that network's gateway"
		take(func(p aiPath) bool { return p == pathNearby || p == pathBoxGateway })
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
			fmt.Fprintf(&b, "- %s, IP %s, kind %s; %s; %s", aiName(w), aiIP(w.IP), aiVal(w.Kind, 30), aiWallFacts(w), f.Paths[i].label())
			if s := aiSafeApply(w); s != "" {
				b.WriteString("; safe apply: " + s)
			}
			b.WriteString("\n")
		}
	}
	switch {
	case f.Edge:
		b.WriteString("This device is the default gateway of its network (the network edge): no firewall or router of the inventory is in front of it. Restrict access to the vulnerable service on the device itself; write no rule for another firewall and no Linux gateway example.\n")
	case len(f.Walls) > 0 && f.OnPath:
		b.WriteString("Firewalls and routers on this device's path (write a firewall rule only for these):\n")
		list()
	case len(f.Walls) > 0:
		fmt.Fprintf(&b, "Vedette does not know which firewall is on this device's path: %s. Firewalls and routers in the inventory (a rule for one of them is an assumption):\n", f.Why)
		list()
	case f.Others == 0 && f.More == 0:
		b.WriteString("No firewall or router is in the inventory.\n")
	default:
		b.WriteString("No firewall or router in the inventory is on a path Vedette knows to this device.\n")
	}
	if f.More > 0 {
		fmt.Fprintf(&b, "%d more firewalls or routers like these are in the inventory and not listed here.\n", f.More)
	}
	if f.Gateway.IsValid() {
		fmt.Fprintf(&b, "The gateway of this device's network is %s; no firewall or router of the inventory has that address, so its vendor is not known.\n", f.Gateway)
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

// aiAssumedTag is what a rule block for a firewall not known to be on the device's path carries in its title.
const aiAssumedTag = "(assumed)"

// aiMarkAssumed puts aiAssumedTag on the title of every firewall rule block of an answer whose firewalls were offered as an
// assumption, when the model left it out: the box knows the offer was a guess and says so itself, whatever the model wrote. The
// device's own block (the first, as the task asks, unless its title names an offered firewall and not the device) is left alone.
func aiMarkAssumed(cfgs []findings.CodeStep, sel aiFirewalls, devNames []string) {
	if !sel.assumed() {
		return
	}
	names := func(title string, list []string) bool {
		t := strings.ToLower(title)
		for _, n := range list {
			if n = strings.ToLower(strings.TrimSpace(n)); len(n) >= 3 && strings.Contains(t, n) {
				return true
			}
		}
		return false
	}
	var walls []string
	for _, w := range sel.Walls {
		walls = append(walls, aiName(w), aiObserved(w.Model), aiObserved(w.Vendor), w.IP)
	}
	for i := range cfgs {
		c := &cfgs[i]
		if strings.Contains(strings.ToLower(c.Title), aiAssumedTag) {
			continue
		}
		if i == 0 && (names(c.Title, devNames) || !names(c.Title, walls)) {
			continue // the device's own block
		}
		c.Title = strings.TrimSpace(c.Title) + " " + aiAssumedTag
	}
}
