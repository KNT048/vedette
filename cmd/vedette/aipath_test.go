package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
)

// A config answer put a deny policy on a firewall that traffic to the device never crosses (a hand-added firewall on another network),
// while the device's real gateway was a different firewall. Every case of the box's network: the AI is given only the firewalls on the
// device's path, or the network block says the choice is an assumption and why; a firewall that is not offered never has its address
// in the block.
func TestAIPickWalls_OnlyFirewallsOnTheDevicePath(t *testing.T) {
	t.Parallel()
	lan := aiNetOf(api.NetState{
		Interfaces: []api.NetInterface{
			{Name: "eth0", Role: "management", Addresses: []string{"192.168.50.9/24", "fd00:50::9/64", "fe80::9/64"}},
			{Name: "eth1", Addresses: []string{"10.77.0.9/24"}},
			{Name: "docker0", Addresses: []string{"172.17.0.1/16"}},
		},
		DefaultRoute:   &api.NetRoute{Iface: "eth0", Gateway: "192.168.50.1", MAC: "00:11:22:33:44:01"},
		DefaultRoutes6: []api.NetRoute{{Iface: "eth0", Gateway: "fe80::1", MAC: "00:11:22:33:44:01"}},
	})
	mac := func(s string) *string { return &s }
	kd := func(id, ip string) inventory.KindDevice {
		return inventory.KindDevice{ID: id, IP: ip, Kind: "firewall"}
	}
	edge, far, inner, other := kd("edge", "192.168.50.1"), kd("far", "100.64.10.1"), kd("inner", "192.168.50.254"), kd("lab", "10.77.0.1")
	edgeMgmt := inventory.KindDevice{ID: "edge-mgmt", IP: "10.99.0.1", Kind: "firewall", MAC: mac("00:11:22:33:44:01")} // the gateway under another address
	branch := kd("branch", "172.20.4.1")
	cases := []struct {
		name     string
		net      aiNet
		dev      aiTarget
		all      []inventory.KindDevice
		want     []string
		paths    []aiPath
		onPath   bool
		edge     bool
		others   int
		gateway  string
		text     []string // in the network block
		devNet   string   // the device's network as the block names it
		boxOnNet bool     // the box is on the device's subnet
	}{
		{devNet: "192.168.50.0/24", boxOnNet: true, name: "gateway of the device's subnet in the inventory, another firewall off the path", net: lan, dev: aiTarget{IP: "192.168.50.47"}, all: []inventory.KindDevice{far, edge},
			want: []string{"edge"}, paths: []aiPath{pathGateway}, onPath: true, others: 1,
			text: []string{"on this device's path (write a firewall rule only for these)", "the default gateway of this device's network", "1 other firewall or router in the inventory is not on a path"}},
		{devNet: "192.168.50.0/24", boxOnNet: true, name: "the gateway is known: a firewall elsewhere on the subnet is not offered", net: lan, dev: aiTarget{IP: "192.168.50.47"}, all: []inventory.KindDevice{edge, inner, far},
			want: []string{"edge"}, paths: []aiPath{pathGateway}, onPath: true, others: 2},
		{devNet: "192.168.50.0/24", boxOnNet: true, name: "gateway known but not a firewall of the inventory: a firewall on the subnet is not offered, the gateway is named", net: lan, dev: aiTarget{IP: "192.168.50.47"}, all: []inventory.KindDevice{inner, far},
			others: 2, gateway: "192.168.50.1",
			text: []string{"No firewall or router in the inventory is on a path Vedette knows", "The gateway of this device's network is 192.168.50.1", "write no rule for them"}},
		{devNet: "192.168.50.0/24", boxOnNet: true, name: "the gateway in the inventory under another address, matched by its MAC", net: lan, dev: aiTarget{IP: "192.168.50.47"}, all: []inventory.KindDevice{far, edgeMgmt},
			want: []string{"edge-mgmt"}, paths: []aiPath{pathGateway}, onPath: true, others: 1},
		{devNet: "fd00:50::/64", boxOnNet: true, name: "IPv6 device behind a link-local next hop: the gateway by its MAC", net: lan, dev: aiTarget{IP: "fd00:50::47"}, all: []inventory.KindDevice{edgeMgmt, far},
			want: []string{"edge-mgmt"}, paths: []aiPath{pathGateway}, onPath: true, others: 1},
		{name: "the device is the gateway itself (the edge): no firewall, whatever is on the subnet", net: lan, dev: aiTarget{ID: "edge", IP: "192.168.50.1"}, all: []inventory.KindDevice{edge, inner, far},
			edge: true, others: 2, text: []string{"This device is the default gateway of its network (the network edge)", "write no rule for another firewall"}},
		{name: "the device is the gateway, by its MAC on the box's link", net: lan, dev: aiTarget{IP: "192.168.50.3", MAC: "00:11:22:33:44:01"}, all: []inventory.KindDevice{inner},
			edge: true, others: 1},
		{devNet: "likely 172.20.4.0/24", name: "device on another network: a firewall on its /24, then the box's gateway, both assumed", net: lan, dev: aiTarget{IP: "172.20.4.40"}, all: []inventory.KindDevice{edge, far, branch},
			want: []string{"branch", "edge"}, paths: []aiPath{pathNearby, pathBoxGateway}, others: 1,
			text: []string{"this device is on another network than the box", "likely its own gateway; an assumption", "covers only traffic from the box's network"}},
		{devNet: "likely 172.20.4.0/24", name: "device on another network, matching the router's MAC there says nothing", net: lan, dev: aiTarget{IP: "172.20.4.40", MAC: "00:11:22:33:44:01"}, all: []inventory.KindDevice{edge},
			want: []string{"edge"}, paths: []aiPath{pathBoxGateway}},
		{devNet: "10.77.0.0/24", boxOnNet: true, name: "device on a box subnet without a gateway: the firewalls on that subnet, assumed", net: lan, dev: aiTarget{IP: "10.77.0.40"}, all: []inventory.KindDevice{edge, other},
			want: []string{"lab"}, paths: []aiPath{pathSameSubnet}, others: 1, text: []string{"the box knows no gateway for this device's subnet"}},
		{devNet: "10.77.0.0/24", boxOnNet: true, name: "device on a box subnet without a gateway and no firewall there", net: lan, dev: aiTarget{IP: "10.77.0.40"}, all: []inventory.KindDevice{edge, far},
			others: 2, text: []string{"No firewall or router in the inventory is on a path"}},
		{devNet: "likely 172.17.5.0/24", name: "a container bridge's range is not the box's network", net: lan, dev: aiTarget{IP: "172.17.5.5"}, all: []inventory.KindDevice{edge},
			want: []string{"edge"}, paths: []aiPath{pathBoxGateway}},
		{devNet: "likely 192.168.50.0/24", name: "the box's network is not known: every firewall, as an assumption", net: aiNet{}, dev: aiTarget{IP: "192.168.50.47"}, all: []inventory.KindDevice{far, edge},
			want: []string{"far", "edge"}, paths: []aiPath{pathUnknown, pathUnknown}, text: []string{"cannot read the box's own network", "a rule for one of them is an assumption", "path to this device: not known"}},
		{devNet: "not known", name: "the device has no IP: every firewall, as an assumption", net: lan, dev: aiTarget{IP: "—"}, all: []inventory.KindDevice{far, edge},
			want: []string{"far", "edge"}, paths: []aiPath{pathUnknown, pathUnknown}, text: []string{"knows no IP address of this device"}},
		{devNet: "192.168.50.0/24", boxOnNet: true, name: "no firewall in the inventory", net: lan, dev: aiTarget{IP: "192.168.50.47"}, gateway: "192.168.50.1", text: []string{"No firewall or router is in the inventory.", "The gateway of this device's network is 192.168.50.1"}},
	}
	count := map[string]int{}
	for _, c := range cases {
		ids, sel := aiPickWalls(c.net, c.dev, c.all)
		if !slices.Equal(ids, c.want) || !slices.Equal(sel.Paths, c.paths) || sel.OnPath != c.onPath || sel.Edge != c.edge || sel.Others != c.others {
			t.Errorf("%s: ids %v (want %v), paths %v (want %v), on path %t, edge %t, others %d (want %d)", c.name, ids, c.want, sel.Paths, c.paths, sel.OnPath, sel.Edge, sel.Others, c.others)
			continue
		}
		got := ""
		if sel.Gateway.IsValid() {
			got = sel.Gateway.String()
		}
		if got != c.gateway {
			t.Errorf("%s: gateway %q, want %q", c.name, got, c.gateway)
		}
		if len(ids) > 0 && sel.OnPath == (sel.Why != "") {
			t.Errorf("%s: an offer is either on the path or an assumption with a reason: %+v", c.name, sel)
		}
		for _, id := range ids {
			for _, k := range c.all {
				if k.ID == id {
					sel.Walls = append(sel.Walls, inventory.Device{AssetCore: inventory.AssetCore{ID: k.ID, IP: k.IP, Kind: k.Kind}})
				}
			}
		}
		block := aiNetworkBlock(sel)
		for _, w := range c.text {
			if !strings.Contains(block, w) {
				t.Errorf("%s: the network block lacks %q:\n%s", c.name, w, block)
			}
		}
		for _, k := range c.all {
			if !slices.Contains(ids, k.ID) && strings.Contains(block, k.IP) {
				t.Errorf("%s: a firewall that is not offered is in the block:\n%s", c.name, block)
			}
		}
		// a firewall filters only what is routed through it: every block that may lead to a firewall rule says which traffic that is,
		// per firewall, and where a rule is tested from (a gateway rule from another network; the box on the device's subnet sees none)
		for _, l := range strings.Split(block, "\n") {
			if !strings.HasPrefix(l, "- ") {
				continue
			}
			if strings.Contains(l, "a rule here filters") {
				count["firewall line says the traffic it filters"]++
			} else {
				count["firewall line silent on the traffic it filters"]++
				t.Errorf("%s: a firewall line does not say which traffic a rule there filters: %s", c.name, l)
			}
		}
		scope := []string{"filters only the traffic routed through it", "reach the device directly", "protects the device only from the traffic that crosses it",
			"only the change on the device itself", "test from a host whose traffic passes that firewall"}
		if c.devNet != "" {
			scope = append(scope, "This device's network: "+c.devNet)
		}
		if c.boxOnNet {
			scope = append(scope, "a scan from the box does not show a gateway rule")
		} else { // a guessed or unknown network: the test host is found by the route, not by the guessed range
			scope = append(scope, "a traceroute or tracert to the device lists the firewall as a hop")
		}
		for i, l := range strings.Split(block, "\n") {
			// a guessed /24 (/64) stays a guess on every firewall line built on it
			if strings.HasPrefix(l, "- ") && strings.HasPrefix(c.devNet, "likely ") && !strings.Contains(l, "hosts on "+c.devNet+" (an assumed size)") {
				t.Errorf("%s: firewall line %d states the guessed network as fact: %s", c.name, i, l)
			}
			if strings.HasPrefix(l, "- ") && strings.Contains(l, "the box's default gateway") && !strings.Contains(l, "test a rule here from a host on the box's network") {
				t.Errorf("%s: the box's gateway line does not say where its rule is tested from: %s", c.name, l)
			}
		}
		for _, w := range scope {
			switch {
			case sel.Edge && strings.Contains(block, w):
				t.Errorf("%s: the edge has no gateway in front of it, yet the block says %q", c.name, w)
			case !sel.Edge && !strings.Contains(block, w):
				count["block silent on the traffic a gateway sees"]++
				t.Errorf("%s: the network block lacks %q:\n%s", c.name, w, block)
			}
		}
		if !c.boxOnNet && strings.Contains(block, "a scan from the box does not show") {
			t.Errorf("%s: the box is not on the device's network, yet the block says a scan from it does not show the rule", c.name)
		}
		switch {
		case sel.Edge:
			count["edge, none offered"]++
		case sel.OnPath:
			count["on path"]++
		case len(ids) > 0:
			count["assumed, with a reason"]++
		default:
			count["none offered"]++
		}
	}
	t.Logf("firewall offers by case: %v", count)
}

// More firewalls than an answer has room for: the first ones, and the block says how many more there are.
func TestAIPickWalls_CountsTheOnesOverTheCap(t *testing.T) {
	t.Parallel()
	var all []inventory.KindDevice
	for i := range aiMaxFirewalls + 3 {
		all = append(all, inventory.KindDevice{ID: string(rune('a' + i)), IP: "192.168.50.47"})
	}
	ids, sel := aiPickWalls(aiNet{}, aiTarget{IP: "192.168.50.47"}, all)
	if len(ids) != aiMaxFirewalls || sel.Others != 0 || sel.More != 3 {
		t.Fatalf("ids %v, others %d, more %d", ids, sel.Others, sel.More)
	}
	sel.Walls = make([]inventory.Device, len(ids))
	if b := aiNetworkBlock(sel); !strings.Contains(b, "3 more firewalls or routers like these are in the inventory and not listed here") {
		t.Fatalf("block = %s", b)
	}
}

func TestAINetOf_SubnetsAndGateways(t *testing.T) {
	t.Parallel()
	n := aiNetOf(api.NetState{
		Interfaces: []api.NetInterface{{Name: "eth0", Addresses: []string{"192.168.50.9/24", "192.168.60.5/32", "fe80::9/64", "127.0.0.1/8", "bad"}},
			{Name: "br-1a2b", Addresses: []string{"172.18.0.1/16"}}, {Name: "wg0", Addresses: []string{"10.8.0.1/24"}}},
		DefaultRoute: &api.NetRoute{Iface: "eth0", Gateway: "192.168.50.1", MAC: "AA:BB:CC:00:00:01"},
	})
	if !n.known || len(n.subnets) != 1 || n.subnets[0].prefix != netip.MustParsePrefix("192.168.50.0/24") || len(n.gateways) != 1 || n.gateways[0].mac != "aa:bb:cc:00:00:01" {
		t.Fatalf("net %+v", n)
	}
	if aiNetReader(nil) != nil {
		t.Fatal("no host: no reader")
	}
}

// The box itself marks the rule blocks of an assumed offer: a model that leaves "(assumed)" out does not make a guess read as fact.
// The device's own block, and every block of an offer on the path, stay as written.
func TestAIMarkAssumed_TheBoxMarksAGuess(t *testing.T) {
	t.Parallel()
	fw := inventory.Device{AssetCore: inventory.AssetCore{IP: "100.64.10.1", Model: obs("FortiGate 60F"), Vendor: obs("Fortinet")}}
	dev := []string{"Juniper Networks EX4200-48T", "EX4200-48T", "Juniper Networks"}
	cfgs := func() []findings.CodeStep {
		return []findings.CodeStep{{Title: "Juniper EX4200-48T (Junos)"}, {Title: "FortiGate 60F"}, {Title: "Linux gateway (nftables) (assumed)"}}
	}
	got := cfgs()
	aiMarkAssumed(got, aiFirewalls{Walls: []inventory.Device{fw}, Why: "not known"}, dev)
	if got[0].Title != "Juniper EX4200-48T (Junos)" || got[1].Title != "FortiGate 60F (assumed)" || got[2].Title != "Linux gateway (nftables) (assumed)" {
		t.Fatalf("assumed offer: %+v", got)
	}
	got = []findings.CodeStep{{Title: "FortiGate 60F policy"}}
	aiMarkAssumed(got, aiFirewalls{Walls: []inventory.Device{fw}, Why: "not known"}, dev)
	if got[0].Title != "FortiGate 60F policy (assumed)" {
		t.Fatalf("a firewall block first: %+v", got)
	}
	for _, sel := range []aiFirewalls{{Walls: []inventory.Device{fw}, OnPath: true}, {Edge: true}} {
		got = cfgs()
		if aiMarkAssumed(got, sel, dev); got[1].Title != "FortiGate 60F" {
			t.Fatalf("on path or edge: %+v", got)
		}
	}
}

// The trusted addresses follow the offer: a config naming a firewall that was not offered is flagged on the page for checking.
func TestAITrusted_OnlyTheOfferedFirewallsAndTheGateway(t *testing.T) {
	t.Parallel()
	row := aiSubject{AssetIP: "192.168.50.47"}
	got := aiTrusted(row, nil, aiFirewalls{Walls: []inventory.Device{{AssetCore: inventory.AssetCore{IP: "192.168.50.2"}}}, Gateway: netip.MustParseAddr("192.168.50.1")})
	if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.168.50.47"), netip.MustParseAddr("192.168.50.2"), netip.MustParseAddr("192.168.50.1")}) {
		t.Fatalf("trusted = %v", got)
	}
}
