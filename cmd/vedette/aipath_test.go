package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/mitigation"
)

// A config answer put a deny policy on a firewall that traffic to the device never crosses (a hand-added firewall on another network),
// while the device's real gateway was a different firewall. Every case of the box's network: the AI is given only the firewalls on the
// device's path, or the network block says the choice is an assumption and why; a firewall with no known path is never offered while
// one on the path is known, and its address never reaches the network block then.
func TestAIPickWalls_OnlyFirewallsOnTheDevicePath(t *testing.T) {
	t.Parallel()
	lan := aiNetOf(api.NetState{
		Interfaces:     []api.NetInterface{{Name: "eth0", Addresses: []string{"192.168.50.9/24", "fd00:50::9/64", "fe80::9/64"}}, {Name: "eth1", Addresses: []string{"10.77.0.9/24"}}},
		DefaultRoute:   &api.NetRoute{Iface: "eth0", Gateway: "192.168.50.1"},
		DefaultRoutes6: []api.NetRoute{{Iface: "eth0", Gateway: "fd00:50::1"}, {Iface: "eth0", Gateway: "fe80::1"}},
	})
	kd := func(id, ip string) inventory.KindDevice {
		return inventory.KindDevice{ID: id, IP: ip, Kind: "firewall"}
	}
	edge, far, inner, v6edge, other := kd("edge", "192.168.50.1"), kd("far", "100.64.10.1"), kd("inner", "192.168.50.2"), kd("edge6", "fd00:50::1"), kd("lab", "10.77.0.1")
	cases := []struct {
		name    string
		net     aiNet
		devID   string
		devIP   string
		all     []inventory.KindDevice
		want    []string
		path    aiPath
		onPath  bool
		others  int
		gateway string
		text    []string // in the network block
	}{
		{name: "gateway of the device's subnet in the inventory, another firewall off the path", net: lan, devIP: "192.168.50.47", all: []inventory.KindDevice{far, edge},
			want: []string{"edge"}, path: pathGateway, onPath: true, others: 1,
			text: []string{"on this device's path (write a firewall rule only for these)", "the default gateway of this device's network", "1 other firewall or router in the inventory is not on a path"}},
		{name: "a firewall on the device's subnet besides its gateway is left out", net: lan, devIP: "192.168.50.47", all: []inventory.KindDevice{edge, inner, far},
			want: []string{"edge"}, path: pathGateway, onPath: true, others: 2},
		{name: "device on another network: the box's default gateway", net: lan, devIP: "172.20.4.5", all: []inventory.KindDevice{far, edge},
			want: []string{"edge"}, path: pathGatewayOther, onPath: true, others: 1, text: []string{"this device is on another network"}},
		{name: "IPv6 device: the IPv6 gateway", net: lan, devIP: "fd00:50::47", all: []inventory.KindDevice{edge, v6edge},
			want: []string{"edge6"}, path: pathGateway, onPath: true, others: 1},
		{name: "gateway not in the inventory: no firewall is offered, the gateway is named", net: lan, devIP: "192.168.50.47", all: []inventory.KindDevice{far},
			others: 1, gateway: "192.168.50.1",
			text: []string{"No firewall or router in the inventory is on a path Vedette knows", "The gateway of this device's network is 192.168.50.1", "write no rule for it"}},
		{name: "only a firewall on the device's subnet: offered as an assumption", net: lan, devIP: "192.168.50.47", all: []inventory.KindDevice{inner, far},
			want: []string{"inner"}, path: pathSameSubnet, others: 1, text: []string{"Vedette does not know which firewall is on this device's path", "may be the device's gateway"}},
		{name: "device on a box subnet without a gateway: the box's gateway is not on its path", net: lan, devIP: "10.77.0.40", all: []inventory.KindDevice{edge, far},
			others: 2, text: []string{"No firewall or router in the inventory is on a path"}},
		{name: "device on a box subnet without a gateway, a firewall on that subnet", net: lan, devIP: "10.77.0.40", all: []inventory.KindDevice{edge, other},
			want: []string{"lab"}, path: pathSameSubnet, others: 1},
		{name: "the box's network is not known: every firewall, as an assumption", net: aiNet{}, devIP: "192.168.50.47", all: []inventory.KindDevice{far, edge},
			want: []string{"far", "edge"}, path: pathUnknown, text: []string{"cannot read the box's own network", "a rule for one of them is an assumption", "path to this device: not known"}},
		{name: "the device has no IP: every firewall, as an assumption", net: lan, devIP: "—", all: []inventory.KindDevice{far, edge},
			want: []string{"far", "edge"}, path: pathUnknown, text: []string{"knows no IP address of this device"}},
		{name: "the finding's device is the gateway itself: it is not a rule target", net: lan, devID: "edge", devIP: "192.168.50.1", all: []inventory.KindDevice{edge, far},
			others: 1, text: []string{"No firewall or router in the inventory is on a path"}},
		{name: "no firewall in the inventory", net: lan, devIP: "192.168.50.47", gateway: "192.168.50.1", text: []string{"No firewall or router is in the inventory.", "The gateway of this device's network is 192.168.50.1"}},
	}
	count := map[string]int{}
	for _, c := range cases {
		ids, sel := aiPickWalls(c.net, c.devID, c.devIP, c.all)
		if !slices.Equal(ids, c.want) || sel.OnPath != c.onPath || sel.Others != c.others || len(sel.Paths) != len(ids) {
			t.Errorf("%s: ids %v (want %v), on path %t, others %d (want %d), paths %v", c.name, ids, c.want, sel.OnPath, sel.Others, c.others, sel.Paths)
			continue
		}
		for _, p := range sel.Paths {
			if p != c.path {
				t.Errorf("%s: path %v, want %v", c.name, p, c.path)
			}
		}
		if got := ""; sel.Gateway.IsValid() {
			got = sel.Gateway.String()
			if got != c.gateway {
				t.Errorf("%s: gateway %s, want %q", c.name, got, c.gateway)
			}
		} else if c.gateway != "" {
			t.Errorf("%s: no gateway, want %s", c.name, c.gateway)
		}
		if len(ids) > 0 && sel.OnPath == (sel.Why != "") {
			t.Errorf("%s: an offer is either on the path or an assumption with a reason: %+v", c.name, sel)
		}
		// the block as the AI reads it
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
			if !slices.Contains(ids, k.ID) && strings.Contains(block, "IP "+k.IP+",") {
				t.Errorf("%s: a firewall that is not offered is in the block:\n%s", c.name, block)
			}
		}
		switch {
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

// More firewalls on the path than an answer has room for: the first ones, the rest neither offered nor counted as off the path.
func TestAIPickWalls_CapsTheOffer(t *testing.T) {
	t.Parallel()
	var all []inventory.KindDevice
	for i := range aiMaxFirewalls + 3 {
		all = append(all, inventory.KindDevice{ID: string(rune('a' + i)), IP: "192.168.50.47"})
	}
	ids, sel := aiPickWalls(aiNet{}, "", "192.168.50.47", all)
	if len(ids) != aiMaxFirewalls || sel.Others != 0 {
		t.Fatalf("ids %v, others %d", ids, sel.Others)
	}
}

func TestAINetOf_SubnetsAndGateways(t *testing.T) {
	t.Parallel()
	n := aiNetOf(api.NetState{
		Interfaces:   []api.NetInterface{{Addresses: []string{"192.168.50.9/24", "192.168.60.5/32", "fe80::9/64", "127.0.0.1/8", "bad"}}},
		DefaultRoute: &api.NetRoute{Gateway: "192.168.50.1"},
	})
	if !n.known || len(n.subnets) != 1 || n.subnets[0] != netip.MustParsePrefix("192.168.50.0/24") || len(n.gateways) != 1 {
		t.Fatalf("net %+v", n)
	}
	if aiNetReader(nil) != nil {
		t.Fatal("no host: no reader")
	}
}

// The trusted addresses follow the offer: a config naming a firewall that was not offered is flagged on the page for checking.
func TestAITrusted_OnlyTheOfferedFirewallsAndTheGateway(t *testing.T) {
	t.Parallel()
	row := findings.Row{Asset: &findings.AssetView{IP: "192.168.50.47"}}
	got := aiTrusted(row, nil, aiFirewalls{Walls: []inventory.Device{{AssetCore: inventory.AssetCore{IP: "192.168.50.2"}}}, Gateway: netip.MustParseAddr("192.168.50.1")})
	if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.168.50.47"), netip.MustParseAddr("192.168.50.2"), netip.MustParseAddr("192.168.50.1")}) {
		t.Fatalf("trusted = %v", got)
	}
}

// The page states the fix from findings.FixedIn; the AI gets the same object. For every kind the page shows, the fact line names a
// fixed release exactly when the page does, and for the kinds where the page says no release is named (or the range end is not a
// fix) the line says so and never reads "fixed in" that release. Counted per kind.
func TestAIFixedIn_AgreesWithThePageForEveryKind(t *testing.T) {
	t.Parallel()
	type tc struct {
		f       *findings.FixedIn
		fixedIn string // the release the page names as the fix, "" when it names none
		says    string // what the line must say
	}
	cases := map[string]tc{
		"fixed":          {&findings.FixedIn{Kind: "fixed", Version: "2.4.49", Fixed: "2.4.51"}, "2.4.51", "fixed in 2.4.51"},
		"up_to":          {&findings.FixedIn{Kind: "up_to", Version: "9.1", Fixed: "9.3"}, "", "no fixed release named"},
		"end_listed":     {&findings.FixedIn{Kind: "end_listed", Version: "15.1R7.9", Fixed: "20.4"}, "", "20.4 is not a fix"},
		"distro":         {&findings.FixedIn{Kind: "distro", Version: "1:9.6p1-3ubuntu13.4", Distro: "Ubuntu", DistroFixed: "1:9.6p1-3ubuntu13.5", DistroRelease: "24.04"}, "1:9.6p1-3ubuntu13.5", "fixed package 1:9.6p1-3ubuntu13.5"},
		"feature_update": {&findings.FixedIn{Kind: "feature_update", Version: "10.0.19044.1", Fixed: "10.0.19045.5000", Branches: []findings.FixedBranch{{Branch: "22H2", Fixed: "10.0.19045.5000"}}}, "10.0.19045.5000", "move to a later release from build 10.0.19045.5000"},
		"esu":            {&findings.FixedIn{Kind: "esu", Version: "10.0.19045.1", Fixed: "10.0.19045.6000"}, "10.0.19045.6000", "Extended Security Updates"},
		"branches":       {&findings.FixedIn{Kind: "branches", Branches: []findings.FixedBranch{{Branch: "21.2", Fixed: "21.2R3-S7"}}, NoFix: 1}, "21.2R3-S7", "21.2 fixed in 21.2R3-S7"},
		"branches, none": {&findings.FixedIn{Kind: "branches", NoFix: 2}, "", "2 release lines have no fixed release"},
		"not known":      {nil, "", "Fixed version: not known on this box"},
	}
	noFix := 0
	for name, c := range cases {
		got := aiFixedIn(c.f, true)
		if !strings.Contains(got, c.says) {
			t.Errorf("%s: %q lacks %q", name, got, c.says)
		}
		if c.fixedIn == "" {
			noFix++
			if c.f != nil && c.f.Fixed != "" && strings.Contains(got, "fixed in "+c.f.Fixed) {
				t.Errorf("%s: the line calls %s the fix while the page does not: %q", name, c.f.Fixed, got)
			}
		} else if !strings.Contains(got, c.fixedIn) {
			t.Errorf("%s: the page's fix %s is not in %q", name, c.fixedIn, got)
		}
	}
	t.Logf("%d kinds, %d of them name no fixed release", len(cases), noFix)

	// the AI reads the verdict in the device block, after the Evidence that holds the "before" end of the range
	req := mitigation.AIRequest{Skill: mitigation.SkillConfig, Finding: findings.Row{CVE: "CVE-2023-0001"}, FixedIn: cases["end_listed"].f}
	if b := aiFindingData(req, nil, aiFirewalls{}); !strings.Contains(b[1].Text, "20.4 is not a fix") {
		t.Fatalf("device block = %q", b[1].Text)
	}
}
