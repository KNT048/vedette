package host_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
)

// D-466: each decoy address answers only its own services. decoy_ip.add takes an optional allow-list,
// decoy_ip.set_ports replaces it, and the namespace's ruleset holds it (input chain, sets open and
// allow), loaded whole and listed back after every change. The fake nft prints back what was loaded.

func dports(p ...any) []api.DecoyPort {
	out := []api.DecoyPort{}
	for i := 0; i+1 < len(p); i += 2 {
		out = append(out, api.DecoyPort{Proto: p[i].(string), Port: p[i+1].(int)})
	}
	return out
}

func (d *decoyEnv) addPorts(t *testing.T, ip string, p []api.DecoyPort) {
	t.Helper()
	d.ok(t, "decoy_ip.add", api.DecoyAddArgs{IP: ip, Ports: &p})
}

func (d *decoyEnv) portsOf(t *testing.T, ip string) *[]api.DecoyPort {
	t.Helper()
	for _, x := range d.state(t).Decoys {
		if x.IP == ip {
			return x.Ports
		}
	}
	t.Fatalf("%s is not in state/net", ip)
	return nil
}

func TestContract_DecoyPorts_AnAddressWithAnAllowListIsOnlyInTheAllowSet(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.addPorts(t, decoyIP1, dports("tcp", 3389, "tcp", 445)) // the File server preset of core, unsorted
	d.add(t, decoyIP2)                                       // an older core: no allow-list
	rs := d.m.IPState("ruleset")
	for _, want := range []string{
		"set open {\n\t\ttype ipv4_addr\n\t\telements = { " + decoyIP2 + " }",
		"elements = { " + decoyIP1 + " . tcp . 3389, " + decoyIP1 + " . tcp . 445 }",
		"ip daddr . meta l4proto . th dport @allow accept",
		"meta l4proto tcp reject with tcp reset",
		"ct state new drop",
	} {
		if !strings.Contains(rs, want) {
			t.Fatalf("the ruleset lacks %q:\n%s", want, rs)
		}
	}
	if got := d.portsOf(t, decoyIP1); got == nil || !slices.Equal(*got, dports("tcp", 445, "tcp", 3389)) {
		t.Fatalf("state/net ports %v (want sorted 445, 3389)", got)
	}
	if got := d.portsOf(t, decoyIP2); got != nil {
		t.Fatalf("an address added without ports reports an allow-list: %v", *got)
	}
	var f struct {
		Decoys []struct {
			IP    string
			Ports *[]api.DecoyPort
		}
	}
	if err := json.Unmarshal([]byte(d.decoysFile()), &f); err != nil || len(f.Decoys) != 2 {
		t.Fatalf("decoys.json %s: %v", d.decoysFile(), err)
	}
	// A restart (the namespace is made again after a reboot) loads the same allow-list from the state file.
	d.o.Close()
	shutdownHost(t, d)
	d2 := restartHost(t, d.netEnv)
	if rs2 := d2.m.IPState("ruleset"); !strings.Contains(rs2, decoyIP1+" . tcp . 445") || !strings.Contains(rs2, "elements = { "+decoyIP2+" }") {
		t.Fatalf("after a restart:\n%s", rs2)
	}
	if got := d2.portsOf(t, decoyIP1); got == nil || len(*got) != 2 {
		t.Fatalf("after a restart: %v", got)
	}
}

func TestContract_DecoyPorts_SetPortsReplacesTheListAndIsIdempotent(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1)
	n := len(d.ipCalls())
	res := result[api.DecoySetPortsResult](t, d.ok(t, "decoy_ip.set_ports", api.DecoySetPortsArgs{IP: decoyIP1, Ports: dports("tcp", 22)}))
	if res.IP != decoyIP1 || !slices.Equal(res.Ports, dports("tcp", 22)) {
		t.Fatalf("result %+v", res)
	}
	want := []string{
		"netns exec vedette-hp /usr/sbin/nft list ruleset", // the namespace is still proven
		"netns exec vedette-hp /usr/sbin/nft -f -",
		"netns exec vedette-hp /usr/sbin/nft list ruleset", // the effect check
	}
	if got := d.since(n); !slices.Equal(got, want) {
		t.Fatalf("calls:\n%q\nwant\n%q", got, want)
	}
	rs := d.m.IPState("ruleset")
	if !strings.Contains(rs, "elements = { "+decoyIP1+" . tcp . 22 }") || strings.Contains(rs, "elements = { "+decoyIP1+" }") {
		t.Fatalf("the address is not moved to the allow set:\n%s", rs)
	}
	if got := d.portsOf(t, decoyIP1); got == nil || !slices.Equal(*got, dports("tcp", 22)) {
		t.Fatalf("state/net %v", got)
	}
	// The same list again: nothing is loaded.
	n = len(d.ipCalls())
	d.ok(t, "decoy_ip.set_ports", api.DecoySetPortsArgs{IP: decoyIP1, Ports: dports("tcp", 22)})
	if got := d.since(n); slices.Contains(got, "netns exec vedette-hp /usr/sbin/nft -f -") {
		t.Fatalf("the same list loaded the ruleset again: %q", got)
	}
	// An empty list: the address is in neither set, so it answers no TCP or UDP port.
	d.ok(t, "decoy_ip.set_ports", api.DecoySetPortsArgs{IP: decoyIP1, Ports: []api.DecoyPort{}})
	if rs := d.m.IPState("ruleset"); strings.Contains(rs, decoyIP1) {
		t.Fatalf("an empty allow-list left the address in a set:\n%s", rs)
	}
	if got := d.portsOf(t, decoyIP1); got == nil || len(*got) != 0 {
		t.Fatalf("state/net %v", got)
	}
	// The link and the routing were not touched by any of it.
	if !slices.Equal(d.m.IPLinks("ns"), []string{"vdhc0a80164"}) {
		t.Fatalf("links %v", d.m.IPLinks("ns"))
	}
	for _, c := range d.m.Calls(ops.BinIP) {
		if err := ops.ValidateIP(c); err != nil {
			t.Errorf("outside the grammar: %q", c)
		}
	}
}

func TestContract_DecoyPorts_RefusalsAndBadArguments(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.add(t, decoyIP1)
	// Not a decoy: refused before any run, nothing loaded.
	n := len(d.ipCalls())
	d.refused(t, "decoy_ip.set_ports", api.DecoySetPortsArgs{IP: decoyIP2, Ports: dports("tcp", 22)}, http.StatusPreconditionFailed, api.CodeNotADecoy)
	if got := d.since(n); len(got) != 0 {
		t.Fatalf("a refused set_ports ran: %q", got)
	}
	many := []api.DecoyPort{}
	for i := 1; i <= api.MaxDecoyPorts+1; i++ {
		many = append(many, api.DecoyPort{Proto: "tcp", Port: i})
	}
	bad := map[string]any{
		"no ports":    map[string]any{"ip": decoyIP1},
		"null ports":  map[string]any{"ip": decoyIP1, "ports": nil},
		"proto":       api.DecoySetPortsArgs{IP: decoyIP1, Ports: dports("icmp", 1)},
		"port 0":      api.DecoySetPortsArgs{IP: decoyIP1, Ports: dports("tcp", 0)},
		"port 65536":  api.DecoySetPortsArgs{IP: decoyIP1, Ports: dports("udp", 65536)},
		"duplicate":   api.DecoySetPortsArgs{IP: decoyIP1, Ports: dports("tcp", 22, "tcp", 22)},
		"too many":    api.DecoySetPortsArgs{IP: decoyIP1, Ports: many},
		"bad ip":      api.DecoySetPortsArgs{IP: "192.168.1.1; id", Ports: dports("tcp", 22)},
		"ipv6":        api.DecoySetPortsArgs{IP: "fd00::1", Ports: dports("tcp", 22)},
		"port string": map[string]any{"ip": decoyIP1, "ports": []any{map[string]any{"proto": "tcp", "port": "22"}}},
		"extra field": map[string]any{"ip": decoyIP1, "ports": []any{map[string]any{"proto": "tcp", "port": 22, "dport": 1}}},
	}
	for name, args := range bad {
		d.refused(t, "decoy_ip.set_ports", args, http.StatusBadRequest, api.CodeInvalidArgs)
		_ = name
	}
	for name, p := range map[string][]api.DecoyPort{"proto": dports("sctp", 22), "duplicate": dports("tcp", 445, "tcp", 445), "port": dports("tcp", -1)} {
		pp := p
		d.refused(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP2, Ports: &pp}, http.StatusBadRequest, api.CodeInvalidArgs)
		_ = name
	}
	if strings.Contains(d.decoysFile(), decoyIP2) {
		t.Fatal("a refused add was recorded")
	}
}

func TestContract_DecoyPorts_ARulesetThatDoesNotTakeKeepsTheOldListAndTheDecoys(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.addPorts(t, decoyIP1, dports("tcp", 445))
	// nft says yes but the new ruleset never shows: the effect check fails.
	d.m.Mark("nft-noload", true)
	d.final(t, "decoy_ip.set_ports", api.DecoySetPortsArgs{IP: decoyIP1, Ports: dports("tcp", 22)}, api.StatusFailed, api.CodeDecoyFailed)
	if got := d.portsOf(t, decoyIP1); got == nil || !slices.Equal(*got, dports("tcp", 445)) {
		t.Fatalf("the old list did not come back: %v", got)
	}
	if !strings.Contains(d.decoysFile(), `"port":445`) || strings.Contains(d.decoysFile(), `"port":22`) {
		t.Fatalf("decoys.json %s", d.decoysFile())
	}
	// The old ruleset still stands and is proven, so the decoy stays.
	if !slices.Equal(d.m.IPLinks("ns"), []string{"vdhc0a80164"}) || !strings.Contains(d.m.IPState("ruleset"), decoyIP1+" . tcp . 445") {
		t.Fatalf("links %v ruleset:\n%s", d.m.IPLinks("ns"), d.m.IPState("ruleset"))
	}
	// An add whose ruleset does not take is undone: no link, no entry.
	d.final(t, "decoy_ip.add", api.DecoyAddArgs{IP: decoyIP2, Ports: &[]api.DecoyPort{{Proto: "tcp", Port: 22}}}, api.StatusFailed, api.CodeDecoyFailed)
	if slices.Contains(d.m.IPLinks("ns"), "vdhc0a80165") || strings.Contains(d.decoysFile(), decoyIP2) {
		t.Fatalf("the failed add left something: links %v, %s", d.m.IPLinks("ns"), d.decoysFile())
	}
	// Once nft takes it again, the change goes through.
	d.m.Mark("nft-noload", false)
	d.ok(t, "decoy_ip.set_ports", api.DecoySetPortsArgs{IP: decoyIP1, Ports: dports("tcp", 22)})
	if got := d.portsOf(t, decoyIP1); got == nil || !slices.Equal(*got, dports("tcp", 22)) {
		t.Fatalf("%v", got)
	}
}

func TestContract_DecoyPorts_ARulesetChangedBehindTheHostIsPutBack(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.addPorts(t, decoyIP1, dports("tcp", 445))
	// Someone widened the allow-list in the namespace: the next command that proves the namespace sees
	// the ruleset is not the wanted one and loads it again.
	d.m.SetIPState("ruleset", strings.Replace(d.m.IPState("ruleset"), decoyIP1+" . tcp . 445", decoyIP1+" . tcp . 445, "+decoyIP1+" . tcp . 22", 1))
	n := len(d.ipCalls())
	d.add(t, decoyIP2)
	got := d.since(n)
	if len(got) < 3 || got[0] != "netns exec vedette-hp /usr/sbin/nft list ruleset" || got[1] != "netns exec vedette-hp /usr/sbin/nft -f -" {
		t.Fatalf("the changed ruleset was not loaded again first: %q", got)
	}
	if rs := d.m.IPState("ruleset"); strings.Contains(rs, ". tcp . 22") {
		t.Fatalf("the widened allow-list stayed:\n%s", rs)
	}
}

func TestContract_DecoyPorts_AReapplyThatDropsADecoyTakesItOutOfTheSets(t *testing.T) {
	t.Parallel()
	d := startDecoy(t)
	d.addPorts(t, decoyIP1, dports("tcp", 445))
	d.addPorts(t, "192.168.1.60", dports("tcp", 22)) // the address the box will take
	d.apply(t, staticArgs("192.168.1.60/24", "192.168.1.2"))
	rs := d.m.IPState("ruleset")
	if strings.Contains(rs, "192.168.1.60") || !strings.Contains(rs, decoyIP1+" . tcp . 445") {
		t.Fatalf("the ruleset after the re-apply:\n%s", rs)
	}
}
